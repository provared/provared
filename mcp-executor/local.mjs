// provared-mcp-executor over HTTP, in front of a local program: the tool
// server is a program the executor starts and speaks to over its standard
// input and output, as the stdio executor does, where http.mjs otherwise
// stands in front of an upstream HTTP MCP server (DESIGN.md, section 10.1).
//
// Each MCP session has a program of its own: started when an agent sends
// "initialize", ended when the session ends. A session belongs to the agent
// that began it, and its program reads and writes that one session's
// messages and no other's, so no agent sees another's traffic. This file
// starts and ends the programs, carries lines to and from them, and keeps
// the limits; http.mjs speaks HTTP and reaches the same check, receipt,
// countersignature and copy as for any other call (executor.mjs, callCore).

import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { SERVER_ENDED, UNREADABLE_ANSWER, isObject } from './executor.mjs';
import { CODES, idKey, readLines, readMessage, topLevelId, unsafeInteger } from './jsonrpc.mjs';

/** The most sessions, each with a program of its own, one agent may have at once, unless the settings say otherwise ("sessions.max"). */
export const SESSIONS_MAX = 8;
/** How long a session with nothing in flight is kept after the agent's last message, unless the settings say otherwise ("sessions.idle"): half an hour. */
export const SESSION_IDLE = 30 * 60 * 1000;

/** The limits on sessions, "sessions": {max, idle}. Read only where the settings name a local program ("server"). */
export function readSessionSettings(config, s, at, warnings) {
  const given = config.sessions ?? {};
  if (!isObject(given)) return at('sessions', 'must be an object: max, idle.');
  s.sessions = { max: given.max ?? SESSIONS_MAX, idle: given.idle ?? SESSION_IDLE };
  if (!Number.isInteger(s.sessions.max) || s.sessions.max < 1 || s.sessions.max > 256) at('sessions.max', 'must be a whole number from 1 to 256: the most sessions, each with a program of its own, one agent may have at once.');
  if (!Number.isInteger(s.sessions.idle) || s.sessions.idle < 1000 || s.sessions.idle > 86400000) at('sessions.idle', 'must be a whole number of milliseconds from 1,000 to 86,400,000: how long a session with nothing in flight is kept after the agent\'s last message.');
  for (const k of Object.keys(given)) if (!['max', 'idle'].includes(k)) warnings.push(`sessions.${k}: not a setting; set aside.`);
}

/**
 * The sessions of a local program. "settings" are the HTTP executor's, with
 * "server.resolved" the program's path; "env" is the program's whole
 * environment and "credentialNames" the names of the credentials in it
 * (readProgramEnvironment); "serverStderr" is where each program's standard
 * error goes (null: nowhere).
 */
export function openLocalSessions({ settings, env, credentialNames, log, serverStderr = process.stderr }) {
  /** Every session that has not ended, by its id. */
  const sessions = new Map();
  /** Every session whose program is still running, ended sessions among them. */
  const running = new Set();

  /** Write one message to a session's program: false where the session has ended or the program has gone. */
  function write(session, text) {
    if (session.gone || session.ended) return false;
    try {
      session.child.stdin.write(`${text}\n`);
      return true;
    } catch {
      return false;
    }
  }

  /** The idle limit: counted from the agent's last message, and begun again while anything is in flight. */
  function touch(session) {
    if (session.ended) return;
    session.last = Date.now();
    clearTimeout(session.idleTimer);
    session.idleTimer = setTimeout(() => (session.busy > 0 ? touch(session) : end(session, 'idle')), settings.sessions.idle);
    session.idleTimer.unref();
  }

  /**
   * End a session: it is forgotten at once, so that a later request under
   * its id is answered as an unknown session; its stream is closed; and its
   * program's input is closed, as the stdio executor closes it, and the
   * program is ended by force where it has not ended within "shutdownWait".
   * A call still with the program is settled when the program ends.
   */
  function end(session, why) {
    if (session.ended) return;
    session.ended = why;
    sessions.delete(session.id);
    clearTimeout(session.idleTimer);
    session.release?.();
    session.closeStream?.();
    for (const [serverId, entry] of [...session.waiting]) {
      if (entry.kind === 'call') continue;
      session.waiting.delete(serverId);
      entry.done({ failed: 'ended' });
    }
    log({ event: 'session-ended', agent: session.agent, why });
    if (session.gone) return;
    try {
      session.child.stdin.end();
    } catch {
      // Already gone.
    }
    session.killTimer = setTimeout(() => {
      if (session.gone) return;
      log({ event: 'server-killed', agent: session.agent });
      session.child.kill();
    }, settings.shutdownWait);
  }

  /** One line from a session's program. */
  function fromProgram(session, line) {
    const read = readMessage(line, { strictNumbers: false });
    if (read.refused) {
      // Not a message the executor can read strictly. Where its top-level id names a request in flight, that request is answered with the line as it is, and a tool call gets a receipt that says the answer could not be read, as on stdio. Otherwise there is no request it could answer, and it goes no further.
      let text = null;
      try {
        text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(line);
      } catch {
        text = null;
      }
      const found = text === null ? null : topLevelId(text);
      const entry = found && typeof found.value === 'string' ? session.waiting.get(found.value) : undefined;
      log({ event: 'server-line-not-read', agent: session.agent, code: read.refused.code, ...(entry ? { matched: entry.kind } : {}) });
      if (entry?.kind === 'call') {
        if (entry.call.state === 'sent' && entry.call.settle) entry.call.settle({ kind: 'unreadable', text, errorText: UNREADABLE_ANSWER });
        return;
      }
      if (entry) {
        session.waiting.delete(found.value);
        entry.done({ text, message: null });
      }
      return;
    }
    const m = read.message;
    if (read.kind === 'response') {
      const entry = typeof m.id === 'string' ? session.waiting.get(m.id) : undefined;
      if (entry?.kind === 'call') {
        const call = entry.call;
        if (call.state !== 'sent' || !call.settle) return log({ event: 'late-answer-dropped', agent: session.agent });
        if (Object.hasOwn(m, 'result')) return call.settle({ kind: 'answer', text: read.text, result: m.result, unsafe: unsafeInteger(read.text) !== null });
        return call.settle({ kind: 'server-error', text: read.text, errorText: `The tool server answered with an error: ${JSON.stringify(m.error)}` });
      }
      if (entry) {
        session.waiting.delete(m.id);
        return entry.done({ text: read.text, message: m });
      }
      // An answer to nothing in flight (it came after a timeout or a cancellation, or names an id the executor never sent): no agent is sent it.
      return log({ event: 'late-answer-dropped', agent: session.agent });
    }
    // A request or a notification of the program's own goes on the session's stream, where the agent has one open.
    if (!session.toStream?.(read.text)) log({ event: 'server-message-dropped', agent: session.agent, method: String(m.method).slice(0, 80) });
  }

  return {
    /** How many sessions have not ended, of one agent or of all; and how many programs are still running. */
    count: (agent) => (agent === undefined ? sessions.size : [...sessions.values()].filter((s) => s.agent === agent).length),
    programs: () => running.size,

    /**
     * Begin a session for an agent: its program is started. "connection" is
     * the connection made through OAuth it is begun under, or null for an
     * agent that signs in with its secret. Gives {session}, or {refused}:
     * "too-many" where the agent has its most sessions and each has
     * something in flight, "not-started" where the program could not be
     * started at all. Where the agent has its most sessions and one has
     * nothing in flight, the one whose agent has been quiet longest is ended
     * to make room.
     */
    begin(agent, connection) {
      const own = [...sessions.values()].filter((s) => s.agent === agent);
      if (own.length >= settings.sessions.max) {
        const quiet = own.filter((s) => s.busy === 0).sort((a, b) => a.last - b.last)[0];
        if (!quiet) return { refused: 'too-many' };
        end(quiet, 'made-room');
      }
      let child;
      try {
        child = spawn(settings.server.resolved, settings.server.args, { cwd: settings.server.cwd, env, stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true, shell: false });
      } catch (e) {
        log({ event: 'server-failed', agent, error: e.code ?? e.message });
        return { refused: 'not-started' };
      }
      // 32 random bytes in base64url: visible ASCII, and not to be guessed.
      const session = { id: randomBytes(32).toString('base64url'), agent, connection, child, gone: false, ended: null, busy: 0, last: Date.now(), waiting: new Map(), toStream: null, closeStream: null, release: null, idleTimer: null, killTimer: null, exited: null };
      sessions.set(session.id, session);
      running.add(session);
      log({ event: 'server-started', agent, command: settings.server.resolved, credentials: credentialNames });
      // What the program says on its standard error goes where the settings' owner looks, as on stdio. Written on, not piped: many programs write to the one place, and a pipe from each would hang its own listeners on it.
      if (serverStderr) child.stderr.on('data', (said) => serverStderr.write(said));
      else child.stderr.resume();
      child.stdin.on('error', (e) => log({ event: 'server-stdin-error', agent, error: e.code ?? e.message }));
      readLines(child.stdout, {
        onLine: (line) => fromProgram(session, line),
        onTooLong: (length) => log({ event: 'server-line-dropped', agent, code: 'too-long', length }),
        onEnd: () => {},
      });
      session.exited = new Promise((done) => {
        const over = (how) => {
          if (session.gone) return;
          session.gone = true;
          clearTimeout(session.killTimer);
          // A call that was with the program gets the receipt it gets on stdio.
          for (const entry of [...session.waiting.values()]) {
            if (entry.kind === 'call' && entry.call.state === 'sent' && entry.call.settle) entry.call.settle({ kind: 'error', text: SERVER_ENDED, code: CODES.noAnswer });
          }
          log({ event: how.error === undefined ? 'server-ended' : 'server-failed', agent, ...how });
          end(session, 'server-ended');
          running.delete(session);
          done();
        };
        child.on('exit', (code, signal) => over({ code, signal }));
        child.on('error', (e) => over({ error: e.code ?? e.message }));
      });
      touch(session);
      return { session };
    },

    /** The session under this id, where it is this agent's and was begun under this connection; or null. A session used under another connection than its own is ended. */
    owned(id, agent, connection) {
      const session = sessions.get(id);
      if (!session || session.agent !== agent) return null;
      if (session.connection !== connection) {
        end(session, 'another-connection');
        return null;
      }
      return session;
    },

    /** A message of the agent's is in hand for this session, until "leave": the session is not idle, and is not ended to make room. */
    enter(session) {
      session.busy += 1;
      touch(session);
    },
    leave(session) {
      session.busy -= 1;
      touch(session);
    },

    /** The key a call in flight is held by: its session and its id, since an id is unique only within its session. */
    key: (session, id) => `${session.id}\n${idKey(id)}`,

    write,
    end,

    /**
     * Send a request to the session's program ("text" carries the
     * executor's own id, "serverId") and wait for its answer: {text,
     * message}, the program's line and the message read from it (null where
     * it could not be read), or {failed}: "ended" (the program or the
     * session ended first), "timeout" (no answer within "timeout") or "gone"
     * (the agent went away, "forget"). "clientId" is the agent's id for it.
     */
    ask(session, text, serverId, clientId) {
      return new Promise((done) => {
        const timer = setTimeout(() => {
          session.waiting.delete(serverId);
          done({ failed: 'timeout' });
        }, settings.timeout);
        timer.unref();
        session.waiting.set(serverId, {
          kind: 'request',
          id: clientId,
          done: (got) => {
            clearTimeout(timer);
            done(got);
          },
        });
        if (!write(session, text)) {
          session.waiting.delete(serverId);
          clearTimeout(timer);
          done({ failed: 'ended' });
        }
      });
    },
    /** The agent that sent a request has gone: its answer, if one comes, is dropped. */
    forget(session, serverId) {
      const entry = session.waiting.get(serverId);
      if (!entry || entry.kind === 'call') return;
      session.waiting.delete(serverId);
      entry.done({ failed: 'gone' });
    },
    /** The executor's id of a request in flight, other than a tool call, that the agent sent under this id; or undefined. */
    serverIdOf(session, clientId) {
      const key = idKey(clientId);
      for (const [serverId, entry] of session.waiting) if (entry.kind === 'request' && idKey(entry.id) === key) return serverId;
      return undefined;
    },

    /** A tool call is with the session's program, from "track" to "untrack": its answer is looked for under the executor's id. */
    track(session, call) {
      session.waiting.set(call.serverId, { kind: 'call', call });
    },
    untrack(session, call) {
      if (session.waiting.get(call.serverId)?.kind === 'call') session.waiting.delete(call.serverId);
    },

    /** End every session and wait until every program has ended: each is given "shutdownWait", and is then ended by force. */
    async close() {
      for (const session of [...sessions.values()]) end(session, 'executor-stopped');
      await Promise.all([...running].map((s) => s.exited));
    },
  };
}
