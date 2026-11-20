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
import { KILL_WAIT, OUTPUT_WAIT, OWN_GROUP, SERVER_ENDED, UNREADABLE_ANSWER, groupLeft, isObject, signalProgram } from './executor.mjs';
import { CODES, MAX_LINE_BYTES, idKey, oneLine, readLines, readMessage, topLevelId, unsafeInteger } from './jsonrpc.mjs';

/** The most sessions, each with a program of its own, one agent may have at once, unless the settings say otherwise ("sessions.max"). */
export const SESSIONS_MAX = 8;
/** How long a session with nothing in flight is kept after the agent's last message, unless the settings say otherwise ("sessions.idle"): half an hour. */
export const SESSION_IDLE = 30 * 60 * 1000;
/** How long, past the two waits, the executor's stop waits for programs to be gone before it finishes without them (X242). */
export const CLOSE_MARGIN = 2000;
/** The most messages that answer nothing in flight a program may write in one second; a session whose program writes more for FLOOD_SECONDS seconds running is ended (X245). */
export const FLOOD_PER_SECOND = 1000;
export const FLOOD_SECONDS = 5;
/** How often, at most, a line of a program that goes nowhere is logged, for each session and each kind: once a second, with the count since the last (X245). */
export const DROPPED_LOG_EVERY = 1000;
/** The longest line of a program's standard error that is written on: 64 KiB. A longer one is dropped. */
export const STDERR_LINE = 64 * 1024;
/**
 * The most bytes of one program's standard error written on in each second
 * of the clock (256 KiB), and the most that may wait to be written to the
 * executor's own standard error, for every program together (1 MiB). Lines
 * past either are dropped, and counted in the log once a second (X353).
 */
export const STDERR_PER_SECOND = 256 * 1024;
export const STDERR_BACKLOG = 1024 * 1024;

const LINE_FEED = Buffer.from('\n');

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
 * error goes (null: nowhere); "backlog" is the most bytes that may wait to
 * be written to a program that is not reading; "spawnProgram" is what
 * starts a program (node:child_process's spawn; a test may give its own).
 */
export function openLocalSessions({ settings, env, credentialNames, log, serverStderr = process.stderr, backlog = MAX_LINE_BYTES, spawnProgram = spawn }) {
  /** Every session that has not ended, by its id. */
  const sessions = new Map();
  /** Every session whose program is still running, ended sessions among them. */
  const running = new Set();
  /** Set by "close": no program is started after it. */
  let closed = false;
  const killWait = Math.min(settings.shutdownWait, KILL_WAIT);
  /** One agent's programs still running, ended sessions' among them. */
  const programsOf = (agent) => [...running].filter((s) => s.agent === agent);

  /**
   * Write one message to a session's program: false where the session has
   * ended or the program has gone. Where more than "backlog" bytes already
   * wait for a program that is not reading, nothing is written and the
   * session is ended: the message is refused, not held in memory (X244).
   * The program is given "shutdownWait", as at every other end, so that one
   * busy with a call may still answer it (X363).
   */
  function write(session, text) {
    if (session.gone || session.ended) return false;
    const held = session.child.stdin.writableLength;
    if (held > backlog) {
      log({ event: 'server-not-reading', agent: session.agent, held });
      end(session, 'not-reading');
      return false;
    }
    try {
      // One line under every way of ending a line: an agent's body may hold line feeds between its values, which would otherwise reach the program as several lines (X248).
      session.child.stdin.write(`${oneLine(text)}\n`);
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

  /** End a program that has not ended of itself: SIGTERM now and, where it is still running after the second wait, SIGKILL (the specification's order for stdio: close the input, SIGTERM, SIGKILL). On Windows the first is already final. */
  function force(session) {
    if (session.gone || session.dead) return;
    const kill = (signal) => {
      log({ event: 'server-killed', agent: session.agent, signal });
      // On Linux and macOS the signal goes to the program's whole process group: to whatever it started, too (X252).
      signalProgram(session.child, signal);
    };
    kill('SIGTERM');
    session.killTimer = setTimeout(() => {
      if (!session.gone && !session.dead) kill('SIGKILL');
    }, killWait);
  }

  /**
   * End a session: it is forgotten at once, so that a later request under
   * its id is answered as an unknown session; its stream is closed; and its
   * program's input is closed, as the stdio executor closes it, and the
   * program is ended by force where it has not ended within "shutdownWait"
   * ("force"). With "now" the program is ended by force at once: it is
   * flooding. A call still with the program is settled when
   * the program ends.
   */
  function end(session, why, now = false) {
    if (session.ended) return;
    session.ended = why;
    sessions.delete(session.id);
    clearTimeout(session.idleTimer);
    session.release?.();
    session.closeStream?.();
    for (const [serverId, entry] of [...session.waiting]) {
      if (entry.kind === 'call') continue;
      session.waiting.delete(serverId);
      entry.done({ failed: why === 'not-reading' ? 'not-reading' : 'ended' });
    }
    log({ event: 'session-ended', agent: session.agent, why });
    if (session.gone) return;
    if (now) {
      // What waits to be written is let go with the input.
      session.child.stdin.destroy();
      force(session);
      return;
    }
    try {
      session.child.stdin.end();
    } catch {
      // Already gone.
    }
    session.killTimer = setTimeout(() => force(session), settings.shutdownWait);
  }

  /** A line of a program that goes nowhere: logged at most once a second for each session and each kind, with the count since the last such line of the log. */
  function dropped(session, event, more = {}) {
    const entry = (session.dropped[event] ??= { count: 0, at: 0, more });
    entry.count += 1;
    entry.more = more;
    const at = Date.now();
    if (at - entry.at < DROPPED_LOG_EVERY) return;
    log({ event, agent: session.agent, ...more, count: entry.count });
    entry.count = 0;
    entry.at = at;
  }

  /**
   * A line of a program that answers nothing in flight is counted: a
   * program that writes more than FLOOD_PER_SECOND of them in each of
   * FLOOD_SECONDS seconds running has its session ended, and is ended by
   * force at once. True where the session has ended. The seconds are the
   * clock's, counted from the session's start: the first, the second and
   * so on. A second that holds no more than the limit, or none at all,
   * breaks the run, however much the seconds beside it hold.
   */
  function counted(session) {
    if (session.ended) return true;
    const second = Math.floor((Date.now() - session.begun) / 1000);
    if (second !== session.second) {
      // The second just over is one more of the run where it came straight before this one and held more than the limit; any other breaks the run.
      session.strikes = second === session.second + 1 && session.inSecond > FLOOD_PER_SECOND ? session.strikes + 1 : 0;
      session.second = second;
      session.inSecond = 0;
    }
    session.inSecond += 1;
    // The seconds over the limit before this one, and this one once it is over it too.
    if (session.strikes + (session.inSecond > FLOOD_PER_SECOND ? 1 : 0) < FLOOD_SECONDS) return false;
    log({ event: 'server-flooding', agent: session.agent });
    end(session, 'flooding', true);
    return true;
  }

  /** One line from a session's program. */
  function fromProgram(session, line) {
    // An ended session with no call in flight: nothing the program writes has anywhere to go.
    if (session.ended && session.waiting.size === 0) return;
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
      if (entry?.kind === 'call') {
        log({ event: 'server-line-not-read', agent: session.agent, code: read.refused.code, matched: entry.kind });
        if (entry.call.state === 'sent' && entry.call.settle) entry.call.settle({ kind: 'unreadable', text, errorText: UNREADABLE_ANSWER });
        return;
      }
      if (entry) {
        log({ event: 'server-line-not-read', agent: session.agent, code: read.refused.code, matched: entry.kind });
        session.waiting.delete(found.value);
        entry.done({ text, message: null });
        return;
      }
      if (!counted(session)) dropped(session, 'server-line-not-read', { code: read.refused.code });
      return;
    }
    const m = read.message;
    if (read.kind === 'response') {
      const entry = typeof m.id === 'string' ? session.waiting.get(m.id) : undefined;
      if (entry?.kind === 'call') {
        const call = entry.call;
        if (call.state !== 'sent' || !call.settle) return dropped(session, 'late-answer-dropped');
        if (Object.hasOwn(m, 'result')) return call.settle({ kind: 'answer', text: read.text, result: m.result, unsafe: unsafeInteger(read.text) !== null });
        return call.settle({ kind: 'server-error', text: read.text, errorText: `The tool server answered with an error: ${JSON.stringify(m.error)}` });
      }
      if (entry) {
        session.waiting.delete(m.id);
        return entry.done({ text: read.text, message: m });
      }
      // An answer to nothing in flight (it came after a timeout or a cancellation, or names an id the executor never sent): no agent is sent it.
      if (!counted(session)) dropped(session, 'late-answer-dropped');
      return;
    }
    // A request or a notification of the program's own goes on the session's stream, where the agent has one open.
    if (counted(session)) return;
    if (!session.toStream?.(read.text)) dropped(session, 'server-message-dropped', { method: String(m.method).slice(0, 80) });
  }

  /** Start a session's program. */
  function start(agent, connection) {
    let child;
    try {
      // On Linux and macOS the program leads a process group of its own, so that a signal reaches whatever it starts (X252).
      child = spawnProgram(settings.server.resolved, settings.server.args, { cwd: settings.server.cwd, env, stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true, shell: false, detached: OWN_GROUP });
    } catch (e) {
      log({ event: 'server-failed', agent, error: e.code ?? e.message });
      return { refused: 'not-started' };
    }
    // 32 random bytes in base64url: visible ASCII, and not to be guessed.
    const session = { id: randomBytes(32).toString('base64url'), agent, connection, child, gone: false, ended: null, busy: 0, last: Date.now(), waiting: new Map(), toStream: null, closeStream: null, release: null, idleTimer: null, killTimer: null, exited: null, starting: true, version: null, dropped: {}, dead: false, begun: Date.now(), second: 0, inSecond: 0, strikes: 0, stderrSecond: -1, stderrBytes: 0 };
    sessions.set(session.id, session);
    running.add(session);
    log({ event: 'server-started', agent, command: settings.server.resolved, credentials: credentialNames });
    // What the program says on its standard error goes where the settings' owner looks, as on stdio: whole lines, each with its line feed, so that a line of the program's never runs into a line of the executor's own. Written on, not piped: many programs write to the one place, and a pipe from each would hang its own listeners on it. Where it goes nowhere it is still read, so that a program that writes much is not held up.
    if (serverStderr) {
      // Bounded, so that a program that writes without pause neither fills the executor's memory where the place is
      // slow to take it (Linux), nor holds the executor in each write (Windows, where a write to a pipe waits): past
      // STDERR_PER_SECOND bytes of this program's in a second of the clock, or STDERR_BACKLOG bytes waiting for every
      // program together, its lines are dropped and counted (X353).
      readLines(child.stderr, {
        limit: STDERR_LINE,
        onLine: (line) => {
          const second = Math.floor(Date.now() / 1000);
          if (session.stderrSecond !== second) {
            session.stderrSecond = second;
            session.stderrBytes = 0;
          }
          session.stderrBytes += line.length + 1;
          if (session.stderrBytes > STDERR_PER_SECOND || (serverStderr.writableLength ?? 0) > STDERR_BACKLOG) return dropped(session, 'server-stderr-dropped');
          serverStderr.write(Buffer.concat([line, LINE_FEED]));
        },
        onTooLong: (length) => dropped(session, 'server-stderr-line-dropped', { length }),
        onEnd: () => {},
      });
      // One read at a time, with everything else that waits taken in between, as for its output.
      child.stderr.on('data', () => {
        child.stderr.pause();
        setImmediate(() => child.stderr.resume());
      });
    } else {
      child.stderr.on('error', () => {});
      child.stderr.resume();
    }
    child.stdin.on('error', (e) => log({ event: 'server-stdin-error', agent, error: e.code ?? e.message }));
    readLines(child.stdout, {
      onLine: (line) => fromProgram(session, line),
      onTooLong: (length) => dropped(session, 'server-line-dropped', { code: 'too-long', length }),
      onEnd: () => {},
    });
    // One read of a program's output at a time, with everything else that waits taken in between: a program that writes without pause does not hold up another agent's requests (X245).
    child.stdout.on('data', () => {
      child.stdout.pause();
      setImmediate(() => child.stdout.resume());
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
        // What was dropped since the last line of the log about it.
        for (const [event, entry] of Object.entries(session.dropped)) if (entry.count > 0) log({ event, agent, ...entry.more, count: entry.count });
        log({ event: how.error === undefined ? 'server-ended' : 'server-failed', agent, ...how });
        end(session, 'server-ended');
        const finish = () => {
          running.delete(session);
          done();
        };
        if (!groupLeft(child)) return finish();
        // What the program started and left in its process group is ended too: SIGTERM, and SIGKILL after the second wait. Until it has gone it counts as the program still running, for "sessions.max" and for the stop (Linux and macOS; X252).
        log({ event: 'server-group-left', agent });
        signalProgram(child, 'SIGTERM');
        const last = Date.now() + killWait;
        const look = setInterval(() => {
          if (groupLeft(child) && Date.now() < last) return;
          clearInterval(look);
          if (groupLeft(child)) signalProgram(child, 'SIGKILL');
          finish();
        }, 50);
      };
      child.on('exit', (code, signal) => {
        // The program has gone. What it wrote before it went may still wait to be read, one read at a time (X245): its calls are settled once its output has ended, so that its last lines are not taken for no answer (X251). At most OUTPUT_WAIT longer, where something it started still holds its output open.
        session.dead = true;
        clearTimeout(session.killTimer);
        if (child.stdout.readableEnded || child.stdout.destroyed) return over({ code, signal });
        const late = setTimeout(() => over({ code, signal }), OUTPUT_WAIT);
        child.stdout.once('end', () => {
          clearTimeout(late);
          over({ code, signal });
        });
      });
      child.on('error', (e) => over({ error: e.code ?? e.message }));
    });
    touch(session);
    return { session };
  }

  return {
    /** How many sessions have not ended, of one agent or of all; and how many programs are still running. */
    count: (agent) => (agent === undefined ? sessions.size : [...sessions.values()].filter((s) => s.agent === agent).length),
    programs: (agent) => (agent === undefined ? running.size : programsOf(agent).length),

    /**
     * Begin a session for an agent: its program is started. "connection" is
     * the connection made through OAuth it is begun under, or null for an
     * agent that signs in with its secret. Gives {session}, or {refused}:
     * "too-many", "not-started" where the program could not be started at
     * all, or "stopping" where the executor has begun to stop.
     *
     * An agent never has more than "sessions.max" programs running, the
     * programs of ended sessions that have not gone yet among them, and one
     * whose "initialize" is not answered yet (X243). Where it has that many,
     * room is made: the session whose agent has been quiet longest, of those
     * with nothing in flight, is ended, and this waits until a program of
     * the agent's has gone. "too-many" where no session can be ended (each
     * has something in flight) or no program has gone within the two waits a
     * program is given to end.
     */
    async begin(agent, connection) {
      const deadline = Date.now() + settings.shutdownWait + killWait + CLOSE_MARGIN;
      // eslint-disable-next-line no-unmodified-loop-condition -- closed is set by close(), which may run while the loop waits.
      while (!closed && programsOf(agent).length >= settings.sessions.max) {
        let ending = programsOf(agent).filter((s) => s.ended);
        if (ending.length === 0) {
          // A session just begun, whose "initialize" is not yet in hand, makes no room.
          const quiet = [...sessions.values()].filter((s) => s.agent === agent && s.busy === 0 && !s.starting).sort((a, b) => a.last - b.last)[0];
          if (!quiet) return { refused: 'too-many' };
          end(quiet, 'made-room');
          ending = [quiet];
        }
        const left = deadline - Date.now();
        if (left <= 0) return { refused: 'too-many' };
        let timer;
        await Promise.race([...ending.map((s) => s.exited), new Promise((d) => {
          timer = setTimeout(d, left);
        })]);
        clearTimeout(timer);
      }
      if (closed) return { refused: 'stopping' };
      return start(agent, connection);
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
      session.starting = false;
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
     * session ended first), "not-reading" (the program was not reading, so
     * the request was not written and the session was ended), "timeout" (no
     * answer within "timeout") or "gone" (the agent went away, "forget").
     * "clientId" is the agent's id for it. At the timeout the program is
     * told that the request is cancelled, as the specification asks of the
     * sender, unless "cancel" is false ("initialize" is never cancelled).
     */
    ask(session, text, serverId, clientId, { cancel = true } = {}) {
      return new Promise((done) => {
        const timer = setTimeout(() => {
          session.waiting.delete(serverId);
          if (cancel) write(session, JSON.stringify({ jsonrpc: '2.0', method: 'notifications/cancelled', params: { requestId: serverId, reason: `The Provared executor gave this request ${settings.timeout} ms and got no answer.` } }));
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
        if (!write(session, text) && session.waiting.has(serverId)) {
          session.waiting.delete(serverId);
          clearTimeout(timer);
          done({ failed: session.ended === 'not-reading' ? 'not-reading' : 'ended' });
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

    /**
     * End every session and wait until every program has gone: each is
     * given "shutdownWait", then SIGTERM, then, after the second wait,
     * SIGKILL. No program is started after this. It always finishes: where
     * a program is still there a little after the two waits, that is logged
     * and the stop goes on without it (X242).
     */
    /** The executor has begun to stop: no program is started from now on (X246). */
    noMore() {
      closed = true;
    },

    async close() {
      closed = true;
      for (const session of [...sessions.values()]) end(session, 'executor-stopped');
      let timer;
      const late = new Promise((d) => {
        timer = setTimeout(() => d('late'), settings.shutdownWait + killWait + CLOSE_MARGIN);
      });
      if ((await Promise.race([Promise.all([...running].map((s) => s.exited)), late])) === 'late') log({ event: 'servers-not-ended', programs: running.size });
      clearTimeout(timer);
    },
  };
}
