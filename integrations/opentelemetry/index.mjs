// A bridge between Provared and OpenTelemetry, in both directions, in one
// call:
//
// - the span names the receipt: the span of a tool call carries the
//   receipt's fingerprint, the fingerprint of the permission (the slip) it
//   relies on, the action, and what the check before acting said
//   (attributes.mjs lists the names);
// - the receipt names the span's trace: the stub names, among its
//   documents, "provared.trace-id", the fingerprint of the span's trace id
//   (format description, section 27).
//
// A span is the agent's side's own word, as the receipt is. The receipt
// and the checker are the evidence; the span is a pointer to it.
//
// It depends on OpenTelemetry's API only (a peer dependency, as
// OpenTelemetry asks of libraries), never on its SDK. With no SDK
// registered, the API records no span; the tools run and are receipted as
// without the bridge, and the receipt names a trace only where the call
// was made inside one passed on from elsewhere.

import { SpanKind, SpanStatusCode, isSpanContextValid, trace } from '@opentelemetry/api';
import { NotTaken, argumentsFingerprint, identifierFingerprint, recordTools } from 'provared';
import { actionOrNull, annotate, codesOf } from './attributes.mjs';

export { ATTRIBUTES, NOT_TAKEN_EVENT, OUTCOMES, annotate, attributesFor, codesOf } from './attributes.mjs';

/** The name and version the bridge gives its tracer. */
export const TRACER_NAME = 'provared-opentelemetry';
export const TRACER_VERSION = '0.1.0';

// The attributes OpenTelemetry's conventions for generative AI give an
// "execute_tool" span (semantic-conventions-genai, gen-ai-spans.md,
// "Execute tool span", status: development).
const GEN_AI = Object.freeze({
  operation: 'gen_ai.operation.name',
  toolName: 'gen_ai.tool.name',
  callId: 'gen_ai.tool.call.id',
  agentName: 'gen_ai.agent.name',
});
const ERROR_TYPE = 'error.type';
const TRACE_ID = 'provared.trace-id';
const EVENT_ID = 'provared.event-id';

// A class name, written as code writes it: low in variety, as error.type
// asks, and never a message. It is put on the span as the code named it.
const ERROR_NAME = /^[A-Za-z_$][A-Za-z0-9_$.]{0,63}$/;

function errorType(e) {
  try {
    const name = e !== null && typeof e === 'object' && typeof e.constructor === 'function' ? e.constructor.name : null;
    return typeof name === 'string' && ERROR_NAME.test(name) ? name : '_OTHER';
  } catch {
    return '_OTHER';
  }
}

// Text of one character or more, well-formed: the form section 27 asks of an identifier.
const identifier = (value) => (typeof value === 'string' && value.length > 0 && value.length <= 256 && value.isWellFormed() ? value : null);

const OPTIONS = ['span', 'tracer', 'agentName', 'bindTrace', 'bindCallId', 'event', 'onStub'];
const ACT_OPTIONS = [...OPTIONS, 'toolName', 'callId'];

function settingsOf(options, known) {
  if (options !== undefined && (options === null || typeof options !== 'object' || Array.isArray(options))) throw new TypeError('options: must be an object.');
  const o = options ?? {};
  for (const name of Object.keys(o)) if (!known.includes(name)) throw new TypeError(`${name}: is not an option. The options are: ${known.join(', ')}.`);
  const span = o.span === undefined ? 'new' : o.span;
  if (span !== 'new' && span !== 'active') throw new TypeError('span: must be "new" (the bridge starts an "execute_tool" span for each call) or "active" (the bridge adds to the span that is active when the tool is called).');
  for (const name of ['bindTrace', 'bindCallId', 'event']) {
    if (o[name] !== undefined && typeof o[name] !== 'boolean') throw new TypeError(`${name}: must be true or false.`);
  }
  if (o.agentName !== undefined && identifier(o.agentName) === null) throw new TypeError('agentName: must be text of 1 to 256 characters.');
  if (o.onStub !== undefined && typeof o.onStub !== 'function') throw new TypeError('onStub: must be a function.');
  if (o.tracer !== undefined && (o.tracer === null || typeof o.tracer !== 'object' || typeof o.tracer.startActiveSpan !== 'function')) throw new TypeError('tracer: must be an OpenTelemetry tracer.');
  if (o.toolName !== undefined && actionOrNull(o.toolName) === null) throw new TypeError('toolName: must be 1 to 64 visible ASCII characters, with no spaces.');
  if (o.callId !== undefined && identifier(o.callId) === null) throw new TypeError('callId: must be text of 1 to 256 characters.');
  return {
    span,
    tracer: o.tracer ?? trace.getTracer(TRACER_NAME, TRACER_VERSION),
    agentName: o.agentName,
    bindTrace: o.bindTrace !== false,
    bindCallId: o.bindCallId !== false,
    event: o.event === true,
    onStub: o.onStub,
    toolName: o.toolName,
    callId: o.callId,
  };
}

// The span to work on, and the call run with it. In "new", the span is
// started as the active one, so that what the tool does (a web call, say)
// is traced beneath it; it is ended here. In "active", the span is the
// caller's (an agent framework's own tool span, say), which the caller
// ends; there may be none.
function withSpan(settings, toolName, callId, work) {
  if (settings.span === 'active') return work(trace.getActiveSpan() ?? null, false);
  const attributes = { [GEN_AI.operation]: 'execute_tool', [GEN_AI.toolName]: toolName };
  if (settings.agentName !== undefined) attributes[GEN_AI.agentName] = settings.agentName;
  if (callId) attributes[GEN_AI.callId] = callId;
  return settings.tracer.startActiveSpan(`execute_tool ${toolName}`, { kind: SpanKind.INTERNAL, attributes }, async (span) => {
    try {
      return await work(span, true);
    } finally {
      span.end();
    }
  });
}

// The documents that bind the receipt to the span: the trace id, and the
// identifier the model gave the call. Each is the fingerprint of the
// identifier, never the identifier.
async function bindings(settings, span, callId) {
  const documents = [];
  const context = span && typeof span.spanContext === 'function' ? span.spanContext() : null;
  if (settings.bindTrace && context && isSpanContextValid(context)) {
    documents.push({ name: TRACE_ID, sha256: await identifierFingerprint(context.traceId) });
  }
  if (settings.bindCallId && callId) documents.push({ name: EVENT_ID, sha256: await identifierFingerprint(callId) });
  return documents;
}

// The bindings to add after documents already named: no second
// "provared.event-id" where the caller named one already, so that one
// receipt does not hold identifiers of the call from two sources.
const after = (named, binding) => (Array.isArray(named) && named.some((d) => d && d.name === EVENT_ID) ? binding.filter((d) => d.name !== EVENT_ID) : binding);

function markNotTaken(span, own, action, answer, denial, settings) {
  annotate(span, { outcome: 'not_taken', action, answer, denial }, { event: settings.event });
  if (own && span) {
    span.setAttribute(ERROR_TYPE, 'NotTaken');
    span.setStatus({ code: SpanStatusCode.ERROR, message: codesOf(answer).join(', ') });
  }
}

function markError(span, own, action, e) {
  annotate(span, { outcome: 'error', action });
  if (own && span) {
    span.setAttribute(ERROR_TYPE, errorType(e));
    // No message: an error's text may quote what the tool was given.
    span.setStatus({ code: SpanStatusCode.ERROR });
  }
}

/**
 * Put an agent's tools behind the stub writer, as recordTools does, and
 * trace each call: each call's span names its receipt, and its receipt
 * names the span's trace.
 *
 * Each tool is described as for recordTools ("action", "run", and where they
 * apply "with", "amount", "details", "countersign", "approve"), with one
 * member more:
 *   - "callId" (optional): a function of the second argument the tool is
 *     called with (the options an agent framework hands a tool, say) that
 *     gives the identifier the model gave the call, or nothing. It goes on
 *     the span as gen_ai.tool.call.id and into the receipt as the
 *     fingerprint "provared.event-id". Anything that is not text of 1 to
 *     256 characters is set aside.
 *
 * @param {object} recorder the stub writer (openRecorder)
 * @param {Record<string, object>} tools by name; the name, as given, is the span's gen_ai.tool.name
 * @param {object} [options]
 * @param {'new'|'active'} [options.span] "new" (the default) starts an "execute_tool" span for each call;
 *   "active" adds to the span that is active when the tool is called, where an agent framework already makes one
 * @param {object} [options.tracer] the tracer for "new"; by default trace.getTracer("provared-opentelemetry")
 * @param {string} [options.agentName] gen_ai.agent.name on each span the bridge starts
 * @param {boolean} [options.bindTrace] false to leave the trace out of the receipt; true by default
 * @param {boolean} [options.bindCallId] false to leave the model's call identifier out of the receipt; true by default
 * @param {boolean} [options.event] true to add a span event "provared.not_taken" where a call is not taken; false by default
 * @param {(stub: object, tool: string) => any} [options.onStub] as for recordTools
 * @returns {Record<string, (args?: any, extra?: any) => Promise<any>>} the tools; a call gives what the tool gives,
 *   and throws what recordTools throws (NotTaken where the call is not allowed)
 */
export function traceTools(recorder, tools, options = {}) {
  const settings = settingsOf(options, OPTIONS);
  if (tools === null || typeof tools !== 'object' || Array.isArray(tools)) throw new TypeError('tools: must be an object that holds the tools by name.');
  // Every description is checked by recordTools now, so that a mistake is found when the tools are put together, not at the first call.
  const fixed = {};
  for (const name of Object.keys(tools)) {
    const spec = tools[name];
    if (spec === null || typeof spec !== 'object') throw new TypeError(`tools.${name}: must be an object.`);
    const { callId, ...rest } = spec;
    if (callId !== undefined && typeof callId !== 'function') throw new TypeError(`tools.${name}.callId: must be a function.`);
    fixed[name] = Object.freeze({ callId, rest: Object.freeze({ ...rest }) });
  }
  recordTools(recorder, Object.fromEntries(Object.entries(fixed).map(([name, t]) => [name, t.rest])));

  const traced = {};
  for (const [name, { callId: callIdOf, rest }] of Object.entries(fixed)) {
    Object.defineProperty(traced, name, {
      enumerable: true,
      value: async (args, extra) => {
        let callId = null;
        if (callIdOf) {
          try {
            callId = identifier(callIdOf(extra));
          } catch {
            callId = null;
          }
        }
        return withSpan(settings, name, callId, async (span, own) => {
          const binding = await bindings(settings, span, callId);
          const traceBound = binding.some((d) => d.name === TRACE_ID);
          // What the caller's own functions throw is the caller's: an error
          // that one of them threw (a NotTaken from another stub writer,
          // say) is never read as this call's check saying no.
          const thrown = new Set();
          let started = false;
          const sync = (fn) => (typeof fn === 'function' ? (...a) => {
            try {
              return (0, fn)(...a);
            } catch (e) {
              thrown.add(e);
              throw e;
            }
          } : fn);
          const later = (fn) => (typeof fn === 'function' ? async (...a) => {
            try {
              return await (0, fn)(...a);
            } catch (e) {
              thrown.add(e);
              throw e;
            }
          } : fn);
          const run = later(rest.run);
          // The documents the tool names, as recordTools would name them, and the bindings after them.
          const details =
            binding.length === 0
              ? later(rest.details)
              : async (a) => {
                  let named = [];
                  if (typeof rest.details === 'function') named = (await later(rest.details)(a)) ?? [];
                  else if (rest.details !== false && a !== undefined) named = [{ name: 'provared.arguments', sha256: await argumentsFingerprint(a) }];
                  return Array.isArray(named) ? [...named, ...after(named, binding)] : named;
                };
          let stub = null;
          const onStub = async (written, tool) => {
            stub = written;
            if (settings.onStub) await settings.onStub(written, tool);
          };
          const spec = {
            ...rest,
            run: (a) => {
              started = true;
              return run(a);
            },
            details,
            amount: sync(rest.amount),
            with: sync(rest.with),
            countersign: later(rest.countersign),
            approve: later(rest.approve),
          };
          for (const member of ['details', 'amount', 'with', 'countersign', 'approve']) if (spec[member] === undefined) delete spec[member];
          const tool = recordTools(recorder, { [name]: spec }, { onStub })[name];
          try {
            const result = await tool(args);
            annotate(span, { outcome: 'taken', action: rest.action, stub, traceBound });
            return result;
          } catch (e) {
            const fromCheck = e instanceof NotTaken && e.tool === name && !started && !thrown.has(e);
            if (fromCheck) markNotTaken(span, own, rest.action, e.answer, e.denial, settings);
            // "onStub" failed after the receipt was written: the receipt stands, and the error is the caller's.
            else if (stub) {
              annotate(span, { outcome: 'taken', action: rest.action, stub, traceBound });
              if (own && span) {
                span.setAttribute(ERROR_TYPE, errorType(e));
                span.setStatus({ code: SpanStatusCode.ERROR });
              }
            } else markError(span, own, rest.action, e);
            throw e;
          }
        });
      },
    });
  }
  return traced;
}

/**
 * Take one action through the stub writer's "act", and trace it, as
 * traceTools does for a tool. The request, "perform" and "more" are those
 * of "act"; "more.detailsAfter" is passed on.
 *
 * Where "more.approval" is given, no binding is added to the request: the
 * person approved the request as it stands, and an approval covers exactly
 * the documents the person saw. The span still names the receipt. Where
 * "request.details" is given and is not a list, the request is passed on
 * as it is, for "act" to refuse.
 *
 * @param {object} recorder the stub writer (openRecorder)
 * @param {{action: string, amount?: object, with?: string, details?: object[]}} request
 * @param {() => Promise<any>} perform takes the action
 * @param {object} [more] as for "act"
 * @param {object} [options] as for traceTools, and:
 * @param {string} [options.toolName] gen_ai.tool.name and the span's name, 1 to 64 visible ASCII characters;
 *   by default the action name where it has that form, or else "action"
 * @param {string} [options.callId] the identifier the model gave the call
 * @returns {Promise<object>} what "act" gives; a call not taken is not thrown, as with "act"
 */
export async function traceAct(recorder, request, perform, more = {}, options = {}) {
  const settings = settingsOf(options, ACT_OPTIONS);
  if (recorder === null || typeof recorder !== 'object' || typeof recorder.act !== 'function') throw new TypeError('recorder: must be a stub writer.');
  if (request === null || typeof request !== 'object') throw new TypeError('request: must be an object.');
  const toolName = settings.toolName ?? actionOrNull(request.action) ?? 'action';
  const callId = settings.callId ?? null;
  const approved = more !== null && typeof more === 'object' && more.approval !== undefined && more.approval !== null;
  const later = more !== null && typeof more === 'object' && more.detailsAfter !== undefined && more.detailsAfter !== null;
  const listed = request.details === undefined || Array.isArray(request.details);
  return withSpan(settings, toolName, callId, async (span, own) => {
    let binding = approved || !listed ? [] : await bindings(settings, span, callId);
    // "detailsAfter" may name the platform's own identifier for the call: then the model's is not added beside it.
    if (later) binding = binding.filter((d) => d.name !== EVENT_ID);
    const traceBound = binding.some((d) => d.name === TRACE_ID);
    const given = Array.isArray(request.details) ? request.details : [];
    const asked = binding.length === 0 ? request : { ...request, details: [...given, ...after(given, binding)] };
    let outcome;
    try {
      outcome = await recorder.act(asked, perform, more);
    } catch (e) {
      markError(span, own, request.action, e);
      throw e;
    }
    if (outcome.done) annotate(span, { outcome: 'taken', action: request.action, stub: outcome.stub, traceBound });
    else markNotTaken(span, own, request.action, outcome.answer, outcome.denial, settings);
    return outcome;
  });
}
