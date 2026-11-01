// Judges a set of receipts of the project "Agent Middleware" (AMW) against a
// Provared permission (a slip) that a person signed with a passkey.
//
// The honest route, and the only one taken here: the slip names the AMW
// gateway, in "with", as the service (an executor) through which the
// agent acted; each AMW receipt is checked by the gateway's own published
// key (verify.mjs); and what a verified receipt states (the tool, the
// amount, the time, the outcome) is compared with the slip's actions and
// limits, by the same arithmetic as the Provared checker uses for its own
// receipts. An AMW receipt is never presented as a Provared receipt: it is
// shown as what it is, the gateway's signed statement, and the words of
// every finding say "AMW receipt".
//
// Where the checker's own finding code applies, it is used (action-not-
// allowed, outside-valid-time, over-limit, over-each-limit,
// over-count-limit, over-period-limit, amount-missing, prohibited,
// approval-missing). Where only AMW's own permit can be compared, the
// codes are this reader's own and begin "amw-". What cannot be judged at
// all is listed in CANNOT_SHOW, and stated in every answer.

import { actionKind, argumentsFingerprint } from 'provared';
import { checkSlip } from 'provared/check';
import { readKeys, verifyRecord } from './verify.mjs';

/** The document name under which a Provared receipt may carry an AMW receipt by its fingerprint (see receiptDocument). */
export const DOCUMENT_NAME = 'agent-middleware.receipt';

/** What a judgement of AMW receipts cannot show, stated in every answer. */
export const CANNOT_SHOW = Object.freeze([
  'No chain. An AMW receipt names no earlier receipt and no place in a sequence, so a receipt left out of the middle, a set cut short at either end, or a receipt never written does not show. Totals, counts and periods are counted over the receipts handed over, which may not be all of them.',
  'No countersignature. An AMW receipt is signed by the gateway alone, not by the agent and then by the other side. Where the slip asks for the service\'s countersignature, that condition is not judged.',
  'No signature of the person on the AMW permit. The permit is signed by the gateway\'s key. What the person allowed rests on the Provared slip alone; the AMW permit is compared only where it is handed over, as the gateway\'s own statement.',
  'Approvals by identifier only. An AMW receipt names an approval by an identifier, and no signed approval can be checked. Where the slip asks for the person\'s approval, only whether an identifier is present is judged.',
  'Which agent. An AMW receipt names the agent by a wallet identifier; the slip names the agent by its keys. Nothing ties the two, and the agent signed nothing.',
  'With whom. An AMW receipt names no party beyond the gateway. The slip\'s service is taken to be the gateway, and the other side of each action is not shown.',
  'The gateway\'s word. The outcome, the tool, the amount and the time are what the gateway wrote. The signature shows that its key signed them, not that they are true.',
]);

const NAME = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const UNIT = /^[A-Za-z0-9][A-Za-z0-9._-]{0,15}$/;
const MAX_VALUE = BigInt(Number.MAX_SAFE_INTEGER);
// The date and time, then the rest (an optional fraction, then "Z" or an
// offset), read apart, so that no part of the pattern is optional.
const AMW_TIME = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(Z|[^\d].*)$/;
const AMW_FRACTION = /^\.(\d{1,9})$/;
const AMW_OFFSET = /^[+-]\d{2}:\d{2}$/;
const WHOLE = /^(0|[1-9][0-9]*)$/;
const DIGITS = /^[0-9]+$/;

const isText = (v) => typeof v === 'string';
const isObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

class JudgeRefusal extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
}

/**
 * The document that carries an AMW receipt inside a Provared receipt's
 * "details": its name and the fingerprint of the AMW envelope, as handed
 * over, written in the one form of RFC 8785. Whoever keeps the AMW receipt
 * can then show that it is the one the Provared receipt named.
 * @param {object} bundle the AMW envelope
 * @returns {Promise<{name: string, sha256: string}>}
 */
export async function receiptDocument(bundle) {
  if (!isObject(bundle)) throw new TypeError('receiptDocument: give the AMW envelope as an object.');
  return { name: DOCUMENT_NAME, sha256: await argumentsFingerprint(bundle) };
}

/**
 * A time as AMW writes it (RFC 3339 with an offset, such as
 * "2026-09-14T17:00:00+00:00"), as milliseconds since 1970, or NaN.
 * @param {unknown} text
 * @returns {number}
 */
export function parseAmwTime(text) {
  if (!isText(text)) return NaN;
  const m = AMW_TIME.exec(text);
  if (!m) return NaN;
  const [y, mo, d, h, mi, s] = m.slice(1, 7).map(Number);
  // What follows the seconds: "Z" or an offset, with an optional fraction before it.
  let rest = m[7];
  let fraction = null;
  if (rest.startsWith('.')) {
    const end = rest.search(/[Z+-]/);
    if (end < 0) return NaN;
    fraction = AMW_FRACTION.exec(rest.slice(0, end));
    if (!fraction) return NaN;
    rest = rest.slice(end);
  }
  if (rest !== 'Z' && !AMW_OFFSET.test(rest)) return NaN;
  const base = Date.UTC(y, mo - 1, d, h, mi, s);
  const check = new Date(base);
  // A date that does not exist (30 February, 25:00) does not come back as it went in.
  if (check.getUTCFullYear() !== y || check.getUTCMonth() !== mo - 1 || check.getUTCDate() !== d || check.getUTCHours() !== h || check.getUTCMinutes() !== mi || check.getUTCSeconds() !== s) return NaN;
  const ms = fraction ? Number(fraction[1].padEnd(3, '0').slice(0, 3)) : 0;
  let offset = 0;
  if (rest !== 'Z') {
    const oh = Number(rest.slice(1, 3));
    const om = Number(rest.slice(4, 6));
    if (oh > 23 || om > 59) return NaN;
    offset = (rest[0] === '-' ? -1 : 1) * (oh * 60 + om) * 60000;
  }
  return base + ms - offset;
}

/**
 * AMW's credits, a decimal written as text ("2.5"), as a whole number of
 * the smallest unit: with 2 decimal places, "2.5" is 250n. Nothing is
 * rounded: a text with more decimal places than stated, unless they are
 * zeros, cannot be read, and neither can a number too large for a
 * Provared amount.
 * @param {unknown} text
 * @param {number} decimals 0 to 18
 * @returns {bigint|null}
 */
export function readCredits(text, decimals) {
  if (!isText(text)) return null;
  const parts = text.split('.');
  if (parts.length > 2 || !WHOLE.test(parts[0]) || (parts.length === 2 && !DIGITS.test(parts[1]))) return null;
  let fraction = parts[1] ?? '';
  if (fraction.length > decimals) {
    if (/[1-9]/.test(fraction.slice(decimals))) return null;
    fraction = fraction.slice(0, decimals);
  }
  const value = BigInt(parts[0] + fraction.padEnd(decimals, '0'));
  return value > MAX_VALUE ? null : value;
}

function periodWords(seconds) {
  if (seconds % 86400 === 0) return seconds === 86400 ? 'any 24 hours' : `any ${seconds / 86400} days`;
  if (seconds % 3600 === 0) return seconds === 3600 ? 'any hour' : `any ${seconds / 3600} hours`;
  return `any ${seconds} seconds`;
}

// The total inside the period that ends at each item, counted back by the
// times the items state: the same rule as the Provared checker's (format
// description, section 4.1). Items are put in order of time; those with
// the same time keep the order in which they were handed over.
function periodTotals(items, periodMs) {
  const sorted = items.map((item, place) => ({ item, place })).sort((a, b) => a.item.when - b.item.when || a.place - b.place);
  const totals = [];
  let head = 0;
  let sum = 0n;
  for (const { item } of sorted) {
    sum += item.value;
    while (sorted[head].item.when <= item.when - periodMs) {
      sum -= sorted[head].item.value;
      head++;
    }
    totals.push({ item, total: sum });
  }
  return totals;
}

// What is shown of an identifier the gateway wrote: printable ASCII only,
// at most 128 characters, anything else as a mark. No identifier is ever
// copied into the words of a finding.
function shown(value) {
  if (!isText(value)) return null;
  return [...value].slice(0, 128).map((ch) => (ch >= ' ' && ch <= '~' ? ch : '�')).join('');
}

function readOptions(options) {
  if (!isObject(options)) throw new JudgeRefusal('bad-field', 'options: must be an object.');
  const { slip, receipts, keys, service, tools, credits, permits, issuerKeys, issuerOrigins, withoutMethods } = options;
  if (slip === undefined) throw new JudgeRefusal('bad-field', 'slip: the Provared slip is missing.');
  if (!Array.isArray(receipts)) throw new JudgeRefusal('bad-field', 'receipts: must be a list of AMW receipt envelopes.');
  if (permits !== undefined && !Array.isArray(permits)) throw new JudgeRefusal('bad-field', 'permits: must be a list of AMW permit envelopes, or left out.');
  let keyList;
  try {
    keyList = readKeys(keys);
  } catch (e) {
    throw new JudgeRefusal('bad-field', `keys: ${e.message}`);
  }
  if (!isText(service) || !NAME.test(service)) throw new JudgeRefusal('bad-field', 'service: must be the id of the service in the slip\'s "with" that is the AMW gateway.');
  const toolMap = new Map();
  if (tools !== undefined) {
    if (!isObject(tools)) throw new JudgeRefusal('bad-field', 'tools: must be an object from AMW tool name to action name, or left out.');
    for (const [tool, action] of Object.entries(tools)) {
      if (!isText(action) || !NAME.test(action)) throw new JudgeRefusal('bad-field', 'tools: each value must be an action name.');
      toolMap.set(tool, action);
    }
  }
  let creditsRead = null;
  if (credits !== undefined) {
    if (!isObject(credits) || !isText(credits.unit) || !UNIT.test(credits.unit) || !Number.isInteger(credits.decimals) || credits.decimals < 0 || credits.decimals > 18) {
      throw new JudgeRefusal('bad-field', 'credits: must be {unit, decimals}: the unit the slip uses for AMW credits, and the number of decimal places (0 to 18) to read them with.');
    }
    creditsRead = { unit: credits.unit, decimals: credits.decimals };
  }
  return { slip, receipts, permits, keyList, service, toolMap, credits: creditsRead, issuerKeys, issuerOrigins, withoutMethods };
}

function readPermits(permits, keyList) {
  const items = [];
  const byId = new Map();
  (permits ?? []).forEach((bundle, place) => {
    const v = verifyRecord(bundle, keyList, 'permit');
    const item = { place, id: shown(v.id), status: v.status, reason: v.reason, key: v.key, active: null, allowedTools: null, from: null, until: null, subject: null };
    if (v.status === 'verified') {
      const c = v.content;
      item.active = c.status === 'active';
      item.allowedTools = Array.isArray(c.allowed_tools) ? c.allowed_tools.filter(isText) : [];
      item.from = parseAmwTime(c.issued_at);
      item.until = parseAmwTime(c.expires_at);
      item.subject = isText(c.subject_wallet_id) ? c.subject_wallet_id : null;
      // Two verified permits with one id: the first handed over counts, and the other is noted.
      if (byId.has(c.permit_id)) item.notes = ['Another verified permit handed over earlier has the same identifier; that one is used.'];
      else byId.set(c.permit_id, item);
    }
    items.push(item);
  });
  return { items, byId };
}

/**
 * Judge AMW receipts against a Provared slip.
 *
 * @param {object} options
 * @param {object|string} options.slip the signed Provared slip (the record, or its JSON text)
 * @param {string[]} [options.issuerKeys] the thumbprints of the passkeys the reader trusts, as for the checker; without it, nothing rests on a key the reader named
 * @param {string[]} [options.issuerOrigins] as for the checker: the page addresses the slip may have been signed at
 * @param {string[]} [options.withoutMethods] as for the checker
 * @param {unknown} options.keys AMW's published key list
 * @param {object[]} options.receipts the AMW receipt envelopes, in any order
 * @param {object[]} [options.permits] the AMW permit envelopes the receipts name, if the reader holds them
 * @param {string} options.service the id of the service in the slip's "with" that is the AMW gateway
 * @param {Record<string, string>} [options.tools] AMW tool name to the slip's action name; a tool not listed is taken to be the action of the same name
 * @param {{unit: string, decimals: number}} [options.credits] how AMW's credits are read as an amount: the slip's unit, and the number of decimal places. Needed where the slip sets any limit or condition on an amount
 * @returns {Promise<object>} see the README, "The answer"
 */
export async function judgeReceipts(options) {
  const result = {
    judged: false,
    problems: [],
    slip: null,
    service: null,
    permits: [],
    receipts: [],
    notJudged: [],
    summary: null,
    cannotShow: [...CANNOT_SHOW],
  };
  try {
    const o = readOptions(options);
    result.service = o.service;

    // The slip, checked as the checker checks it. What it allows is read only if it is sound.
    const slipRecord = isText(o.slip) ? JSON.parse(o.slip) : o.slip;
    const slipOptions = {};
    if (o.issuerKeys !== undefined) slipOptions.issuerKeys = o.issuerKeys;
    if (o.issuerOrigins !== undefined) slipOptions.issuerOrigins = o.issuerOrigins;
    if (o.withoutMethods !== undefined) slipOptions.withoutMethods = o.withoutMethods;
    const checked = await checkSlip(slipRecord, slipOptions);
    result.slip = { fingerprint: checked.fingerprint, issuerKey: checked.issuerKey, signature: checked.signature, problems: checked.problems, notes: checked.notes, content: null };
    if (checked.problems.length > 0) {
      result.problems.push({ code: 'slip-unusable', message: 'The slip did not pass its check, so nothing is judged against it.' });
      return result;
    }
    if (checked.signature.state !== 'valid') {
      result.problems.push({ code: 'slip-unusable', message: 'The slip\'s passkey signature could not be checked on this device, so nothing is judged against it.' });
      return result;
    }
    const s = checked.content;
    result.slip.content = s;
    if (!s.with.some((w) => w.id === o.service)) {
      throw new JudgeRefusal('amw-service-not-in-slip', 'The slip does not name the AMW gateway among the services the agent may deal with ("with"), so no AMW receipt can be judged under it.');
    }
    const needsAmounts = s.limits.some((l) => Object.hasOwn(l, 'unit')) || s.requires.some((r) => Object.hasOwn(r, 'above'));
    if (needsAmounts && !o.credits) {
      throw new JudgeRefusal('amw-credits-not-stated', 'The slip sets a limit or a condition on an amount, and how AMW\'s credits are to be read as that amount was not stated (the "credits" option: the unit and the number of decimal places).');
    }
    if (s.requires.some((r) => r.need === 'countersignature')) result.notJudged.push('countersignature');
    if (s.requires.some((r) => r.need === 'approval')) result.notJudged.push('approval');

    const permits = readPermits(o.permits, o.keyList);
    result.permits = permits.items;

    // Each receipt: checked, then read.
    const compared = [];
    o.receipts.forEach((bundle, place) => {
      const v = verifyRecord(bundle, o.keyList, 'receipt');
      const item = {
        place,
        id: shown(v.id),
        status: v.status,
        reason: v.reason,
        key: v.key,
        compared: false,
        kind: null,
        tool: null,
        action: null,
        when: null,
        amount: null,
        permit: null,
        approval: null,
        findings: [],
        permitFindings: [],
        notes: [],
      };
      result.receipts.push(item);
      if (v.status !== 'verified') {
        item.notes.push('Not compared: the receipt did not verify, and what it says is not shown.');
        return;
      }
      const c = v.content;
      item.permit = shown(c.permit_id);
      item.approval = Object.hasOwn(c, 'approval_id') && isText(c.approval_id) && c.approval_id.length > 0;
      item.tool = shown(c.tool);
      if (c.outcome === 'denied') {
        item.kind = 'denied';
        item.notes.push('Not compared: the gateway states that it refused this call. As a denial, it is the gateway\'s own word and is not counted against the agent.');
        return;
      }
      if (c.outcome !== 'success') {
        item.kind = 'other';
        item.notes.push('Not compared: the receipt states an outcome this reader does not know.');
        return;
      }
      item.kind = 'action';
      const when = parseAmwTime(c.created_at);
      if (Number.isNaN(when)) {
        item.notes.push('Not compared: the receipt\'s time cannot be read.');
        return;
      }
      item.when = new Date(when).toISOString();
      if (!isText(c.tool)) {
        item.notes.push('Not compared: the receipt names no tool.');
        return;
      }
      const action = o.toolMap.has(c.tool) ? o.toolMap.get(c.tool) : c.tool;
      item.action = NAME.test(action) ? action : null;
      if (o.credits) {
        const value = readCredits(c.credits_charged, o.credits.decimals);
        item.amount = value === null ? null : { unit: o.credits.unit, value: value.toString() };
        if (value === null) item.notes.push(`The receipt's credits cannot be read as a whole number of ${o.credits.unit} with ${o.credits.decimals} decimal places; where the slip needs an amount, that is a finding.`);
      }
      item.compared = true;
      compared.push({ item, c, when, action, value: item.amount ? BigInt(item.amount.value) : null });
    });

    // The comparison, in order of time; receipts with the same time keep
    // the order in which they were handed over.
    compared.sort((a, b) => a.when - b.when || a.item.place - b.item.place);
    const sums = new Map();
    const counts = new Map();
    const periods = new Map();
    const validFrom = Date.parse(s.validFrom);
    const validUntil = Date.parse(s.validUntil);
    for (const r of compared) {
      const { item, c, when, action } = r;
      const findings = item.findings;
      let missing = false;
      const amountIn = (unit) => {
        if (r.value !== null && o.credits.unit === unit) return true;
        if (!missing) {
          findings.push({ code: 'amount-missing', message: `The slip sets a limit or a condition in "${unit}" for this action, and the AMW receipt's credits give no amount in that unit.` });
          missing = true;
        }
        return false;
      };

      if (item.action === null) {
        findings.push({ code: 'action-not-allowed', message: 'The slip does not allow this action: the tool\'s name is not in the form of an action name, so no slip could name it.' });
      } else if (!s.actions.includes(action)) {
        findings.push({ code: 'action-not-allowed', message: `The slip does not allow the action "${action}".` });
      }
      const kind = item.action === null ? null : actionKind(action);
      if (kind && s.never.includes(kind)) {
        findings.push({ code: 'prohibited', message: `The slip says the agent must never do an action of the kind "${kind}", and "${action}" is of that kind.` });
      }
      if (when < validFrom || when >= validUntil) {
        findings.push({ code: 'outside-valid-time', message: 'The AMW receipt is dated outside the time the slip allows.' });
      }

      s.limits.forEach((limit, i) => {
        if (limit.action !== action) return;
        const periodMs = Object.hasOwn(limit, 'per') ? limit.per * 1000 : null;
        if (Object.hasOwn(limit, 'count')) {
          if (periodMs === null) {
            const n = (counts.get(i) ?? 0) + 1;
            counts.set(i, n);
            if (n > limit.count) findings.push({ code: 'over-count-limit', message: `This is action number ${n} of this kind among the AMW receipts. The slip allows ${limit.count}.` });
          } else {
            if (!periods.has(i)) periods.set(i, []);
            periods.get(i).push({ when, value: 1n, findings });
          }
          return;
        }
        if (!amountIn(limit.unit)) return;
        const value = r.value;
        if (Object.hasOwn(limit, 'each')) {
          if (value > BigInt(limit.each)) findings.push({ code: 'over-each-limit', message: `This AMW receipt is ${value} ${limit.unit}. The slip allows no single action above ${limit.each} ${limit.unit}.` });
        } else if (periodMs === null) {
          const total = (sums.get(i) ?? 0n) + value;
          sums.set(i, total);
          if (total > BigInt(limit.max)) {
            findings.push({ code: 'over-limit', message: `With this AMW receipt the total is ${total} ${limit.unit}. The slip's limit is ${limit.max} ${limit.unit}: over by ${total - BigInt(limit.max)}.` });
          }
        } else {
          if (!periods.has(i)) periods.set(i, []);
          periods.get(i).push({ when, value, findings });
        }
      });

      // The slip's conditions.
      for (const cond of s.requires) {
        if (Object.hasOwn(cond, 'action') && cond.action !== action) continue;
        if (Object.hasOwn(cond, 'above')) {
          if (!amountIn(cond.unit)) continue;
          if (!(r.value > BigInt(cond.above))) continue;
        }
        if (cond.need === 'approval') {
          if (item.approval) item.notes.push('The slip asks for the person\'s approval of this action. The AMW receipt names an approval by identifier only, and no signed approval can be checked.');
          else findings.push({ code: 'approval-missing', message: 'The slip asks for the person\'s approval of this action, and the AMW receipt names none.' });
        } else if (cond.need === 'countersignature') {
          item.notes.push('The slip asks for the service\'s countersignature of this action. An AMW receipt carries none; it is the gateway\'s own signed statement, which is not a countersignature of a Provared receipt.');
        }
      }

      // The AMW permit the receipt names, where it was handed over: the gateway's own statement of what it allowed.
      if (o.permits !== undefined) {
        const permit = isText(c.permit_id) ? permits.byId.get(c.permit_id) : undefined;
        if (!permit) {
          item.permitFindings.push({ code: 'amw-permit-not-handed-over', message: 'The AMW receipt names a permit that was not handed over, or that did not verify.' });
        } else {
          if (!permit.active) item.permitFindings.push({ code: 'amw-permit-not-active', message: 'The AMW permit it names does not say that it is active.' });
          if (!permit.allowedTools.includes(c.tool)) item.permitFindings.push({ code: 'amw-permit-tool-not-allowed', message: 'The AMW permit it names does not list this tool among the tools it allows.' });
          if (Number.isNaN(permit.from) || Number.isNaN(permit.until) || when < permit.from || when >= permit.until) {
            item.permitFindings.push({ code: 'amw-permit-not-in-force', message: 'The AMW receipt is dated outside the time its AMW permit says it was in force, or that time cannot be read.' });
          }
          if (permit.subject !== null && c.wallet_id !== permit.subject) {
            item.permitFindings.push({ code: 'amw-permit-subject-differs', message: 'The AMW receipt names a wallet other than the subject of the AMW permit it names.' });
          }
        }
      }
    }

    // Limits within a period, once every compared receipt has been read.
    for (const [i, items] of periods) {
      const limit = s.limits[i];
      const allowed = BigInt(Object.hasOwn(limit, 'count') ? limit.count : limit.max);
      for (const { item, total } of periodTotals(items, limit.per * 1000)) {
        if (!(total > allowed)) continue;
        const message = Object.hasOwn(limit, 'count')
          ? `With this AMW receipt there are ${total} such actions in ${periodWords(limit.per)}. The slip allows ${limit.count}.`
          : `With this AMW receipt the total in ${periodWords(limit.per)} is ${total} ${limit.unit}. The slip's limit is ${limit.max} ${limit.unit}.`;
        item.findings.push({ code: 'over-period-limit', message });
      }
    }

    const byStatus = {};
    for (const r of result.receipts) byStatus[r.status] = (byStatus[r.status] ?? 0) + 1;
    const comparedItems = result.receipts.filter((r) => r.compared);
    const withPermits = o.permits === undefined ? null : comparedItems.every((r) => r.permitFindings.length === 0);
    result.summary = {
      handed: result.receipts.length,
      byStatus,
      compared: comparedItems.length,
      denied: result.receipts.filter((r) => r.kind === 'denied').length,
      notCompared: result.receipts.length - comparedItems.length,
      withinSlip: comparedItems.length === 0 ? null : comparedItems.every((r) => r.findings.length === 0),
      withinPermits: comparedItems.length === 0 ? null : withPermits,
      trusted: Array.isArray(o.issuerKeys),
    };
    result.judged = true;
  } catch (e) {
    if (e instanceof JudgeRefusal) result.problems.push({ code: e.code, message: e.message });
    else if (e instanceof SyntaxError) result.problems.push({ code: 'not-json', message: 'The slip is not JSON text.' });
    else result.problems.push({ code: 'check-failed', message: 'The reader met something it did not expect, and gives no pass.' });
  }
  return result;
}
