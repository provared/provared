// A small world for tests: a person with a (stand-in) passkey, an agent, a
// service, a signed slip, and a way to add stubs to a book.

import {
  assembleApproval,
  assembleCancellation,
  assembleSlip,
  countersign,
  fingerprint,
  fromBase64url,
  generateKeySet,
  generateSealKeySet,
  openRecorder,
  prepareApproval,
  prepareCancellation,
  prepareSlip,
  toBase64url,
  writeAcknowledgement,
  writeBook,
  writePass,
  writeRefusal,
  writeSeal,
  writeStub,
  writeTerms,
  writeVouching,
  writeWithdrawal,
} from '../../src/index.js';
import { canonicalJson } from '../../src/encoding.js';
import { makeBlockStamp } from './blockstamp.mjs';
import { makePasskey } from './passkey.mjs';
import { makeStampService } from './stamp.mjs';

export const START = Date.parse('2026-10-05T09:00:00Z');

/**
 * @param {object} [o]
 * @param {string} [o.passkeyAlg]
 * @param {object} [o.fields] members of the slip to override
 * @param {object} [o.assertion] changes to the passkey's answer (see makePasskey)
 * @param {string[]} [o.cover] fields of the slip to cover; the disclosures are in "prepared.disclosures"
 * @param {{keys: object[], privateKeys: any[]}} [o.agent] the agent's key set; a new one by default
 * @param {{keys: object[], privateKeys: any[]}} [o.service] the service's key set; a new one by default
 */
export async function makeWorld(o = {}) {
  const passkey = await makePasskey(o.passkeyAlg ?? 'ES256');
  const agent = o.agent ?? (await generateKeySet());
  const service = o.service ?? (await generateKeySet());
  const fields = {
    issuer: { name: 'Sam Example', key: passkey.key, rpId: passkey.rpId, origin: passkey.origin },
    agent: { name: 'Office supplies agent', keys: agent.keys },
    actions: ['supplies.order'],
    limits: [{ action: 'supplies.order', max: 200, unit: 'GBP' }],
    with: [{ id: 'supplier', name: 'Example Stationery (invented)', keys: service.keys }],
    validFrom: '2026-10-05T08:00:00Z',
    validUntil: '2026-10-12T08:00:00Z',
    purpose: 'Keep the office stocked with paper, pens and toner.',
    ...o.fields,
  };
  const prepared = await prepareSlip(fields, { cover: o.cover });
  const slip = assembleSlip(prepared, await passkey.sign(prepared.challenge, o.assertion));
  const slipFingerprint = await fingerprint(fromBase64url(slip.payload));

  const world = {
    passkey,
    agent,
    service,
    fields,
    prepared,
    slip,
    slipFingerprint,
    entries: [{ slip }],
    after: null,
    count: 0,
    /**
     * Add a stub to the book. By default: an order of 10 GBP with the
     * supplier, countersigned, one hour after the stub before.
     */
    async add(change = {}) {
      const when = change.when ?? START + world.count * 3600 * 1000;
      const request = {
        slip: change.slip ?? slipFingerprint,
        action: change.action ?? 'supplies.order',
        amount: 'amount' in change ? change.amount : { unit: 'GBP', value: change.value ?? 10 },
        with: 'with' in change ? change.with : 'supplier',
        details: change.details,
      };
      // "approve: true" has the person approve exactly this action first.
      // "approve: {...}" changes what the person approves, or how the
      // passkey answers ("assertion").
      let approval;
      if (change.approve) {
        const { assertion, ...other } = change.approve === true ? {} : change.approve;
        approval = await world.approve({ ...request, when: when - 60000, ...other }, assertion);
      }
      const stub = await writeStub(
        {
          ...request,
          after: 'after' in change ? change.after : world.after,
          id: change.id,
          approval: 'approval' in change ? change.approval : approval?.fingerprint,
          terms: change.terms,
          pass: change.pass,
          when,
        },
        change.signer ?? agent.privateKeys,
      );
      const entry = { stub: stub.record };
      if (approval) entry.approval = approval.record;
      if (change.countersigned !== false) {
        entry.countersignature = await countersign(stub.record, change.countersigner ?? service.privateKeys, when + 60000);
      }
      world.entries.push(entry);
      world.after = { seq: stub.seq, fingerprint: stub.fingerprint };
      world.count++;
      return { ...stub, entry };
    },
    /**
     * An agent hands part of its permission to a helper agent. It returns
     * the helper, with an "add" of its own for stubs under the pass.
     */
    async pass(change = {}) {
      const helper = change.helper ?? (await generateKeySet());
      const pass = await writePass(
        {
          slip: change.slip ?? slipFingerprint,
          from: change.from,
          to: { keys: helper.keys, name: change.name ?? 'Helper agent' },
          actions: change.actions ?? ['supplies.order'],
          limits: change.limits ?? [],
          validFrom: change.validFrom ?? fields.validFrom,
          validUntil: change.validUntil ?? fields.validUntil,
          when: change.when ?? START,
        },
        change.signer ?? agent.privateKeys,
      );
      world.entries.push({ pass: pass.record });
      let after = null;
      return {
        ...pass,
        helper,
        /** A stub by the helper, under the pass, in the helper's own chain. */
        async add(more = {}) {
          const saved = { after: world.after, count: world.count };
          const stub = await world.add({ after, pass: pass.fingerprint, signer: helper.privateKeys, ...more });
          after = { seq: stub.seq, fingerprint: stub.fingerprint };
          // The helper's stubs do not move the first agent's chain on.
          world.after = saved.after;
          return stub;
        },
      };
    },
    /** The person approves one action with the passkey. */
    async approve(request, assertion) {
      const prepared = await prepareApproval(request);
      return { record: assembleApproval(prepared, await passkey.sign(prepared.challenge, assertion)), fingerprint: prepared.fingerprint };
    },
    /** The service writes a refusal and it goes into the book. */
    async refuse(change = {}) {
      const signer = change.signer ?? service;
      const refusal = await writeRefusal(
        {
          slip: change.slip ?? slipFingerprint,
          by: change.by ?? { keys: signer.keys, name: 'Example Stationery (invented)' },
          action: change.action ?? 'supplies.order',
          amount: change.amount,
          reason: change.reason ?? 'over-limit',
          when: change.when ?? START + world.count * 3600 * 1000,
        },
        change.privateKeys ?? signer.privateKeys,
      );
      world.entries.push({ refusal: refusal.record });
      return refusal;
    },
    /** The service publishes its terms for agents and they go into the book. */
    async publishTerms(change = {}) {
      const signer = change.signer ?? service;
      const terms = await writeTerms(
        {
          by: { keys: signer.keys, name: 'Example Stationery (invented)' },
          accepts: change.accepts ?? ['supplies.order'],
          never: change.never ?? [],
          validFrom: change.validFrom ?? '2026-10-01T00:00:00Z',
          validUntil: change.validUntil ?? '2027-10-01T00:00:00Z',
        },
        change.privateKeys ?? signer.privateKeys,
      );
      world.entries.push({ terms: terms.record });
      return terms;
    },
    /**
     * The person cancels the slip with the passkey. "stampTime" has a
     * made-up time-stamp service state when the cancellation existed.
     */
    async cancel(change = {}) {
      const when = change.when ?? START + world.count * 3600 * 1000 + 10 * 60 * 1000;
      const prepared = await prepareCancellation({ slip: change.slip ?? slipFingerprint, when });
      const record = assembleCancellation(prepared, await (change.passkey ?? passkey).sign(prepared.challenge, change.assertion));
      const entry = { cancellation: record };
      if (change.stampTime !== undefined) {
        world.stampService ??= await makeStampService();
        entry.stamps = [toBase64url(await world.stampService.stamp(fromBase64url(prepared.fingerprint), change.stampTime))];
      }
      world.entries.push(entry);
      return { record, fingerprint: prepared.fingerprint, entry, when };
    },
    /**
     * The agent's side acknowledges that it was handed a cancellation; the
     * record goes into the book. "pass" and "signer" make it a helper's.
     */
    async acknowledge(cancellationFingerprint, change = {}) {
      const acknowledgement = await writeAcknowledgement(
        { slip: change.slip ?? slipFingerprint, cancellation: cancellationFingerprint, pass: change.pass, id: change.id, when: change.when ?? START + world.count * 3600 * 1000 + 11 * 60 * 1000 },
        change.signer ?? agent.privateKeys,
      );
      world.entries.push({ acknowledgement: acknowledgement.record });
      return { ...acknowledgement, entry: world.entries.at(-1) };
    },
    /** An organisation vouches for a name; the record goes into the book. */
    async vouch(who, change = {}) {
      world.organisation ??= await generateKeySet();
      const signer = change.signer ?? world.organisation;
      const vouching = await writeVouching(
        {
          by: { keys: signer.keys, name: change.by ?? 'Example Organisation (invented)' },
          for: who,
          validFrom: change.validFrom ?? '2026-01-01T00:00:00Z',
          validUntil: change.validUntil ?? '2027-01-01T00:00:00Z',
          when: change.when ?? Date.parse('2026-10-01T09:00:00Z'),
        },
        change.privateKeys ?? signer.privateKeys,
      );
      world.entries.push({ vouching: vouching.record });
      return vouching;
    },
    /** The organisation withdraws a vouching record. */
    async withdraw(vouchingFingerprint, change = {}) {
      const withdrawal = await writeWithdrawal({ vouching: vouchingFingerprint, when: change.when ?? START }, change.privateKeys ?? world.organisation.privateKeys);
      world.entries.push({ withdrawal: withdrawal.record });
      return withdrawal;
    },
    /**
     * Whoever keeps the book seals it as it stands, and a made-up
     * time-stamp service stamps the seal one minute later. Signing a seal
     * takes about a second and a half, so tests seal sparingly.
     * "blockTime" also puts a made-up block time-stamp beside the seal, in
     * a block that states that time; "stamp: false" leaves the service's out.
     */
    async seal(change = {}) {
      world.recorder ??= await generateSealKeySet();
      world.stampService ??= await makeStampService();
      const when = change.when ?? START + world.count * 3600 * 1000 + 30 * 60 * 1000;
      const sealed = await writeSeal(
        world.book(),
        { by: { keys: world.recorder.keys, name: 'Example recorder (invented)' }, previous: 'previous' in change ? change.previous : world.lastSeal, when },
        world.recorder.privateKeys,
      );
      const entry = { seal: sealed.record };
      if (change.stamp !== false) {
        const service = change.service ?? world.stampService;
        entry.stamps = [toBase64url(await service.stamp(sealed.fingerprintBytes, change.stampTime ?? when + 60000))];
      }
      let block;
      if (change.blockTime !== undefined) {
        block = await makeBlockStamp(sealed.fingerprintBytes, change.blockTime);
        (entry.stamps ??= []).push(block.item);
      }
      world.entries.push(entry);
      world.lastSeal = sealed.fingerprint;
      return { ...sealed, entry, when, block };
    },
    book() {
      return writeBook(world.entries);
    },
  };
  return world;
}

/**
 * Open a stub writer for a test. "act" takes an action at the clock's time,
 * and nothing is written that is dated ahead of the clock. The tests use
 * dates of their own. So unless a test gives a clock ("now"), the clock
 * here starts at START and is moved on to the date a test gives an action
 * or a stub, never back.
 */
export async function openWriter(options) {
  let clock = START;
  const writer = await openRecorder({ now: () => clock, ...options });
  const moveOn = (more) => {
    if (more && more.when !== undefined) clock = Math.max(clock, new Date(more.when).getTime());
  };
  return {
    ...writer,
    act(request, perform, more) {
      moveOn(more);
      return writer.act(request, perform, more);
    },
    record(request, more) {
      moveOn(more);
      return writer.record(request, more);
    },
  };
}

/**
 * Decode a record's content, change it, and put it back without signing
 * again. The changed content is written in the canonical form, unless the
 * change returns text, which is then used as it is.
 */
export function withContent(record, change) {
  const content = JSON.parse(Buffer.from(record.payload, 'base64url').toString());
  const changed = change(content) ?? content;
  return { ...record, payload: Buffer.from(typeof changed === 'string' ? changed : canonicalJson(changed)).toString('base64url') };
}
