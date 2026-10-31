// A small invented world, for the example. Everything in it is
// invented: the person, the agent, the supplier and the money. No real firm,
// person or payment is involved, and nothing is sent anywhere.
//
// The permission (the slip) is signed with the library's DEVELOPMENT
// STAND-IN for a passkey: a key made in memory, which no person confirmed.
// Every slip it signs says "(development)" in the issuer's name. A real slip
// is signed by a person, in a browser, with a real passkey.
//
// The slip lets the agent order supplies from the invented supplier, up to
// 100 GBP in all, and send messages.

import { checkBook, recordTools } from 'provared';
import { developmentRecorder } from 'provared/dev';

export const ORDER = 'supplies.order';
export const MESSAGE = 'provared.message.send';
export const SUPPLIER = 'supplier';
export const LIMIT_GBP = 100;

/**
 * The person's slip, the stub writer under it, and the agent's two tools,
 * each put behind the stub writer with recordTools. `orders` and `messages`
 * are what the invented supplier and the invented recipients received, so a
 * reader can see which calls were run.
 */
export async function makeWorld() {
  const { recorder, issuerKeys } = await developmentRecorder({
    issuer: { name: 'Sam Example (invented)' },
    agent: { name: 'Office supplies agent (invented)' },
    actions: [ORDER, MESSAGE],
    limits: [{ action: ORDER, max: LIMIT_GBP, unit: 'GBP' }],
    with: [{ id: SUPPLIER, name: 'Example Stationery (invented)' }],
    purpose: 'Keep the office stocked with paper, pens and toner.',
  });
  const world = { recorder, issuerKeys, orders: [], messages: [] };

  // Each tool: the action name the slip uses, the service, the amount, and
  // the function itself, run only if the slip allows the call. A call that
  // the slip does not allow throws NotTaken, and the function is not run.
  world.tools = recordTools(recorder, {
    orderSupplies: {
      action: ORDER,
      with: SUPPLIER,
      amount: (order) => ({ unit: 'GBP', value: order.totalGbp }),
      run: (order) => {
        world.orders.push(order);
        return `Ordered ${order.item} for ${order.totalGbp} GBP.`;
      },
    },
    sendMessage: {
      action: MESSAGE,
      run: (message) => {
        world.messages.push(message);
        return `Sent to ${message.to}.`;
      },
    },
  });
  return world;
}

/**
 * What happened, in a few lines: who signed the permission, what the supplier received, what the agent
 * was told after its last tool call, its answer, and the checker's answer.
 * The book is checked with checkBook, naming the passkey the checker trusts.
 */
export async function report(world, told, answer, say) {
  const check = await checkBook(world.recorder.book(), { issuerKeys: world.issuerKeys });
  const slip = check.entries.find((entry) => entry.kind === 'slip');
  say(`The permission was signed by "${slip?.content?.issuer?.name}": a development stand-in for a passkey, not a person.`);
  for (const order of world.orders) say(`The supplier received an order: ${order.item}, ${order.totalGbp} GBP.`);
  if (told) say(`The agent was told, after its last tool call${told.error ? ' (marked as an error)' : ''}: ${told.words}`);
  say(`The agent answered: ${answer}`);
  const s = check.summary;
  say(`The book checks as intact: ${s.intact ? 'yes' : 'no'}. ` +
    `The agent stayed within its slip: ${s.withinSlips ? 'yes' : 'no'}. ` +
    `Stubs in the book: ${s.counts.stubs}.`);
  return check;
}
