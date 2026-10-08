// What every set of shared test cases uses: an answer is {ok: value} or
// {refused: {code, message}}, and a set is written with the answer this
// library gives for each case.

import { problemFrom } from '../../src/encoding.js';

/** The answer to one case: what the work gives, or why it was refused. */
export async function answer(work) {
  try {
    return { ok: await work() };
  } catch (e) {
    return { refused: problemFrom(e) };
  }
}

/** A set of cases, each with the answer this library gives ("expected"). */
export async function finish(about, fn, cases, answers) {
  for (const c of cases) c.expected = JSON.parse(JSON.stringify(await answers[fn](c)));
  return { about, function: fn, cases };
}
