// The scripted stand-in model. It is the Vercel AI SDK's own mock model for
// tests (MockLanguageModelV4, from "ai/test"). No AI service is called: what
// the "model" says is written here in advance.
//
// First it asks to order printer paper for 30 GBP: inside the slip. Then it
// asks to order a standing desk for 250 GBP: over the limit. Then it answers
// in words. Each step is chosen by how many tool answers it has been given,
// so the script does not depend on how the framework counts its steps.

import { MockLanguageModelV4 } from 'ai/test';

const STEPS = [
  { toolName: 'orderSupplies', input: { item: 'printer paper', totalGbp: 30 } },
  { toolName: 'orderSupplies', input: { item: 'standing desk', totalGbp: 250 } },
  { text: 'I ordered the printer paper. The standing desk was not ordered: it would go over the limit the person set.' },
];

const USAGE = {
  inputTokens: { total: 0, noCache: 0, cacheRead: 0, cacheWrite: 0 },
  outputTokens: { total: 0, text: 0, reasoning: 0 },
};

/** How many tool answers the model has been handed so far. */
function answersSoFar(prompt) {
  let n = 0;
  for (const message of prompt) {
    if (message.role !== 'tool') continue;
    for (const part of message.content) if (part.type === 'tool-result') n++;
  }
  return n;
}

/**
 * The words of the last tool answer the model was handed, and whether the
 * framework marked it as an error: what the agent was told.
 */
export function lastAnswer(prompt) {
  for (let i = prompt.length - 1; i >= 0; i--) {
    if (prompt[i].role !== 'tool') continue;
    const parts = prompt[i].content.filter((p) => p.type === 'tool-result');
    if (parts.length === 0) continue;
    const output = parts[parts.length - 1].output;
    const words = typeof output?.value === 'string' ? output.value : JSON.stringify(output?.value ?? output);
    return { words, error: typeof output?.type === 'string' && output.type.startsWith('error') };
  }
  return null;
}

function step(prompt) {
  const n = answersSoFar(prompt);
  return { n, step: STEPS[Math.min(n, STEPS.length - 1)] };
}

function content({ n, step: s }) {
  if (s.text) return [{ type: 'text', text: s.text }];
  return [{ type: 'tool-call', toolCallId: `call-${n + 1}`, toolName: s.toolName, input: JSON.stringify(s.input) }];
}

function finishReason(s) {
  return s.text ? { unified: 'stop', raw: 'stop' } : { unified: 'tool-calls', raw: 'tool-calls' };
}

/** The scripted model. `seen` keeps every prompt it was handed, for the tests. */
export function scriptedModel() {
  const seen = [];
  const model = new MockLanguageModelV4({
    provider: 'scripted',
    modelId: 'scripted-office-agent',
    doGenerate: async ({ prompt }) => {
      seen.push(prompt);
      const chosen = step(prompt);
      return { content: content(chosen), finishReason: finishReason(chosen.step), usage: USAGE, warnings: [] };
    },
  });
  return { model, seen };
}
