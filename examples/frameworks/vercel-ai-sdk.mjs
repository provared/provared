// An agent built with the Vercel AI SDK (the npm package "ai"), with every
// tool call behind Provared's stub writer. Run it from this folder:
//
//   npm ci --ignore-scripts
//   npm start
//
// The model is the SDK's own scripted stand-in: no AI service is called, and
// nothing is sent anywhere. See README.md.

import { pathToFileURL } from 'node:url';
import { generateText, stepCountIs, tool } from 'ai';
import { z } from 'zod';
import { makeWorld, report } from './_world.mjs';
import { lastAnswer, scriptedModel } from './_model.mjs';
import { holdOffline } from './_offline.mjs';

export async function main(say = console.log) {
  const world = await makeWorld();
  const { model, seen } = scriptedModel();

  // The SDK's tools: each one's "execute" calls the recorded tool. A call the
  // slip does not allow throws NotTaken and the tool is not run; the SDK
  // hands the error's words back to the model as the tool's answer.
  const tools = {
    orderSupplies: tool({
      description: 'Order office supplies from the supplier.',
      inputSchema: z.object({ item: z.string(), totalGbp: z.number().int().nonnegative() }),
      execute: (order) => world.tools.orderSupplies(order),
    }),
    sendMessage: tool({
      description: 'Send a short message to a colleague.',
      inputSchema: z.object({ to: z.string(), text: z.string() }),
      execute: (message) => world.tools.sendMessage(message),
    }),
  };

  const result = await generateText({
    model,
    tools,
    prompt: 'We are out of printer paper, and Alex asked for a standing desk.',
    stopWhen: stepCountIs(5),
    telemetry: { isEnabled: false },
  });

  const told = lastAnswer(seen[seen.length - 1]);
  const check = await report(world, told, result.text, say);
  return { world, result, check, seen };
}

// Run by itself: the guard is opened (if "npm start" has not already opened
// it, before any module was loaded) and stays open until the process ends.
if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  holdOffline();
  await main();
}
