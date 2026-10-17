import { pathToFileURL } from 'node:url';
import { relayCall } from './terminal-relay.mjs';
import { FRAME_BYTES, parseFrame, terminalSafeJson } from './terminal-review-contract.mjs';

export async function readTerminalInput(stream, timeoutMs = 30_000) {
  const chunks = [];
  let size = 0;
  const timer = setTimeout(() => stream.destroy(new Error('terminal stdin deadline exceeded')), timeoutMs);
  try {
  for await (const chunk of stream) {
    size += chunk.length;
    if (size > FRAME_BYTES) throw new Error('terminal input byte limit exceeded');
    chunks.push(chunk);
  }
  return parseFrame(Buffer.concat(chunks));
  } finally { clearTimeout(timer); }
}
export async function terminalClient(argv) {
  const [operation, flag, socketPath, ...rest] = argv;
  if (!['claim', 'submit', 'status'].includes(operation) || flag !== '--socket' || !socketPath || rest.length) throw new Error('usage: terminal-review-client.mjs claim|submit|status --socket <owner-only-path>');
  const request = operation === 'submit' ? await readTerminalInput(process.stdin) : { version: 1, method: `review.${operation}` };
  if (operation === 'submit' && request?.method !== 'review.submit') throw new Error('expected a review.submit data frame');
  const response = await relayCall(socketPath, request);
  if (operation === 'claim') {
    const { request: review, claimId } = response;
    response.submissionTemplate = { version: 1, method: 'review.submit', requestId: review.requestId, jobId: review.jobId, sourceDigest: review.sourceDigest, claimId, result: { summary: 'Replace with the supplied review; origin remains unverified.', notes: [] } };
  }
  process.stdout.write(`${terminalSafeJson(response)}\n`);
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  terminalClient(process.argv.slice(2)).catch(() => {
    console.error('Terminal review request failed or was rejected. No command was executed.');
    process.exitCode = 2;
  });
}
