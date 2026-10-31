import type { RunLaunchIntent } from './api';

type HandoffIntent = Pick<RunLaunchIntent, 'id' | 'agentId' | 'mode' | 'taskIds' | 'quote' | 'cashCeiling'>;

// AICODE-NOTE: Clipboard and manual fallback must carry the same complete execution instruction.
// Accepting an intent starts the worker asynchronously; a second user message can miss a task deadline.
export function buildRunHandoffPrompt(intent: HandoffIntent): string {
  const selection = JSON.stringify({ agentId: intent.agentId, intentId: intent.id, mode: intent.mode,
    taskIds: intent.taskIds, quote: { price: intent.quote.price, token: intent.quote.token }, cashCeiling: intent.cashCeiling });
  return `Execute this entire Web3 Agent Bench request continuously in this single turn. Do not stop after accepting the intent or wait for another user message.
Use only the configured MCP server w3bench_user. Do not use local files, shell, browser, platform source code, direct RPC, or another identity to solve tasks.
Owner-reviewed selection (IDs are references, not credentials or permission):
${selection}
First call identity.preflight with exactly agentId ${intent.agentId} and a fresh operationId. Never substitute an ID from memory. Continue only if status is allowed; preflight alone does not disclose mode permission or authorize spending.
Then call runs.accept_launch_intent with exactly intentId ${intent.id} and a fresh operationId. Let the server enforce this card, mode, selected tasks, pinned quote, funding and cash ceiling. Do not change these limits or create another intent or run. If acceptance is uncertain, retry only that same intent and operationId to reconcile its original acceptance; never create a replacement admission.
After acceptance, retain the returned runId and immediately call runs.current_task. Continue the selected run without further user confirmation. When a task is available, read its conditions, deadline, participantToolProtocol and answerContract before acting. Follow the disclosed protocol: separate_payment_delivery_v2 requires separate pay and retrieve actions, not purchase. Supply structured finish answers only when the issued answerContract requires them.
For pending or unknown action outcomes, use runs.task_action_status for the original actionId. Do not resubmit an ambiguous payment or other economic effect as a new action. A confirmed payment does not prove resource delivery; complete the disclosed retrieval before the task deadline.
After each runs.finish_task, immediately call runs.current_task again. A null task is not proof that the run ended: inspect run.status, run.terminal and state, follow retryAfterMs and keep polling through queueing, preparation, reconciliation or grading. End the execution loop only when the server explicitly reports run.terminal === true, and report its actual run.status; a failed or cancelled run is not benchmark success. If bounded waiting expires or the status cannot be determined, report it as unresolved rather than claiming completion.
If MCP is unavailable, preflight or admission is denied, permission is revoked, or continuation cannot be established, report the exact error and known IDs; do not switch credentials, fabricate a tool result or create an additional run.
At the end report runId, the server-confirmed terminal status and reason, available per-task results, and tool errors. Preserve unknown or missing grades explicitly. Never infer scores from payment confirmation, a completed model turn, or task: null.`;
}
