import { BlockNotFoundError, HttpRequestError, TimeoutError, TransactionNotFoundError, TransactionReceiptNotFoundError } from 'viem';

export type PostminePhase = 'receipt' | 'transaction' | 'blocks' | 'poststate' | 'measurement' | 'effects';

export class PostmineObservationError extends Error {
  constructor(readonly phase: PostminePhase, cause: unknown) {
    super(`postmine_${phase}_observation_unavailable`, { cause });
  }
}

export async function inPostminePhase<T>(phase: PostminePhase, read: () => Promise<T> | T): Promise<T> {
  try { return await read(); } catch (cause) { throw new PostmineObservationError(phase, cause); }
}

// AICODE-NOTE: This is an observation retry, never a transaction retry. Only SDK-classified
// transport/visibility failures qualify. Binding contradictions and EVM reverts do not.
export function postmineAvailabilityFailure(error: unknown): boolean {
  if (!(error instanceof PostmineObservationError) || ['measurement', 'effects'].includes(error.phase)) return false;
  let cause: unknown = error.cause;
  for (let depth = 0; depth < 8 && cause instanceof Error; depth++) {
    if (cause instanceof TimeoutError || cause instanceof BlockNotFoundError ||
        cause instanceof TransactionNotFoundError || cause instanceof TransactionReceiptNotFoundError) return true;
    if (cause instanceof HttpRequestError && (cause.status === undefined || [408, 429, 502, 503, 504].includes(cause.status))) return true;
    cause = cause.cause;
  }
  return false;
}

export async function observeOriginalHashWithinBudget<T>(input: {
  deadline: number; read: (remainingMs: number, signal: AbortSignal) => Promise<T>; now?: () => number; sleep?: (ms: number) => Promise<void>;
}): Promise<T> {
  const now = input.now ?? Date.now, sleep = input.sleep ?? ((ms: number) => new Promise<void>(resolve => setTimeout(resolve, ms)));
  if (now() >= input.deadline) throw new Error('postmine_observation_budget_exhausted');
  const controller = new AbortController();
  let timer: ReturnType<typeof setTimeout>;
  const expired = new Promise<never>((_, reject) => {
    timer = setTimeout(() => { controller.abort(); reject(new Error('postmine_observation_budget_exhausted')); }, input.deadline - now());
  });
  try {
    const read = () => Promise.race([input.read(Math.max(0, input.deadline - now()), controller.signal), expired]);
    try { return await read(); }
    catch (error) {
      // One retry, only when 100ms backoff leaves positive time in the original budget.
      if (!postmineAvailabilityFailure(error) || input.deadline - now() <= 100) throw error;
      await Promise.race([sleep(100), expired]);
      if (now() >= input.deadline) throw error;
      return await read();
    }
  } finally {
    clearTimeout(timer!);
  }
}

export function postmineFailureCode(error: unknown): string | null {
  if (error instanceof PostmineObservationError && ['receipt', 'transaction', 'blocks', 'poststate', 'measurement', 'effects'].includes(error.phase)) {
    return `postmine_${error.phase}_observation_unavailable`;
  }
  if (error instanceof Error && [
    'receipt_hash_mismatch', 'original_transaction_binding_mismatch', 'original_receipt_transaction_binding_mismatch',
    'receipt_block_invalid', 'receipt_block_prestate_binding_mismatch', 'receipt_block_transactions_not_expanded',
    'receipt_block_sender_attribution_ambiguous',
    'postmine_observation_budget_exhausted',
    'execution_persistence_measurement_invalid', 'execution_persistence_measurement_action_invalid',
    'execution_persistence_measurement_action_binding_conflict', 'execution_persistence_measurement_action_receipt_conflict',
    'execution_persistence_terminal_binding_conflict',
  ].includes(error.message)) return error.message;
  return null;
}
