export interface CoordinatorStartupLease {
  acquire(): Promise<boolean>;
  ownsLease(): boolean;
  stop(): Promise<void>;
}

export interface CoordinatorStartupRetryOptions {
  /** Total wall-clock budget for waiting on the existing singleton owner. */
  maxElapsedMs?: number;
  /** Hard cap even if coordinator construction is unusually fast. */
  maxAttempts?: number;
  retryDelayMs?: number;
  now?: () => number;
  sleep?: (milliseconds: number) => Promise<void>;
}

const DEFAULT_MAX_ELAPSED_MS = 30_000;
const DEFAULT_MAX_ATTEMPTS = 8;
const DEFAULT_RETRY_DELAY_MS = 4_000;

const sleep = (milliseconds: number) => new Promise<void>((resolve) => setTimeout(resolve, milliseconds));

function startupError(code: string): Error {
  return new Error(code);
}

async function stopFailedCoordinator(coordinator: CoordinatorStartupLease): Promise<void> {
  try { await coordinator.stop(); }
  catch { throw startupError('bef_task_coordinator_startup_cleanup_failed'); }
}

/**
 * AICODE-NOTE: Acquire the singleton before HTTP listen. A failed acquisition destroys its lease
 * object, so every contention retry must construct and clean up a fresh coordinator instance.
 */
export async function acquireCoordinatorForStartup<T extends CoordinatorStartupLease>(
  createCoordinator: () => Promise<T>,
  options: CoordinatorStartupRetryOptions = {},
): Promise<T> {
  const maxElapsedMs = options.maxElapsedMs ?? DEFAULT_MAX_ELAPSED_MS;
  const maxAttempts = options.maxAttempts ?? DEFAULT_MAX_ATTEMPTS;
  const retryDelayMs = options.retryDelayMs ?? DEFAULT_RETRY_DELAY_MS;
  const now = options.now ?? Date.now;
  const wait = options.sleep ?? sleep;
  if (!Number.isSafeInteger(maxElapsedMs) || maxElapsedMs < 1 || maxElapsedMs > 120_000 ||
      !Number.isSafeInteger(maxAttempts) || maxAttempts < 1 || maxAttempts > 32 ||
      !Number.isSafeInteger(retryDelayMs) || retryDelayMs < 0 || retryDelayMs > 30_000) {
    throw startupError('bef_task_coordinator_startup_retry_config_invalid');
  }

  const deadline = now() + maxElapsedMs;
  const instances = new WeakSet<object>();
  for (let attempt = 0; attempt < maxAttempts && now() < deadline; attempt += 1) {
    let coordinator: T;
    try { coordinator = await createCoordinator(); }
    catch { throw startupError('bef_task_coordinator_startup_factory_failed'); }
    if (!coordinator || typeof coordinator !== 'object') {
      throw startupError('bef_task_coordinator_startup_factory_invalid');
    }
    if (instances.has(coordinator)) {
      // The previous attempt already stopped this instance. Never re-arm a lost lease object.
      throw startupError('bef_task_coordinator_startup_instance_reused');
    }
    instances.add(coordinator);

    let acquired = false;
    try { acquired = await coordinator.acquire(); }
    catch {
      await stopFailedCoordinator(coordinator);
      throw startupError('bef_task_coordinator_startup_acquire_failed');
    }

    if (acquired) {
      let ownsLease = false;
      try { ownsLease = coordinator.ownsLease(); }
      catch { ownsLease = false; }
      if (ownsLease && now() < deadline) return coordinator;
    }

    await stopFailedCoordinator(coordinator);
    const remainingMs = deadline - now();
    if (attempt + 1 >= maxAttempts || remainingMs <= 0) break;
    await wait(Math.min(retryDelayMs, remainingMs));
  }
  throw startupError('bef_task_coordinator_startup_lease_unavailable');
}
