import { randomUUID } from "node:crypto";
import { open, lstat, readFile, rename, unlink } from "node:fs/promises";
import { dirname, isAbsolute, parse, resolve, sep } from "node:path";

export const REPORT_CLOSURE_STATE_SCHEMA = "beta-report-closure-state/v1" as const;

export interface AuthoritativeReportClosure {
  betaEndedAt: string | null;
  sourceEvidenceSha256: string;
}

export interface ReportClosureStateStore {
  readAuthoritativeClosure(): Promise<AuthoritativeReportClosure>;
  persistAuthoritativeClosure(state: { betaEndedAt: string; sourceEvidenceSha256: string }): Promise<void>;
}

interface ClosureFile extends AuthoritativeReportClosure {
  schemaVersion: typeof REPORT_CLOSURE_STATE_SCHEMA;
}

function validHash(value: unknown): value is string {
  return typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
}

function validTimestamp(value: unknown): value is string {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value)) return false;
  const parsed = new Date(value);
  return !Number.isNaN(parsed.getTime()) && parsed.toISOString() === value;
}

function validateClosureFile(value: unknown): ClosureFile {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error("Authoritative beta report closure state is invalid");
  const state = value as Record<string, unknown>;
  if (state.schemaVersion !== REPORT_CLOSURE_STATE_SCHEMA ||
    !(state.betaEndedAt === null || validTimestamp(state.betaEndedAt)) || !validHash(state.sourceEvidenceSha256) ||
    Object.keys(state).some((key) => !["schemaVersion", "betaEndedAt", "sourceEvidenceSha256"].includes(key))) {
    throw new Error("Authoritative beta report closure state is invalid");
  }
  return {
    schemaVersion: REPORT_CLOSURE_STATE_SCHEMA,
    betaEndedAt: state.betaEndedAt as string | null,
    sourceEvidenceSha256: state.sourceEvidenceSha256
  };
}

async function assertNoSymlinkPath(path: string, allowMissingFinal = false): Promise<void> {
  const absolute = resolve(path);
  const root = parse(absolute).root;
  const components = absolute.slice(root.length).split(sep).filter(Boolean);
  let current = root;
  for (const component of components) {
    current = resolve(current, component);
    try {
      const info = await lstat(current);
      if (info.isSymbolicLink()) throw new Error("Authoritative beta report closure state path cannot contain symbolic links");
      if (current !== absolute && !info.isDirectory()) throw new Error("Authoritative beta report closure state parent is not a directory");
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT" && allowMissingFinal && current === absolute) return;
      if ((error as NodeJS.ErrnoException).code === "ENOENT") throw new Error("Authoritative beta report closure state path is missing or incomplete");
      throw error;
    }
  }
}

async function readFileState(path: string): Promise<ClosureFile> {
  await assertNoSymlinkPath(path);
  const info = await lstat(path);
  if (!info.isFile() || (process.platform !== "win32" && (info.mode & 0o077) !== 0)) {
    throw new Error("Authoritative beta report closure state must be a private regular file");
  }
  let value: unknown;
  try { value = JSON.parse(await readFile(path, "utf8")); }
  catch { throw new Error("Authoritative beta report closure state cannot be read or parsed"); }
  return validateClosureFile(value);
}

async function writeAtomic(path: string, state: ClosureFile): Promise<void> {
  const temporary = `${path}.${process.pid}.${randomUUID()}.tmp`;
  let handle: Awaited<ReturnType<typeof open>> | undefined;
  try {
    handle = await open(temporary, "wx", 0o600);
    await handle.writeFile(`${JSON.stringify(state)}\n`, "utf8");
    await handle.sync();
    await handle.close();
    handle = undefined;
    await rename(temporary, path);
    const directory = await open(dirname(path), "r");
    try { await directory.sync(); } finally { await directory.close(); }
  } catch (error) {
    if (handle) await handle.close().catch(() => undefined);
    await unlink(temporary).catch(() => undefined);
    throw error;
  }
}

async function withOperatorLock<T>(path: string, action: () => Promise<T>): Promise<T> {
  const lockPath = `${path}.lock`;
  await assertNoSymlinkPath(path, true);
  let lock: Awaited<ReturnType<typeof open>>;
  try { lock = await open(lockPath, "wx", 0o600); }
  catch (error) {
    if ((error as NodeJS.ErrnoException).code === "EEXIST") {
      throw new Error("Authoritative beta report closure is locked; inspect the operator lock before retrying");
    }
    throw error;
  }
  try {
    await lock.sync();
    return await action();
  } finally {
    await lock.close();
    await unlink(lockPath);
    const directory = await open(dirname(path), "r");
    try { await directory.sync(); } finally { await directory.close(); }
  }
}

/** Read required operator state each time; absent or malformed files fail closed. */
export function createReportClosureStateStore(path: string): ReportClosureStateStore {
  if (!isAbsolute(path)) throw new Error("Authoritative beta report closure state path must be absolute");
  const absolute = resolve(path);
  return {
    async readAuthoritativeClosure() {
      const state = await readFileState(absolute);
      return { betaEndedAt: state.betaEndedAt, sourceEvidenceSha256: state.sourceEvidenceSha256 };
    },
    async persistAuthoritativeClosure(next) {
      if (!validTimestamp(next.betaEndedAt) || !validHash(next.sourceEvidenceSha256)) {
        throw new Error("Audited beta report closure metadata is invalid");
      }
      await withOperatorLock(absolute, async () => {
        const current = await readFileState(absolute);
        if (current.betaEndedAt !== null) {
          if (current.betaEndedAt === next.betaEndedAt && current.sourceEvidenceSha256 === next.sourceEvidenceSha256) return;
          throw new Error("Beta report closure is immutable and cannot be moved or reset");
        }
        await writeAtomic(absolute, {
          schemaVersion: REPORT_CLOSURE_STATE_SCHEMA,
          betaEndedAt: next.betaEndedAt,
          sourceEvidenceSha256: next.sourceEvidenceSha256
        });
      });
    }
  };
}

/** Explicit operator provisioning only; runtime startup must never create a missing state file. */
export async function initializeReportClosureStateFile(path: string, sourceEvidenceSha256: string): Promise<void> {
  if (!isAbsolute(path) || !validHash(sourceEvidenceSha256)) throw new Error("Initial beta report closure metadata is invalid");
  const absolute = resolve(path);
  await withOperatorLock(absolute, async () => {
    try {
      await lstat(absolute);
      throw new Error("Authoritative beta report closure state already exists");
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
    await writeAtomic(absolute, {
      schemaVersion: REPORT_CLOSURE_STATE_SCHEMA,
      betaEndedAt: null,
      sourceEvidenceSha256
    });
  });
}
