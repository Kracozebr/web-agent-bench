import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  createReportClosureStateStore,
  initializeReportClosureStateFile,
  REPORT_CLOSURE_STATE_SCHEMA
} from "./report-closure-state.js";

const sourceHash = "a".repeat(64);
const closedHash = "b".repeat(64);
const closedAt = "2026-10-28T12:34:56.789Z";
type TestContext = { after(callback: () => void | Promise<void>): void; skip(message: string): void };

async function temporaryState(t: TestContext) {
  const directory = await mkdtemp(join(tmpdir(), "report-closure-state-"));
  t.after(async () => { await rm(directory, { recursive: true, force: true }); });
  return { directory, path: join(directory, "closure.json") };
}

test("explicit initialization writes the required private v1 schema and null closure", async (t) => {
  const { path } = await temporaryState(t);
  await initializeReportClosureStateFile(path, sourceHash);
  const state = createReportClosureStateStore(path);
  assert.deepEqual(await state.readAuthoritativeClosure(), { betaEndedAt: null, sourceEvidenceSha256: sourceHash });
  assert.deepEqual(JSON.parse(await readFile(path, "utf8")), {
    schemaVersion: REPORT_CLOSURE_STATE_SCHEMA,
    betaEndedAt: null,
    sourceEvidenceSha256: sourceHash
  });
});

test("missing or malformed operator state fails closed", async (t) => {
  const { path } = await temporaryState(t);
  const store = createReportClosureStateStore(path);
  await assert.rejects(store.readAuthoritativeClosure(), /missing or incomplete/);
  await writeFile(path, JSON.stringify({ schema: REPORT_CLOSURE_STATE_SCHEMA, betaEndedAt: null, sourceEvidenceSha256: sourceHash }), { mode: 0o600 });
  await assert.rejects(store.readAuthoritativeClosure(), /invalid/);
});

test("closure is monotonic, immutable and idempotent", async (t) => {
  const { path } = await temporaryState(t);
  await initializeReportClosureStateFile(path, sourceHash);
  const store = createReportClosureStateStore(path);
  await store.persistAuthoritativeClosure({ betaEndedAt: closedAt, sourceEvidenceSha256: closedHash });
  await store.persistAuthoritativeClosure({ betaEndedAt: closedAt, sourceEvidenceSha256: closedHash });
  assert.deepEqual(await store.readAuthoritativeClosure(), { betaEndedAt: closedAt, sourceEvidenceSha256: closedHash });
  await assert.rejects(store.persistAuthoritativeClosure({ betaEndedAt: "2026-10-29T12:34:56.789Z", sourceEvidenceSha256: closedHash }), /immutable/);
  await assert.rejects(store.persistAuthoritativeClosure({ betaEndedAt: closedAt, sourceEvidenceSha256: sourceHash }), /immutable/);
});

test("an existing operator lock blocks state mutation", async (t) => {
  const { path } = await temporaryState(t);
  await initializeReportClosureStateFile(path, sourceHash);
  await writeFile(`${path}.lock`, "operator recovery required", { mode: 0o600 });
  const store = createReportClosureStateStore(path);
  await assert.rejects(store.persistAuthoritativeClosure({ betaEndedAt: closedAt, sourceEvidenceSha256: closedHash }), /locked/);
  assert.equal((await store.readAuthoritativeClosure()).betaEndedAt, null);
});

test("symlinked closure files are rejected", async (t) => {
  if (process.platform === "win32") return t.skip("symlink behavior is verified in the Linux runtime");
  const { directory, path } = await temporaryState(t);
  const target = join(directory, "target.json");
  await initializeReportClosureStateFile(target, sourceHash);
  await symlink(target, path);
  await assert.rejects(createReportClosureStateStore(path).readAuthoritativeClosure(), /symbolic links/);
});
