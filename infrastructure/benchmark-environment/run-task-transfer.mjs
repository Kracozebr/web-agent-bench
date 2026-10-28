// Run inside the owner-identity Docker tool image. Credentials stay in memory.
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { randomUUID } from "node:crypto";
import { spawn } from "node:child_process";
import { createServer, connect } from "node:net";

if (process.platform !== "linux") throw new Error("Run this capture through the Docker runtime");
const captureArguments = process.argv.slice(2);
const trainingCases = captureArguments[0] === "--training-cases" && captureArguments.length === 2 && captureArguments[1] === "env-a";
if ((!trainingCases && captureArguments.length > 1) || (captureArguments.length === 1 && !["--reverse-swap", "--reverse-swap-fee3000", "--native-task-cases", "--resource-catalog", "--reference-cases", "--h3", "--u1", "--u1-v2"].includes(captureArguments[0]))
  || (captureArguments[0] === "--training-cases" && !trainingCases)) {
  throw new Error("Usage: run-task-transfer.mjs [--reverse-swap|--reverse-swap-fee3000|--native-task-cases|--resource-catalog|--reference-cases|--h3|--u1|--u1-v2|--training-cases env-a]");
}
const fee3000ReverseSwap = captureArguments[0] === "--reverse-swap-fee3000";
const reverseSwap = captureArguments[0] === "--reverse-swap" || fee3000ReverseSwap;
const nativeTaskCases = captureArguments[0] === "--native-task-cases";
const resourceCatalog = captureArguments[0] === "--resource-catalog";
const referenceCases = captureArguments[0] === "--reference-cases";
const h3Capture = captureArguments[0] === "--h3";
const u1Capture = captureArguments[0] === "--u1";
const u1V2Capture = captureArguments[0] === "--u1-v2";
const targetEnvironment = referenceCases || fee3000ReverseSwap || nativeTaskCases || u1Capture || u1V2Capture ? "bef-env-b" : "bef-env-a";
const targetProxyPort = referenceCases || fee3000ReverseSwap || nativeTaskCases || u1Capture || u1V2Capture ? 28545 : 18545;
const apiHostPort = process.env.BEF_API_HOST_PORT ?? "8783";
if (!/^[1-9][0-9]{0,4}$/.test(apiHostPort) || Number(apiHostPort) > 65535) {
  throw new Error("BEF_API_HOST_PORT must be a valid TCP port");
}
const secretRoot = resolve("infrastructure/benchmark-environment/.local/secrets");
async function secret(name) {
  const value = (await readFile(resolve(secretRoot, name), "utf8")).trim();
  if (value.length < 16) throw new Error("Required local capture credential is unavailable");
  return value;
}
const captureId = randomUUID();
const captureDirectory = `artifacts/runs/${trainingCases ? "bts-open-training-reference-profile" : u1V2Capture ? "bts-difficulty-v2-reference/u1-ranked" : u1Capture ? "bts-u1-same-generation-reference" : h3Capture ? "bts-h3-paid-route-swap-foundation" : referenceCases ? "bts-reference-foundation" : nativeTaskCases ? "bts-native-task-primitives" : fee3000ReverseSwap ? "bts-route-fee3000" : resourceCatalog ? "bts-resource-catalog-primitive" : reverseSwap ? "bts-reverse-swap-primitive" : "bts-transfer-primitive"}/${captureId}`;
const hostname = "host.docker.internal";
// Preserve the observer's loopback-only endpoint rule inside the container.
// The only relay destination is the already published local BEF proxy.
const sockets = new Set();
const relay = createServer((incoming) => {
  const outgoing = connect({ host: hostname, port: targetProxyPort });
  sockets.add(incoming); sockets.add(outgoing);
  incoming.on("error", () => outgoing.destroy());
  outgoing.on("error", () => incoming.destroy());
  incoming.on("close", () => { sockets.delete(incoming); outgoing.destroy(); });
  outgoing.on("close", () => { sockets.delete(outgoing); incoming.destroy(); });
  incoming.pipe(outgoing); outgoing.pipe(incoming);
});
await new Promise((done, reject) => { relay.once("error", reject); relay.listen(targetProxyPort, "127.0.0.1", done); });
const observerPassword = await secret("database-observer-password");
const environment = {
  ...process.env,
  BEF_API_BASE_URL: `http://${hostname}:${apiHostPort}`,
  BEF_DATABASE_OBSERVER_URL: `postgres://bef_observer:${encodeURIComponent(observerPassword)}@${hostname}:55432/bef`,
  BEF_ADMIN_KEY: await secret("admin-key"),
  BEF_SERVICE_KEY: await secret("service-key"),
  BEF_SOURCE_PROXY_URL: `http://${hostname}:18544`,
  BEF_LOCAL_RPC_PROXY_URL_BEF_ENV_A: "http://127.0.0.1:18545",
  BEF_LOCAL_RPC_PROXY_URL_BEF_ENV_B: referenceCases || fee3000ReverseSwap || nativeTaskCases || u1Capture || u1V2Capture ? "http://127.0.0.1:28545" : `http://${hostname}:28545`,
  BEF_FACILITATOR_URL_BEF_ENV_A: `http://${hostname}:34021`,
  BEF_FACILITATOR_URL_BEF_ENV_B: `http://${hostname}:44021`,
};
const childCommand = u1Capture || u1V2Capture || trainingCases ? process.execPath : "pnpm";
const childArguments = trainingCases
  ? ["--import", "./packages/benchmark-environment/node_modules/tsx/dist/loader.mjs", "packages/benchmark-environment/src/probe/task-training-main.ts",
      "--env-id", targetEnvironment, "--evidence-dir", captureDirectory]
  : u1Capture
  ? ["--import", "./packages/benchmark-environment/node_modules/tsx/dist/loader.mjs", "packages/benchmark-environment/src/probe/task-u1-main.ts",
      "--env-id", targetEnvironment, "--evidence-dir", captureDirectory]
  : u1V2Capture
  ? ["--import", "./packages/benchmark-environment/node_modules/tsx/dist/loader.mjs", "packages/benchmark-environment/src/probe/task-u1-main.ts",
      "--env-id", targetEnvironment, "--evidence-dir", captureDirectory, "--profile", "v2"]
  : ["--filter", "@web-agent-bench/benchmark-environment",
      h3Capture ? "probe:task-h3" : referenceCases ? "probe:task-reference" : nativeTaskCases ? "probe:task-native" : resourceCatalog ? "probe:task-resource-catalog" : reverseSwap ? "probe:task-reverse-swap" : "probe:task-transfer", "--",
      "--env-id", targetEnvironment, "--evidence-dir", captureDirectory, ...(resourceCatalog || h3Capture ? [] : ["--amount-units", "100000"]),
      ...(fee3000ReverseSwap ? ["--fee-tier", "3000"] : [])];
const child = spawn(childCommand, childArguments, { env: environment, stdio: "inherit" });
const exitCode = await new Promise((done, reject) => {
  child.once("error", reject);
  child.once("exit", (code) => done(code ?? 1));
});
for (const socket of sockets) socket.destroy();
await new Promise((done) => relay.close(done));
console.log(JSON.stringify({ captureId, captureDirectory, exitCode, apiHostPort: Number(apiHostPort), feeTier: fee3000ReverseSwap ? 3000 : reverseSwap ? 500 : null, ...(u1V2Capture ? { profile: "difficulty-v2-ranked" } : {}), networkProfile: "docker-loopback-relay-to-host-published-BEF",
  classification: trainingCases || u1Capture || u1V2Capture || h3Capture || referenceCases || nativeTaskCases ? "local_fork_public_tool_evidence_not_bts_task_acceptance" : resourceCatalog ? "selected_executor_resource_catalog_capture_not_bts_acceptance"
    : reverseSwap ? "selected_executor_reverse_swap_capture_not_bts_acceptance" : "selected_executor_primitive_capture_not_bts_acceptance" }));
process.exitCode = exitCode;
