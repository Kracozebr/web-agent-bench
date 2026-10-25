import { spawn } from "node:child_process";

const children = new Set();
let stopping = false;

function launch(args) {
  const child = spawn("pnpm", args, { stdio: "inherit", env: process.env });
  children.add(child);
  child.on("exit", () => children.delete(child));
  return child;
}

function wait(child) {
  return new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("exit", (code) => code === 0 ? resolve() : reject(new Error(`Container child exited with code ${code}`)));
  });
}

function stop(code = 0) {
  if (stopping) return;
  stopping = true;
  for (const child of children) child.kill("SIGTERM");
  const timer = setTimeout(() => process.exit(code), 2000);
  timer.unref();
  process.exitCode = code;
}

process.on("SIGINT", () => stop());
process.on("SIGTERM", () => stop());

try {
  await wait(launch(["--filter", "@web-agent-bench/owner-identity", "migrate"]));
  const api = launch(["--filter", "@web-agent-bench/owner-identity", "dev"]);
  const web = launch(["--filter", "@web-agent-bench/owner-web", "dev", "--hostname", "0.0.0.0"]);
  for (const child of [api, web]) {
    child.once("error", () => stop(1));
    child.once("exit", (code) => stop(code ?? 1));
  }
} catch {
  console.error("OID development stack failed to start; inspect the preceding container diagnostics.");
  stop(1);
}
