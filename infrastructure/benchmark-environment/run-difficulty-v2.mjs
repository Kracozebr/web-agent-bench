// Docker-only one-task difficulty-v2 reference capture. Credentials stay in memory.
import { randomUUID } from 'node:crypto';
import { mkdir, readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { spawn } from 'node:child_process';
import { connect, createServer } from 'node:net';
import { fileURLToPath } from 'node:url';

export function parseDifficultyReferenceArguments(args) {
  const values = new Map();
  const offset = args[0] === '--' ? 1 : 0;
  for (let index = offset; index < args.length; index += 1) {
    const flag = args[index];
    if (!['--task-id', '--mode', '--env-id', '--recipient'].includes(flag) || values.has(flag)) throw new Error('usage');
    const value = args[++index];
    if (!value || value.startsWith('--')) throw new Error('usage');
    values.set(flag, value);
  }
  const taskId = values.get('--task-id');
  const mode = values.get('--mode');
  const envId = values.get('--env-id');
  if (!['S1', 'S2', 'S3', 'S4', 'M1', 'M2', 'M3', 'M4', 'H1', 'H2', 'H3'].includes(taskId) || !['ranked', 'training'].includes(mode)
    || (['S3', 'M2', 'H3'].includes(taskId) && mode !== 'ranked')
    || !['bef-env-a', 'bef-env-b'].includes(envId)) throw new Error('usage');
  const recipient = values.get('--recipient');
  if (recipient !== undefined && (taskId !== 'S1' || !/^0x[0-9a-f]{40}$/i.test(recipient) || /^0x0{40}$/i.test(recipient))) throw new Error('usage');
  return { taskId, mode, envId, ...(recipient === undefined ? {} : { recipient: recipient.toLowerCase() }) };
}

function portFromEnvironment(name, fallback) {
  const value = process.env[name] ?? fallback;
  if (!/^[1-9][0-9]{0,4}$/.test(value) || Number(value) > 65535) throw new Error('port');
  return Number(value);
}

async function readLocalSecret(root, name, minimumLength) {
  const value = (await readFile(resolve(root, name), 'utf8')).trim();
  if (value.length < minimumLength) throw new Error('secret');
  return value;
}

async function main() {
  if (process.platform !== 'linux' || process.cwd() !== '/workspace') throw new Error('docker');
  const { taskId, mode, envId, recipient } = parseDifficultyReferenceArguments(process.argv.slice(2));
  const apiPort = portFromEnvironment('BEF_API_HOST_PORT', '38783');
  const observerPort = portFromEnvironment('BEF_DATABASE_OBSERVER_HOST_PORT', '55432');
  const sourcePort = portFromEnvironment('BEF_SOURCE_PROXY_HOST_PORT', '18544');
  const envA = envId === 'bef-env-a';
  const relayPort = envA ? 18545 : 28545;
  const facilitatorPort = envA ? 34021 : 44021;
  const host = 'host.docker.internal';
  const secretRoot = resolve('infrastructure/benchmark-environment/.local/secrets');
  const observerPassword = await readLocalSecret(secretRoot, 'database-observer-password', 1);
  const adminKey = await readLocalSecret(secretRoot, 'admin-key', 32);
  const serviceKey = await readLocalSecret(secretRoot, 'service-key', 32);

  const captureId = randomUUID();
  const captureDirectory = resolve('artifacts/runs/bts-difficulty-v2-reference', `${taskId.toLowerCase()}-${mode}`, captureId);
  await mkdir(captureDirectory, { recursive: true });

  const sockets = new Set();
  const relay = createServer((incoming) => {
    const outgoing = connect({ host, port: relayPort });
    sockets.add(incoming); sockets.add(outgoing);
    incoming.on('error', () => outgoing.destroy());
    outgoing.on('error', () => incoming.destroy());
    incoming.on('close', () => { sockets.delete(incoming); outgoing.destroy(); });
    outgoing.on('close', () => { sockets.delete(outgoing); incoming.destroy(); });
    incoming.pipe(outgoing); outgoing.pipe(incoming);
  });

  try {
    await new Promise((done, reject) => { relay.once('error', reject); relay.listen(relayPort, '127.0.0.1', done); });
    const suffix = envA ? 'BEF_ENV_A' : 'BEF_ENV_B';
    const runtimeEnvironment = {
      PATH: process.env.PATH ?? '',
      HOME: process.env.HOME ?? '/tmp',
      TMPDIR: process.env.TMPDIR ?? '/tmp',
      BEF_API_BASE_URL: `http://${host}:${apiPort}`,
      BEF_DATABASE_OBSERVER_URL: `postgres://bef_observer:${encodeURIComponent(observerPassword)}@${host}:${observerPort}/bef`,
      BEF_ADMIN_KEY: adminKey,
      BEF_SERVICE_KEY: serviceKey,
      BEF_SOURCE_PROXY_URL: `http://${host}:${sourcePort}`,
      [`BEF_LOCAL_RPC_PROXY_URL_${suffix}`]: `http://127.0.0.1:${relayPort}`,
      [`BEF_FACILITATOR_URL_${suffix}`]: `http://${host}:${facilitatorPort}`,
    };
    const childArguments = [
      '--import', './packages/benchmark-environment/node_modules/tsx/dist/loader.mjs',
      'packages/benchmark-environment/src/probe/task-difficulty-v2-main.ts',
      '--task-id', taskId, '--mode', mode, '--env-id', envId, '--evidence-dir', captureDirectory,
      ...(recipient === undefined ? [] : ['--recipient', recipient]),
    ];
    const child = spawn(process.execPath, childArguments, { cwd: '/workspace', env: runtimeEnvironment, stdio: 'inherit' });
    const exitCode = await new Promise((done, reject) => {
      child.once('error', reject);
      child.once('exit', (code) => done(code ?? 1));
    });
    process.stdout.write(`${JSON.stringify({ captureId, captureDirectory, exitCode,
      boundary: 'docker-local-fork-one-task-one-mode-reference-capture', releaseReadiness: 'blocked' })}\n`);
    process.exitCode = exitCode;
  } finally {
    for (const socket of sockets) socket.destroy();
    if (relay.listening) await new Promise((done) => relay.close(done));
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) void main().catch(() => {
  process.stderr.write('status=error code=difficulty_v2_wrapper_failed\n');
  process.exitCode = 2;
});
