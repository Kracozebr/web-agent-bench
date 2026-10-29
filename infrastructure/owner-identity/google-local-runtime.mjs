import { randomBytes, randomUUID } from 'node:crypto';
import { createRequire } from 'node:module';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import { resolve } from 'node:path';
import { prepareGoogleLocalCoordinator } from './google-local-coordinator.mjs';
const root = '/workspace';
const stateRoot = resolve(root, '.local/owner-identity/google-local');
const require = createRequire(resolve(root, 'packages/owner-acceptance/package.json'));
const { Client } = require('pg');
let phase = 'validate_private_configuration';
const children = [];
let stopping = false;
const executorEnabled = process.env.OID_GOOGLE_LOCAL_EXECUTOR_ENABLED === 'true';
if (!['true', 'false', undefined].includes(process.env.OID_GOOGLE_LOCAL_EXECUTOR_ENABLED)) throw new Error('executor_opt_in_invalid');
function child(command, args, env) {
  const value = spawn(command, args, { cwd: root, env, stdio: 'ignore' });
  children.push(value);
  return value;
}
async function command(commandName, args, env) {
  const value = child(commandName, args, env);
  const code = await new Promise((done, reject) => { value.once('error', reject); value.once('exit', done); });
  if (code !== 0) throw new Error('subprocess_failed');
}
async function waitHttp(url, valid) {
  const deadline = Date.now() + 60000;
  while (Date.now() < deadline) {
    try { const response = await fetch(url, { redirect: 'manual', signal: AbortSignal.timeout(2000) }); if (await valid(response)) return; }
    catch { }
    await new Promise(done => setTimeout(done, 300));
  }
  throw new Error('http_not_ready');
}
function stop() {
  if (stopping) return;
  stopping = true;
  for (const value of children) if (value.exitCode === null) value.kill('SIGTERM');
}
process.on('SIGTERM', () => { stop(); setTimeout(() => process.exit(0), 1000); });
process.on('SIGINT', () => { stop(); setTimeout(() => process.exit(0), 1000); });
async function main() {
  await mkdir(stateRoot, { recursive: true, mode: 0o700 });
  await writeFile(resolve(stateRoot, 'ready.json'), JSON.stringify({status:'starting',startedAt:new Date().toISOString()})+'\n',{mode:0o600});
  const credentials = JSON.parse((await readFile(resolve(root, '.local/owner-identity/secrets/google-oauth-local.json'), 'utf8')).replace(/^\uFEFF/, '')).web;
  if (!credentials || typeof credentials.client_id !== 'string' || !credentials.client_id.endsWith('.apps.googleusercontent.com') ||
      typeof credentials.client_secret !== 'string' || credentials.client_secret.length < 16 ||
      (credentials.redirect_uris && !credentials.redirect_uris.includes('http://127.0.0.1:3000/api/auth/callback/google'))) throw new Error('client_configuration_invalid');
  const statePath = resolve(stateRoot, 'runtime.json');
  let state;
  try { state = JSON.parse(await readFile(statePath, 'utf8')); }
  catch (error) {
    if (error.code !== 'ENOENT') throw error;
    state = { schemaVersion: 'real-google-local-runtime/v1', databaseName: 'oid_google_local_' + randomUUID().replaceAll('-', ''),
      authSecret: randomBytes(48).toString('base64url'), bonusVerifierSecret: randomBytes(48).toString('base64url'), initialized: false };
    await writeFile(statePath, JSON.stringify(state) + '\n', { flag: 'wx', mode: 0o600 });
  }
  if (state.schemaVersion !== 'real-google-local-runtime/v1' || !/^oid_google_local_[a-f0-9]{32}$/.test(state.databaseName) ||
      typeof state.authSecret !== 'string' || state.authSecret.length < 32 || typeof state.bonusVerifierSecret !== 'string' || state.bonusVerifierSecret.length < 32) throw new Error('runtime_identity_invalid');
  const sourceUrl = new URL(process.env.OID_DATABASE_URL);
  if (sourceUrl.hostname !== 'postgres' || sourceUrl.username !== 'oid_owner') throw new Error('database_host_invalid');
  const databaseUrl = new URL(sourceUrl); databaseUrl.pathname = '/' + state.databaseName;
  phase = 'prepare_dedicated_database';
  const admin = new Client({ connectionString: sourceUrl.href }); await admin.connect();
  try {
    const exists = (await admin.query('SELECT 1 FROM pg_database WHERE datname=$1', [state.databaseName])).rowCount === 1;
    if (!exists) {
      if (state.initialized) throw new Error('initialized_database_missing');
      await admin.query(`CREATE DATABASE "${state.databaseName}" TEMPLATE template0`);
      state.createdByLauncher = true;
      await writeFile(statePath, JSON.stringify(state) + '\n', { mode: 0o600 });
    } else if (!state.initialized && !state.createdByLauncher) throw new Error('unmarked_database_exists');
  } finally { await admin.end(); }
  const setup = new Client({ connectionString: databaseUrl.href }); await setup.connect();
  try {
    await setup.query(`GRANT CONNECT ON DATABASE "${state.databaseName}" TO oid_observer`);
    await setup.query('GRANT USAGE ON SCHEMA public TO oid_observer');
    await setup.query('ALTER DEFAULT PRIVILEGES FOR ROLE oid_owner IN SCHEMA public GRANT SELECT ON TABLES TO oid_observer');
    await setup.query('ALTER DEFAULT PRIVILEGES FOR ROLE oid_owner IN SCHEMA public GRANT SELECT ON SEQUENCES TO oid_observer');
  } finally { await setup.end(); }
  const captureRoot = resolve('/local-google-data', state.databaseName);
  await mkdir(resolve(captureRoot, 'private-data'), { recursive: true, mode: 0o700 });
  const closureStatePath = resolve(captureRoot, 'report-closure-state.json');
  try { await readFile(closureStatePath); }
  catch(error) {
    if(error.code !== 'ENOENT') throw error;
    await writeFile(closureStatePath, JSON.stringify({schemaVersion:'beta-report-closure-state/v1',betaEndedAt:null,
      sourceEvidenceSha256:'0'.repeat(64)})+'\n',{flag:'wx',mode:0o600});
  }
  const apiEnv = { ...process.env, NODE_ENV: 'development', OID_DATABASE_URL: databaseUrl.href,
    OID_PUBLIC_ORIGIN: 'http://127.0.0.1:3000', OID_API_HOST: '127.0.0.1', OID_API_PORT: '8784',
    OID_AUTH_SECRET: state.authSecret, OID_BONUS_CODE_VERIFIER_SECRET: state.bonusVerifierSecret,
    OID_GOOGLE_CLIENT_ID: credentials.client_id, OID_GOOGLE_CLIENT_SECRET: credentials.client_secret,
    OID_REGISTRATION_MODE: 'open', OID_LOCAL_BEF_TASK_COORDINATOR_ENABLED: String(executorEnabled),
    OID_LOCAL_GOOGLE_QUALIFICATION_ENABLED: 'true', OID_LOCAL_REPORT_ACCEPTANCE_ENABLED: 'true',
    OID_LOCAL_REPORT_CAPTURE_ROOT: captureRoot, OID_BETA_REPORT_CLOSURE_STATE_FILE: closureStatePath,
    OID_PRIVATE_DATA_DIR: resolve(captureRoot, 'private-data'),
    OID_MCP_TRANSPORT_PROFILE: executorEnabled ? 'codex-local-manual-2025-06-18' : 'strict-2026-07-28' };
  for (const key of ['OID_GOOGLE_FIXTURE_ORIGIN', 'OID_ADMIN_PROVIDER', 'OID_ADMIN_SUBJECT', 'OID_BETA_MANIFEST_FILE',
    'OID_BETA_BEF_TASK_COORDINATOR_CONFIG', 'NODE_OPTIONS', 'OID_LOCAL_REPORT_CAPTURE_BASE']) delete apiEnv[key];
  if (process.env.OID_GOOGLE_LOCAL_DIAGNOSTICS === 'true') apiEnv.NODE_OPTIONS = '--import=/workspace/.local/owner-identity/google-token-diagnostic.mjs';
  if (state.adminSubject) { apiEnv.OID_ADMIN_PROVIDER = 'google'; apiEnv.OID_ADMIN_SUBJECT = state.adminSubject; }
  phase = 'api_build'; await command('pnpm', ['--filter', '@web-agent-bench/owner-identity', 'build'], apiEnv);
  phase = 'schema_migration'; await command('pnpm', ['--filter', '@web-agent-bench/owner-identity', 'migrate'], apiEnv);
  state.initialized = true; await writeFile(statePath, JSON.stringify(state) + '\n', { mode: 0o600 });
  if (executorEnabled) {
    phase = 'prepare_synthetic_executor';
    apiEnv.OID_LOCAL_BEF_TASK_COORDINATOR_CONFIG = await prepareGoogleLocalCoordinator(root, apiEnv);
    phase = 'activate_verified_local_release';
    const { validateAndActivatePinnedRelease } = await import('../../packages/owner-acceptance/src/genuine-s1-cases.mjs');
    const observerUrl = new URL(process.env.OID_OBSERVER_DATABASE_URL); observerUrl.pathname = '/' + state.databaseName;
    await validateAndActivatePinnedRelease({repositoryRoot:root,databaseUrl:databaseUrl.href,observerDatabaseUrl:observerUrl.href});
  }
  const webEnv = { ...process.env, NODE_ENV: 'production', OID_API_URL: 'http://127.0.0.1:8784', NEXT_TELEMETRY_DISABLED: '1' };
  for (const key of ['OID_AUTH_SECRET', 'OID_DATABASE_URL', 'OID_OBSERVER_DATABASE_URL', 'OID_GOOGLE_CLIENT_SECRET', 'OID_GOOGLE_CLIENT_ID', 'NODE_OPTIONS']) delete webEnv[key];
  phase = 'web_build'; await command('pnpm', ['--filter', '@web-agent-bench/owner-web', 'build'], webEnv);
  phase = 'api_start'; const api = child(process.execPath, [resolve(root, 'packages/owner-identity/dist/server.js')], apiEnv);
  await waitHttp('http://127.0.0.1:8784/healthz', async r => r.ok);
  phase = 'web_start'; const web = child('pnpm', ['--filter', '@web-agent-bench/owner-web', 'exec', 'next', 'start', '-p', '3000', '-H', '0.0.0.0'], webEnv);
  await waitHttp('http://127.0.0.1:3000/api/identity/config', async r => r.ok && (await r.json()).googleMode === 'google');
  await writeFile(resolve(stateRoot, 'ready.json'), JSON.stringify({ schemaVersion: 'real-google-local-ready/v1',
    status:'ready', databaseName: state.databaseName, publicOrigin: 'http://127.0.0.1:3000', googleMode: 'google',
    adminConfigured: Boolean(state.adminSubject), executorEnabled, readyAt: new Date().toISOString() }) + '\n', { mode: 0o600 });
  console.log(JSON.stringify({ event: 'google_local_ready', publicOrigin: 'http://127.0.0.1:3000', googleMode: 'google', adminConfigured: Boolean(state.adminSubject) }));
  for (const value of [api, web]) value.once('exit', () => { if (!stopping) { stop(); process.exitCode = 1; } });
}
main().catch(error => { console.error(JSON.stringify({ event: 'google_local_start_failed', phase, errorName: error.name, detailsOmitted: true })); stop(); process.exitCode = 1; });
