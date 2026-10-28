// Docker-only package regression against a new, retained test database.
import { randomUUID } from 'node:crypto';
import { createRequire } from 'node:module';
import { createServer, connect } from 'node:net';
import { spawn } from 'node:child_process';
import { readdir, mkdir, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';

if (process.platform !== 'linux' || process.cwd() !== '/workspace') throw new Error('Use the owner-identity Docker tool runtime');
const require = createRequire(new URL('../../packages/benchmark-environment/package.json', import.meta.url));
const { Pool } = require('pg');
const source = new URL(process.env.OID_DATABASE_URL ?? '');
if (source.hostname !== 'postgres' || source.username !== 'oid_owner' || source.pathname !== '/owner_identity') {
  throw new Error('An isolated local owner PostgreSQL service is required');
}
const captureId = randomUUID();
const databaseName = `bef_migration_test_${captureId.replaceAll('-', '')}`;
const directory = resolve('artifacts/runs/bef-package-postgres', captureId);
await mkdir(directory, { recursive: true });
const admin = new Pool({ connectionString: source.toString(), max: 1 });
const sockets = new Set();
const relay = createServer((incoming) => {
  const outgoing = connect({ host: 'postgres', port: 5432 });
  sockets.add(incoming); sockets.add(outgoing);
  incoming.on('error', () => outgoing.destroy());
  outgoing.on('error', () => incoming.destroy());
  incoming.on('close', () => { sockets.delete(incoming); outgoing.destroy(); });
  outgoing.on('close', () => { sockets.delete(outgoing); incoming.destroy(); });
  incoming.pipe(outgoing); outgoing.pipe(incoming);
});
try {
  // AICODE-NOTE: Never run migration fault tests against either runtime database.
  // The generated identifier is fixed here; the database is retained for inspection.
  await admin.query(`CREATE DATABASE ${databaseName}`);
  await new Promise((done, reject) => { relay.once('error', reject); relay.listen(0, '127.0.0.1', done); });
  const target = new URL(source);
  target.hostname = '127.0.0.1';
  target.port = String(relay.address().port);
  target.pathname = `/${databaseName}`;
  const tests = [];
  for (const part of ['src', 'src/probe']) {
    const base = `packages/benchmark-environment/${part}`;
    for (const name of (await readdir(base)).sort()) if (name.endsWith('.test.ts')) tests.push(`${base}/${name}`);
  }
  const args = ['--import', './packages/benchmark-environment/node_modules/tsx/dist/loader.mjs', '--test', '--test-concurrency=1', ...tests];
  const output = [];
  const child = spawn(process.execPath, args, {
    cwd: '/workspace', env: { ...process.env, BEF_MIGRATION_TEST_DATABASE_URL: target.toString() },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  for (const stream of [child.stdout, child.stderr]) stream.on('data', (chunk) => output.push(chunk));
  const code = await new Promise((done, reject) => { child.once('error', reject); child.once('exit', (value) => done(value ?? 1)); });
  const bytes = Buffer.concat(output);
  // Tests must not emit connection strings/passwords even on failure.
  if (bytes.includes(Buffer.from(source.password)) || bytes.includes(Buffer.from(source.toString()))) {
    throw new Error('Test output failed credential redaction check');
  }
  await writeFile(resolve(directory, 'tests.log'), bytes, { flag: 'wx' });
  const summary = { schemaVersion: 'bef-package-postgres-regression/v1', captureId, databaseName,
    boundary: 'Docker package checks and dedicated retained local PostgreSQL database; no fork actions',
    runtimeDatabasesTouched: false, exitCode: code, testFiles: tests, output: 'tests.log' };
  await writeFile(resolve(directory, 'capture.json'), JSON.stringify(summary, null, 2) + '\n', { flag: 'wx' });
  process.stdout.write(bytes);
  process.stdout.write(JSON.stringify({ captureId, databaseName, exitCode: code, directory }) + '\n');
  process.exitCode = code;
} catch (error) {
  process.stderr.write(JSON.stringify({ error: 'bef_package_postgres_check_failed', code: error?.code ?? null }) + '\n');
  process.exitCode = 1;
} finally {
  for (const socket of sockets) socket.destroy();
  if (relay.listening) await new Promise((done) => relay.close(done));
  await admin.end();
}
