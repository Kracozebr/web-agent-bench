import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import { readFile, lstat, realpath } from 'node:fs/promises';
import { dirname, basename, resolve } from 'node:path';

const [artifactPath, expectedHash] = process.argv.slice(2);
assert.ok(artifactPath && /^[a-f0-9]{64}$/.test(expectedHash ?? ''), 'Provide artifact path and exact SHA-256');
assert.equal(basename(artifactPath), 'local-operations-observation.json');
assert.match(basename(dirname(artifactPath)), /^oid_acceptance_[a-f0-9]{32}$/);
assert.equal(await realpath(artifactPath), resolve(artifactPath));
const info = await lstat(artifactPath);
assert.ok(info.isFile() && !info.isSymbolicLink() && info.size <= 1024*1024);
const bytes = await readFile(artifactPath);
assert.equal(createHash('sha256').update(bytes).digest('hex'), expectedHash);
const evidence = JSON.parse(bytes);
assert.equal(evidence.schemaVersion, 'bpc-local-operations-observation/v1');
assert.equal(evidence.scenarioId, 'BPC-SC-021');
assert.equal(evidence.localStatus, 'observed_partial');
assert.equal(evidence.boundary, 'isolated_browser_api_postgresql');
const { before, after, responses } = evidence;
assert.deepEqual(after.identity, before.identity);
assert.equal(after.identity.database, basename(dirname(artifactPath)));
assert.equal(after.identity.role, 'oid_observer');
assert.equal(after.identity.read_only, 'on');
assert.equal(before.control.mode, 'active');
assert.equal(after.control.mode, 'active');
assert.equal(Number(after.control.revision), Number(before.control.revision)+2);
assert.deepEqual(after.events.slice(0,before.events.length), before.events);
const changes = after.events.slice(before.events.length);
assert.equal(changes.length,2);
assert.deepEqual(changes.map(row => [row.previous_mode,row.next_mode]), [['active','paused'],['paused','active']]);
for (const [index, row] of changes.entries()) {
  assert.equal(Number(row.revision), Number(before.control.revision)+index+1);
  assert.ok(responses.some(response => response.method === 'POST' && response.path === '/api/admin/operations/control'
    && response.status === 201 && response.operationId === row.operation_id && response.revision === Number(row.revision)));
}
assert.equal(after.control.operation_id, changes[1].operation_id);
assert.deepEqual(after.invariants,before.invariants);
for (const [method,path,status] of [['GET','/api/owner/reports/:id',200],['GET','/api/admin/operations',403],
  ['POST','/api/admin/operations/control',403],['GET','/api/admin/operations/usage-support-export',403],
  ['GET','/api/admin/operations/usage-support-export',503]]) {
  assert.ok(responses.some(row => row.method === method && row.path === path && row.status === status));
}

const url = new URL(process.env.OID_OBSERVER_DATABASE_URL);
assert.equal(url.hostname,'postgres'); assert.equal(url.username,'oid_observer');
url.pathname = '/'+after.identity.database;
const require = createRequire(new URL('../packages/owner-acceptance/package.json',import.meta.url));
const { Pool } = require('pg');
const pool = new Pool({connectionString:url.href,max:1,application_name:'bpc-operations-independent-replay'});
try {
  const connection = await pool.connect();
  try {
    await connection.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
    const identity = (await connection.query(`SELECT current_database() AS database,current_user AS role,
      current_setting('transaction_read_only') AS read_only`)).rows[0];
    assert.deepEqual(identity,after.identity);
    const control = (await connection.query(`SELECT mode,revision::text,operation_id FROM oid_beta_operations_control WHERE id=1`)).rows[0];
    const events = (await connection.query(`SELECT operation_id,revision::text,previous_mode,next_mode,reason_code
      FROM oid_beta_operations_control_event ORDER BY revision`)).rows;
    const invariants = (await connection.query(`SELECT
      (SELECT count(*)::int FROM oid_ledger_entry) AS ledger,
      (SELECT count(*)::int FROM oid_benchmark_run) AS runs,
      (SELECT count(*)::int FROM oid_run_task_action) AS actions,
      (SELECT count(*)::int FROM oid_support_report) AS reports`)).rows[0];
    assert.deepEqual(control,after.control); assert.deepEqual(events,after.events);
    assert.deepEqual(invariants,after.invariants);
    await connection.query('COMMIT');
  } catch (error) { await connection.query('ROLLBACK').catch(()=>{}); throw error; }
  finally { connection.release(); }
} finally { await pool.end(); }
console.log(JSON.stringify({status:'verified_local_partial',scenarioId:'BPC-SC-021',sha256:expectedHash,
  database:after.identity.database,revision:after.control.revision,newAuditEvents:changes.length,
  targetGateAccepted:false}));
