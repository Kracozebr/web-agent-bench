#!/usr/bin/env node
import { createHash, randomUUID } from 'node:crypto';
import { mkdir, readFile, readdir, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { createRequire } from 'node:module';

const EXPECTED = {
  manifestSha256: 'e90d876b500f2bd8d45e891295028d4b87993070a4c08b18b262fa302cde13e4',
  applicationSourceSha256: '7330b2493e5014f20fb455a9613cf420b12408fcc92c2e6c0b11c6de8e100171',
};
const pinArguments = process.argv.slice(2);
if (pinArguments.length !== 0) {
  if (pinArguments.length !== 4 || pinArguments[0] !== '--manifest-sha256' ||
      pinArguments[2] !== '--application-sha256' ||
      !pinArguments.filter((_, index) => index % 2 === 1).every((value) => /^[0-9a-f]{64}$/.test(value))) {
    throw new Error('Explicit manifest and application SHA-256 pins are required together');
  }
  EXPECTED.manifestSha256 = pinArguments[1];
  EXPECTED.applicationSourceSha256 = pinArguments[3];
}
const ENVIRONMENTS = [
  { envId: 'bef-env-a', proxyPort: 18545 },
  { envId: 'bef-env-b', proxyPort: 28545 },
];
const EXPECTED_LOCAL_API_PORT = '38783';
const root = process.cwd();
const secretPaths = {
  adminKey: 'infrastructure/benchmark-environment/.local/secrets/admin-key',
  serviceKey: 'infrastructure/benchmark-environment/.local/secrets/service-key',
  observerPassword: 'infrastructure/benchmark-environment/.local/secrets/database-observer-password',
  ownerDatabaseUrl: 'infrastructure/benchmark-environment/.local/secrets/database-owner-url',
};
const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const artifacts = [];
const sensitiveValues = [];
const blockerSet = new Set();
const comparisons = { environments: {}, contractCode: {}, database: {} };
let captureId;

function safeFailureCode(error) {
  if (error?.name === 'AbortError' || error?.name === 'TimeoutError') return 'request_timeout';
  if (error?.code === 'ECONNREFUSED') return 'connection_refused';
  if (error?.code === 'ENOTFOUND') return 'host_unresolved';
  if (error?.code === 'EACCES' || error?.code === 'EPERM') return 'permission_denied';
  return 'observation_unavailable';
}

function addBlocker(code) {
  if (/^[a-z0-9_]{1,80}$/.test(code)) blockerSet.add(code);
  else blockerSet.add('unexpected_blocker_code');
}

function checkNoSecret(name, bytes) {
  const text = Buffer.isBuffer(bytes) ? bytes.toString('utf8') : String(bytes);
  for (const secret of sensitiveValues) {
    if (secret.length >= 8 && text.includes(secret)) {
      addBlocker('credential_echo_in_observation');
      throw new Error(`credential_echo_in_${name}`);
    }
  }
}

async function saveArtifact(name, bytes, boundary, metadata = {}) {
  const content = Buffer.isBuffer(bytes) ? bytes : Buffer.from(String(bytes));
  checkNoSecret(name, content);
  const relativePath = `artifacts/runs/bts-release-feasibility-witness/${captureId}/${name}`;
  await writeFile(resolve(root, relativePath), content, { flag: 'wx' });
  artifacts.push({ path: relativePath.replaceAll('\\', '/'), boundary, sha256: sha256(content), byteLength: content.length, ...metadata });
  return content;
}

async function captureHttp(name, url, options, boundary, metadata = {}) {
  try {
    const response = await fetch(url, { ...options, signal: AbortSignal.timeout(15_000), redirect: 'error' });
    const raw = Buffer.from(await response.arrayBuffer());
    await saveArtifact(name, raw, boundary, { httpStatus: response.status, contentType: response.headers.get('content-type'), ...metadata });
    return { status: response.status, raw: raw.toString('utf8'), ok: response.ok };
  } catch (error) {
    addBlocker(safeFailureCode(error));
    const observation = JSON.stringify({ observation: 'unavailable', code: safeFailureCode(error) });
    await saveArtifact(name, observation, boundary, { httpStatus: null, ...metadata });
    return { status: null, raw: observation, ok: false };
  }
}

function parseJson(raw) {
  try { return JSON.parse(raw); } catch { return null; }
}

async function captureRpc(env, label, method, params, serviceKey) {
  const name = `${env.envId}-rpc-${label}.raw.json`;
  const req = { jsonrpc: '2.0', id: 1, method, params };
  const captured = await captureHttp(
    name,
    `http://host.docker.internal:${env.proxyPort}/`,
    { method: 'POST', headers: { 'content-type': 'application/json', 'x-bef-service-key': serviceKey }, body: JSON.stringify(req) },
    'loopback_published_local_rpc_proxy',
    { envId: env.envId, rpcMethod: method, rpcParams: params },
  );
  const document = parseJson(captured.raw);
  const result = document && !document.error ? document.result : undefined;
  const ok = captured.ok && Boolean(document) && Object.hasOwn(document, 'result') && !document.error;
  if (!ok) addBlocker(`rpc_${label.replaceAll('-', '_')}_unavailable`);
  return { document, result, ok };
}

async function main() {
  if (root !== '/workspace' || process.env.BEF_API_HOST_PORT !== EXPECTED_LOCAL_API_PORT) {
    throw new Error('unexpected_runtime_boundary');
  }
  captureId = randomUUID();
  const outputRoot = resolve(root, 'artifacts/runs/bts-release-feasibility-witness');
  const outputDir = resolve(root, 'artifacts/runs/bts-release-feasibility-witness', captureId);
  await mkdir(outputRoot, { recursive: true });
  await mkdir(outputDir, { recursive: false });

  const secrets = {};
  for (const [key, relativePath] of Object.entries(secretPaths)) {
    const value = (await readFile(resolve(root, relativePath), 'utf8')).trim();
    if (!value) throw new Error('required_secret_unavailable');
    secrets[key] = value;
    sensitiveValues.push(value);
  }

  const manifestBytes = await readFile(resolve(root, 'infrastructure/benchmark-environment/manifest.json'));
  const manifestSha256 = sha256(manifestBytes);
  const manifest = JSON.parse(manifestBytes.toString('utf8'));
  await saveArtifact('manifest.raw.json', manifestBytes, 'checked_out_manifest');

  const { sourceDigests } = await import('../../packages/benchmark-environment/src/probe/environment.ts');
  const localDigests = await sourceDigests(root);
  const appSourceMatchesExpected = localDigests.appSourceSha256 === EXPECTED.applicationSourceSha256;
  if (manifestSha256 !== EXPECTED.manifestSha256) addBlocker('checked_out_manifest_pin_mismatch');
  if (!appSourceMatchesExpected) addBlocker('checked_out_application_source_pin_mismatch');

  const apiBase = `http://host.docker.internal:${EXPECTED_LOCAL_API_PORT}`;
  const apiHealth = await captureHttp('api-health.raw.json', `${apiBase}/healthz`, { method: 'GET' }, 'loopback_published_bef_api');
  const apiHealthDoc = parseJson(apiHealth.raw);
  const apiHealthMatches = Boolean(apiHealthDoc)
    && apiHealthDoc.status === 'ready'
    && apiHealthDoc.manifestSha256 === EXPECTED.manifestSha256
    && apiHealthDoc.applicationSourceSha256 === EXPECTED.applicationSourceSha256;
  if (!apiHealthMatches) addBlocker('api_health_identity_mismatch');

  for (const env of ENVIRONMENTS) {
    const capability = await captureHttp(
      `${env.envId}-capabilities.raw.json`,
      `${apiBase}/internal/admin/environments/${env.envId}/probe-capabilities`,
      { method: 'GET', headers: { 'x-bef-admin-key': secrets.adminKey } },
      'authenticated_private_admin_capability_read',
      { envId: env.envId },
    );
    const capabilityDoc = parseJson(capability.raw);
    const capabilityMatches = capability.status === 200
      && capabilityDoc?.schemaVersion === 'bef-probe-capabilities/v1'
      && capabilityDoc.envId === env.envId
      && capabilityDoc.ready === true
      && Array.isArray(capabilityDoc.blockers) && capabilityDoc.blockers.length === 0
      && capabilityDoc.manifestSha256 === EXPECTED.manifestSha256
      && capabilityDoc.applicationSourceSha256 === EXPECTED.applicationSourceSha256;
    if (!capabilityMatches) addBlocker(`${env.envId.replaceAll('-', '_')}_capability_identity_mismatch`);

    const proxyHealth = await captureHttp(
      `${env.envId}-proxy-health.raw.json`,
      `http://host.docker.internal:${env.proxyPort}/healthz`,
      { method: 'GET' },
      'loopback_published_local_rpc_proxy',
      { envId: env.envId },
    );
    const proxyHealthDoc = parseJson(proxyHealth.raw);
    const proxyHealthMatches = proxyHealth.status === 200
      && proxyHealthDoc?.status === 'ok'
      && proxyHealthDoc.boundary === 'local-chain-readonly-proxy'
      && proxyHealthDoc.envId === env.envId
      && proxyHealthDoc.manifestSha256 === EXPECTED.manifestSha256;
    if (!proxyHealthMatches) addBlocker(`${env.envId.replaceAll('-', '_')}_proxy_identity_mismatch`);

    const chain = await captureRpc(env, 'chain-id', 'eth_chainId', [], secrets.serviceKey);
    const chainIdMatches = chain.ok && typeof chain.result === 'string' && /^0x[0-9a-f]+$/i.test(chain.result)
      && BigInt(chain.result) === BigInt(manifest.local.chainId);
    if (!chainIdMatches) addBlocker(`${env.envId.replaceAll('-', '_')}_chain_id_mismatch`);

    const block = await captureRpc(env, 'source-block', 'eth_getBlockByNumber', [manifest.source.blockNumber, false], secrets.serviceKey);
    const blockNumberMatches = block.ok && String(block.result?.number).toLowerCase() === manifest.source.blockNumber.toLowerCase();
    const blockHashMatches = block.ok && String(block.result?.hash).toLowerCase() === manifest.source.blockHash.toLowerCase();
    if (!blockNumberMatches || !blockHashMatches) addBlocker(`${env.envId.replaceAll('-', '_')}_source_block_identity_mismatch`);

    comparisons.environments[env.envId] = {
      capability: { httpStatus: capability.status, matchesExpectedPin: capabilityMatches },
      proxyHealth: { httpStatus: proxyHealth.status, matchesExpectedPin: proxyHealthMatches },
      chainId: { observed: chain.result ?? null, expected: `0x${BigInt(manifest.local.chainId).toString(16)}`, matches: chainIdMatches },
      sourceBlock: {
        number: block.result?.number ?? null, hash: block.result?.hash ?? null,
        expectedNumber: manifest.source.blockNumber, expectedHash: manifest.source.blockHash,
        numberMatches: blockNumberMatches, hashMatches: blockHashMatches,
      },
    };

    const contracts = [
      ['usdc-proxy', manifest.contracts.usdc.address, manifest.contracts.usdc.proxyCodeHash],
      ['usdc-implementation', manifest.contracts.usdc.implementation, manifest.contracts.usdc.implementationCodeHash],
      ['weth', manifest.contracts.weth.address, manifest.contracts.weth.codeHash],
      ['factory', manifest.contracts.factory.address, manifest.contracts.factory.codeHash],
      ['swap-router-02', manifest.contracts.swapRouter02.address, manifest.contracts.swapRouter02.codeHash],
      ['quoter-v2', manifest.contracts.quoterV2.address, manifest.contracts.quoterV2.codeHash],
      ['pool-500', manifest.contracts.pool.address, manifest.contracts.pool.codeHash],
      ['pool-3000', manifest.contracts.pool3000.address, manifest.contracts.pool3000.codeHash],
    ];
    for (const [label, address, expectedCodeHash] of contracts) {
      const observed = await captureRpc(env, `code-${label}`, 'eth_getCode', [address, manifest.source.blockNumber], secrets.serviceKey);
      const code = typeof observed.result === 'string' && /^0x(?:[0-9a-f]{2})*$/i.test(observed.result) ? observed.result : null;
      const observedCodeHash = code && code !== '0x' ? keccak256(code) : null;
      const matches = observed.ok && observedCodeHash?.toLowerCase() === expectedCodeHash.toLowerCase();
      if (!matches) addBlocker(`${env.envId.replaceAll('-', '_')}_${label.replaceAll('-', '_')}_code_hash_mismatch`);
      comparisons.contractCode[`${env.envId}:${label}`] = {
        address, observedCodeHash, expectedCodeHash, hasCode: Boolean(code && code !== '0x'), matches,
      };
    }

    const storage = await captureRpc(env, 'usdc-implementation-slot', 'eth_getStorageAt', [
      manifest.contracts.usdc.address, manifest.contracts.usdc.implementationSlot, manifest.source.blockNumber,
    ], secrets.serviceKey);
    const expectedSlotValue = `0x${manifest.contracts.usdc.implementation.slice(2).toLowerCase().padStart(64, '0')}`;
    const storageMatches = storage.ok && String(storage.result).toLowerCase() === expectedSlotValue;
    if (!storageMatches) addBlocker(`${env.envId.replaceAll('-', '_')}_usdc_implementation_slot_mismatch`);
    comparisons.environments[env.envId].usdcImplementationSlot = {
      slot: manifest.contracts.usdc.implementationSlot, observed: storage.result ?? null,
      expected: expectedSlotValue, matches: storageMatches,
    };
  }

  const migrationDir = resolve(root, 'infrastructure/benchmark-environment/migrations');
  const localMigrationNames = (await readdir(migrationDir, { withFileTypes: true }))
    .filter((entry) => entry.isFile() && /^\d{3}_[a-z0-9_]+\.sql$/.test(entry.name))
    .map((entry) => entry.name).sort();
  const localMigrations = [];
  for (const filename of localMigrationNames) {
    const bytes = await readFile(resolve(migrationDir, filename));
    localMigrations.push({ migrationId: filename.slice(0, 3), filename, sha256: sha256(bytes) });
  }

  const require = createRequire(resolve(root, 'packages/benchmark-environment/package.json'));
  const { Pool } = require('pg');
  const ownerUrl = new URL(secrets.ownerDatabaseUrl);
  if (!['postgres:', 'postgresql:'].includes(ownerUrl.protocol) || !ownerUrl.pathname || ownerUrl.pathname === '/') {
    addBlocker('observer_database_configuration_unavailable');
  }
  const observerUrl = new URL(ownerUrl.toString());
  observerUrl.hostname = 'host.docker.internal';
  observerUrl.port = '55432';
  observerUrl.username = 'bef_observer';
  observerUrl.password = secrets.observerPassword;
  const pool = new Pool({
    connectionString: observerUrl.toString(), max: 1, connectionTimeoutMillis: 5_000,
    idleTimeoutMillis: 5_000, statement_timeout: 8_000, query_timeout: 10_000,
    application_name: 'bef-release-feasibility-readonly',
  });
  let dbRaw;
  let readOnlyRoleProof = { verified: false, code: 'observer_database_unavailable' };
  try {
    const client = await pool.connect();
    try {
      await client.query('BEGIN READ ONLY');
      const session = await client.query(`SELECT current_user AS current_user, session_user AS session_user,
        current_database() AS database_name, current_setting('transaction_read_only') AS transaction_read_only`);
      const role = await client.query(`SELECT rolname, rolsuper, rolinherit, rolcreaterole, rolcreatedb, rolreplication, rolbypassrls,
        has_database_privilege(current_user, current_database(), 'CONNECT') AS db_connect,
        has_database_privilege(current_user, current_database(), 'CREATE') AS db_create,
        has_database_privilege(current_user, current_database(), 'TEMP') AS db_temp
        FROM pg_roles WHERE rolname = current_user`);
      const memberships = await client.query(`SELECT parent.rolname AS inherited_role, m.admin_option
        FROM pg_auth_members AS m JOIN pg_roles AS parent ON parent.oid = m.roleid
        JOIN pg_roles AS member ON member.oid = m.member WHERE member.rolname = current_user ORDER BY parent.rolname`);
      const tableNames = ['bef_schema_migration', 'bef_environment', 'bef_generation'];
      const privilegeRows = [];
      for (const tableName of tableNames) {
        const result = await client.query(`SELECT $1::text AS table_name,
          has_table_privilege(current_user, 'public.' || $1, 'SELECT') AS can_select,
          has_table_privilege(current_user, 'public.' || $1, 'INSERT') AS can_insert,
          has_table_privilege(current_user, 'public.' || $1, 'UPDATE') AS can_update,
          has_table_privilege(current_user, 'public.' || $1, 'DELETE') AS can_delete,
          has_table_privilege(current_user, 'public.' || $1, 'TRUNCATE') AS can_truncate,
          has_table_privilege(current_user, 'public.' || $1, 'REFERENCES') AS can_reference,
          has_table_privilege(current_user, 'public.' || $1, 'TRIGGER') AS can_trigger`, [tableName]);
        privilegeRows.push(result.rows[0]);
      }
      const migrations = await client.query(`SELECT migration_id, filename, trim(sha256) AS sha256, applied_at
        FROM public.bef_schema_migration ORDER BY migration_id`);
      const environments = await client.query(`SELECT env_id, chain_id::text AS chain_id, trim(manifest_sha256) AS manifest_sha256
        FROM public.bef_environment WHERE env_id = ANY($1::text[]) ORDER BY env_id`, [ENVIRONMENTS.map((env) => env.envId)]);
      const generations = await client.query(`SELECT env_id, generation_id, status, created_at, expires_at, fenced_at,
          trim(manifest_sha256) AS manifest_sha256
        FROM public.bef_generation WHERE env_id = ANY($1::text[]) ORDER BY env_id, created_at, generation_id`,
      [ENVIRONMENTS.map((env) => env.envId)]);
      await client.query('COMMIT');
      dbRaw = {
        session: session.rows,
        role: role.rows,
        memberships: memberships.rows,
        tablePrivileges: privilegeRows,
        migrations: migrations.rows,
        environments: environments.rows,
        generations: generations.rows,
      };
      const roleRow = role.rows[0];
      const privilegesOkay = privilegeRows.length === tableNames.length && privilegeRows.every((row) =>
        row.can_select === true && row.can_insert === false && row.can_update === false && row.can_delete === false
        && row.can_truncate === false && row.can_reference === false && row.can_trigger === false);
      const roleOkay = session.rows[0]?.current_user === 'bef_observer'
        && session.rows[0]?.session_user === 'bef_observer'
        && session.rows[0]?.transaction_read_only === 'on'
        && roleRow?.rolsuper === false && roleRow?.rolcreaterole === false && roleRow?.rolcreatedb === false
        && roleRow?.rolreplication === false && roleRow?.rolbypassrls === false && roleRow?.db_create === false
        && memberships.rows.length === 0 && privilegesOkay;
      readOnlyRoleProof = {
        verified: roleOkay,
        currentRole: session.rows[0]?.current_user ?? null,
        transactionReadOnly: session.rows[0]?.transaction_read_only ?? null,
        noElevatedRoleFlags: Boolean(roleRow) && roleRow.rolsuper === false && roleRow.rolcreaterole === false
          && roleRow.rolcreatedb === false && roleRow.rolreplication === false && roleRow.rolbypassrls === false,
        noRoleMemberships: memberships.rows.length === 0,
        relevantTablePrivilegesAreSelectOnly: privilegesOkay,
        databaseCreatePrivilege: roleRow?.db_create ?? null,
      };
      if (!roleOkay) addBlocker('observer_read_only_role_proof_incomplete');
    } finally {
      client.release();
    }
  } catch (error) {
    addBlocker(safeFailureCode(error));
    dbRaw = { observation: 'unavailable', code: safeFailureCode(error) };
  } finally {
    await pool.end().catch(() => {});
  }

  const dbText = JSON.stringify(dbRaw, null, 2);
  await saveArtifact('observer-database.raw.json', dbText, 'bef_observer_read_only_transaction', {
    querySet: 'schema_migrations_environment_generation_status',
  });
  const actualMigrations = dbRaw?.migrations;
  const migrationsMatch = Array.isArray(actualMigrations) && actualMigrations.length === localMigrations.length
    && actualMigrations.every((row, index) => row.migration_id === localMigrations[index].migrationId
      && row.filename === localMigrations[index].filename && row.sha256 === localMigrations[index].sha256);
  const environmentsMatch = Array.isArray(dbRaw?.environments) && dbRaw.environments.length === ENVIRONMENTS.length
    && dbRaw.environments.every((row) => row.chain_id === String(manifest.local.chainId)
      && row.manifest_sha256 === EXPECTED.manifestSha256);
  const noActiveGenerations = Array.isArray(dbRaw?.generations) && dbRaw.generations.every((row) => row.status !== 'active');
  if (!migrationsMatch) addBlocker('database_migration_ledger_mismatch');
  if (!environmentsMatch) addBlocker('database_environment_identity_mismatch');
  if (!noActiveGenerations) addBlocker('active_or_unobserved_generation');
  comparisons.database = {
    readOnlyRoleProof,
    migrationLedgerMatchesCheckedOutFiles: migrationsMatch,
    checkedOutMigrationCount: localMigrations.length,
    appliedMigrationCount: Array.isArray(actualMigrations) ? actualMigrations.length : null,
    environmentPinsMatch: environmentsMatch,
    generationRowsObserved: Array.isArray(dbRaw?.generations) ? dbRaw.generations.length : null,
    noActiveGenerationObserved: noActiveGenerations,
  };

  const witness = {
    schemaVersion: 'bts-release-feasibility-witness/v1',
    classification: 'read_only_local_bef_feasibility_observations_not_release_acceptance',
    captureId,
    capturedAt: new Date().toISOString(),
    status: blockerSet.size === 0 ? 'captured' : 'blocked',
    releaseReadiness: 'blocked',
    scope: { environments: ENVIRONMENTS.map((entry) => entry.envId), chainMethods: ['eth_chainId', 'eth_getBlockByNumber', 'eth_getCode', 'eth_getStorageAt'] },
    selectedPins: {
      expectedManifestSha256: EXPECTED.manifestSha256,
      observedManifestSha256: manifestSha256,
      expectedApplicationSourceSha256: EXPECTED.applicationSourceSha256,
      observedCheckedOutApplicationSourceSha256: localDigests.appSourceSha256,
      observedCheckedOutProbeSourceSha256: localDigests.probeSourceSha256,
      apiHealth: { status: apiHealthDoc?.status ?? null, manifestSha256: apiHealthDoc?.manifestSha256 ?? null,
        applicationSourceSha256: apiHealthDoc?.applicationSourceSha256 ?? null, matchesExpected: apiHealthMatches },
    },
    comparisons,
    blockers: [...blockerSet].sort(),
    noGenerationCreatedByWitness: true,
    noStateChangingMethodsUsed: true,
    noReleaseActivationOrGradePosted: true,
    artifacts,
  };
  const witnessBytes = Buffer.from(`${JSON.stringify(witness, null, 2)}\n`);
  checkNoSecret('witness', witnessBytes);
  await writeFile(resolve(outputDir, 'witness.json'), witnessBytes, { flag: 'wx' });
  const witnessSha256 = sha256(witnessBytes);
  process.stdout.write(JSON.stringify({
    status: witness.status, classification: witness.classification, captureId,
    artifactDirectory: `artifacts/runs/bts-release-feasibility-witness/${captureId}`,
    rawArtifactCount: artifacts.length + 1, witnessSha256, blockers: witness.blockers,
    generationRowsObserved: comparisons.database.generationRowsObserved,
    releaseReadiness: 'blocked',
  }) + '\n');
  if (witness.status !== 'captured') process.exitCode = 2;
}

let keccak256;
try {
  const require = createRequire(resolve(root, 'packages/benchmark-environment/package.json'));
  ({ keccak256 } = require('viem'));
} catch {
  process.stderr.write('status=blocked code=keccak_runtime_unavailable\n');
  process.exitCode = 2;
}

if (keccak256) main().catch((error) => {
  const code = error?.message === 'unexpected_runtime_boundary' ? 'unexpected_runtime_boundary' : safeFailureCode(error);
  process.stderr.write(`status=blocked code=${code}\n`);
  process.exitCode = 2;
});
