/** Read-only verification of retained local BEF feasibility, not release approval. */
import { createHash } from 'node:crypto';
import { open, realpath } from 'node:fs/promises';
import { constants } from 'node:fs';
import { basename, dirname, isAbsolute, relative, resolve, sep } from 'node:path';
import { keccak256, type Hex } from 'viem';
import { sha256CanonicalTaskJson, type EvidenceReference, type FeasibilityVerification,
  type TaskReleaseManifest } from './task-release.js';

type Document = Record<string, any>;
type Identity = TaskReleaseManifest['executionIdentity'];
const digest = (bytes: Uint8Array) => createHash('sha256').update(bytes).digest('hex');
const equal = (a: unknown, b: unknown) => sha256CanonicalTaskJson(a) === sha256CanonicalTaskJson(b);
const cleanHash = (value: string) => value.replace(/^0x/, '').toLowerCase();
function requireFact(condition: unknown, code: string): asserts condition {
  if (!condition) throw new Error(code);
}
function object(value: unknown): Document {
  requireFact(value && typeof value === 'object' && !Array.isArray(value), 'feasibility_object_invalid');
  return value as Document;
}

async function containedBytes(root: string, path: string): Promise<Buffer> {
  requireFact(typeof path === 'string' && path.length <= 512 && path.trim() === path &&
    !path.includes('\\') && !isAbsolute(path) && !path.includes(':') &&
    path.split('/').every((part) => part && part !== '.' && part !== '..'), 'feasibility_path_invalid');
  const actual = await realpath(resolve(root, path));
  const rel = relative(root, actual);
  requireFact(rel && !isAbsolute(rel) && rel !== '..' && !rel.startsWith(`..${sep}`), 'feasibility_path_escape');
  const handle = await open(actual, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const info = await handle.stat();
    requireFact(info.isFile() && info.size <= 8 * 1024 * 1024, 'feasibility_file_invalid');
    const buffer = Buffer.alloc(info.size + 1);
    let offset = 0;
    while (offset < buffer.length) {
      const { bytesRead } = await handle.read(buffer, offset, buffer.length - offset, offset);
      if (bytesRead === 0) break;
      offset += bytesRead;
    }
    const after = await handle.stat();
    requireFact(offset === info.size && after.size === info.size && after.mtimeMs === info.mtimeMs &&
      after.ctimeMs === info.ctimeMs, 'feasibility_file_changed');
    return buffer.subarray(0, offset);
  } finally { await handle.close(); }
}

/**
 * AICODE-NOTE: Hashes bind this historical observation. No live readiness, current
 * generation availability, reference solvability or difficulty approval follows.
 * Summary booleans are never substitutes for the indexed RPC/SQL response bytes.
 */
export async function verifyRetainedTaskFeasibility(input: {
  repositoryRoot: string; evidence: EvidenceReference; executionIdentity: Identity; expectedIdentityHash: string;
  profilePolicy: { path: string; sha256: string };
  participantToolProtocol?: TaskReleaseManifest['participantToolProtocol'];
}): Promise<FeasibilityVerification> {
  try {
    const root = await realpath(input.repositoryRoot);
    const { evidence, executionIdentity: identity } = input;
    requireFact(evidence.boundary === 'actual_tool_http_x402_local_evm_application_store' &&
      evidence.sha256.length === 64 && /^[0-9a-f]+$/i.test(evidence.sha256), 'feasibility_reference_invalid');
    requireFact(sha256CanonicalTaskJson(identity) === input.expectedIdentityHash, 'feasibility_identity_hash_mismatch');
    const policyBytes = await containedBytes(root, input.profilePolicy.path);
    requireFact(digest(policyBytes) === input.profilePolicy.sha256, 'feasibility_profile_policy_hash_mismatch');
    const policy = object(JSON.parse(policyBytes.toString('utf8')));
    requireFact(policy.schemaVersion === 'bts-local-case-assembly-policy/v1' &&
      policy.boundary === 'isolated_local_bef_anvil_fork' && policy.profileId === identity.profileId,
      'feasibility_profile_policy_mismatch');
    const bytes = await containedBytes(root, evidence.path);
    requireFact(digest(bytes) === evidence.sha256.toLowerCase(), 'feasibility_witness_hash_mismatch');
    const witness = object(JSON.parse(bytes.toString('utf8')));
    requireFact(witness.schemaVersion === 'bts-release-feasibility-witness/v1' && witness.status === 'captured' &&
      Array.isArray(witness.blockers) && witness.blockers.length === 0, 'feasibility_witness_incomplete');
    requireFact(witness.classification === 'read_only_local_bef_feasibility_observations_not_release_acceptance' &&
      witness.releaseReadiness === 'blocked' && witness.noGenerationCreatedByWitness === true &&
      witness.noStateChangingMethodsUsed === true && witness.noReleaseActivationOrGradePosted === true &&
      evidence.path === `artifacts/runs/bts-release-feasibility-witness/${witness.captureId}/witness.json` &&
      /^[0-9a-f-]{36}$/.test(witness.captureId) &&
      equal(witness.scope, { environments: ['bef-env-a', 'bef-env-b'],
        chainMethods: ['eth_chainId', 'eth_getBlockByNumber', 'eth_getCode', 'eth_getStorageAt'] }),
      'feasibility_witness_scope_mismatch');
    requireFact(Array.isArray(witness.artifacts) && witness.artifacts.length === 29, 'feasibility_artifact_inventory_invalid');
    const documents = new Map<string, Document>();
    const artifactRows = new Map<string, Document>();
    const prefix = `${dirname(evidence.path).replaceAll('\\', '/')}/`;
    for (const value of witness.artifacts) {
      const row = object(value);
      requireFact(typeof row.path === 'string' && row.path === `${prefix}${basename(row.path)}` &&
        !documents.has(basename(row.path)), 'feasibility_artifact_path_conflict');
      const raw = await containedBytes(root, row.path);
      requireFact(digest(raw) === row.sha256 && raw.length === row.byteLength, 'feasibility_raw_hash_mismatch');
      documents.set(basename(row.path), object(JSON.parse(raw.toString('utf8'))));
      artifactRows.set(basename(row.path), row);
    }
    const consumed = new Set<string>();
    const doc = (name: string) => {
      const value = documents.get(name);
      requireFact(value, `feasibility_artifact_missing:${name}`);
      consumed.add(name);
      const row = artifactRows.get(name)!;
      const expectedBoundary = name === 'manifest.raw.json' ? 'checked_out_manifest' :
        name === 'observer-database.raw.json' ? 'bef_observer_read_only_transaction' :
        name === 'api-health.raw.json' ? 'loopback_published_bef_api' :
        name.endsWith('-capabilities.raw.json') ? 'authenticated_private_admin_capability_read' :
        'loopback_published_local_rpc_proxy';
      requireFact(row.boundary === expectedBoundary, 'feasibility_artifact_boundary_mismatch');
      if (name !== 'manifest.raw.json' && name !== 'observer-database.raw.json') {
        requireFact(row.httpStatus === 200 && row.contentType?.split(';')[0] === 'application/json',
          'feasibility_artifact_transport_mismatch');
      }
      return value;
    };
    const manifestRow = artifactRows.get('manifest.raw.json');
    requireFact(manifestRow?.sha256 === identity.environmentManifestSha256, 'feasibility_manifest_mismatch');
    const manifest = doc('manifest.raw.json');
    requireFact((manifest.tools?.participantProtocol ?? 'combined_purchase_v1') ===
      (input.participantToolProtocol ?? 'combined_purchase_v1'), 'feasibility_tool_protocol_mismatch');
    const health = doc('api-health.raw.json');
    requireFact(artifactRows.get('api-health.raw.json')?.httpStatus === 200 && health.status === 'ready' &&
      health.manifestSha256 === identity.environmentManifestSha256 &&
      health.applicationSourceSha256 === identity.x402ServiceSha256, 'feasibility_application_mismatch');
    requireFact(identity.sourceNetwork === manifest.source.caip2 && identity.sourceChainId === manifest.source.chainId &&
      identity.sourceBlockNumber === BigInt(manifest.source.blockNumber).toString() &&
      identity.sourceBlockHash === cleanHash(manifest.source.blockHash) &&
      identity.localChainId === manifest.local.chainId && identity.localNetwork === `eip155:${manifest.local.chainId}` &&
      identity.localForkBlockNumber === BigInt(manifest.local.forkBlock).toString() &&
      identity.toolSurfaceSha256 === sha256CanonicalTaskJson(manifest.tools), 'feasibility_execution_identity_mismatch');

    const contracts = manifest.contracts;
    const contractRows = [
      ['usdc', 'usdc-proxy', 'proxyCodeHash'], ['weth', 'weth', 'codeHash'], ['factory', 'factory', 'codeHash'],
      ['swapRouter02', 'swap-router-02', 'codeHash'], ['quoterV2', 'quoter-v2', 'codeHash'],
      ['pool', 'pool-500', 'codeHash'], ['pool3000', 'pool-3000', 'codeHash'],
    ] as const;
    const expectedContracts = contractRows.map(([id, , field]) => ({ contractId: id,
      address: contracts[id].address, codeHash: cleanHash(contracts[id][field]), chainId: identity.sourceChainId,
      blockNumber: identity.sourceBlockNumber, blockHash: identity.sourceBlockHash }));
    requireFact(equal(identity.contracts, expectedContracts), 'feasibility_contract_inventory_mismatch');
    requireFact(equal(identity.assets, [
      { assetId: 'ETH', kind: 'native', chainId: identity.sourceChainId, address: null, codeHash: null, decimals: 18 },
      { assetId: 'WETH', kind: 'erc20', chainId: identity.sourceChainId, address: contracts.weth.address,
        codeHash: cleanHash(contracts.weth.codeHash), decimals: Number(contracts.weth.decimals) },
      { assetId: 'USDC', kind: 'erc20', chainId: identity.sourceChainId, address: contracts.usdc.address,
        codeHash: cleanHash(contracts.usdc.proxyCodeHash), decimals: Number(contracts.usdc.decimals) },
    ]), 'feasibility_asset_inventory_mismatch');

    for (const envId of ['bef-env-a', 'bef-env-b']) {
      const capabilities = doc(`${envId}-capabilities.raw.json`);
      requireFact(artifactRows.get(`${envId}-capabilities.raw.json`)?.httpStatus === 200 &&
        artifactRows.get(`${envId}-capabilities.raw.json`)?.envId === envId &&
        capabilities.schemaVersion === 'bef-probe-capabilities/v1' &&
        Array.isArray(capabilities.blockers) && capabilities.blockers.length === 0 &&
        capabilities.envId === envId && capabilities.ready === true &&
        capabilities.manifestSha256 === identity.environmentManifestSha256 &&
        capabilities.applicationSourceSha256 === identity.x402ServiceSha256, 'feasibility_capability_mismatch');
      const proxy = doc(`${envId}-proxy-health.raw.json`);
      requireFact(artifactRows.get(`${envId}-proxy-health.raw.json`)?.envId === envId &&
        proxy.envId === envId && proxy.status === 'ok' && proxy.boundary === 'local-chain-readonly-proxy' &&
        proxy.manifestSha256 === identity.environmentManifestSha256, 'feasibility_proxy_identity_mismatch');
      const rpc = (label: string, method: string, params: unknown[]) => {
        const name = `${envId}-rpc-${label}.raw.json`;
        const row = artifactRows.get(name), response = doc(name);
        requireFact(row?.httpStatus === 200 && row.envId === envId && row.rpcMethod === method &&
          equal(row.rpcParams, params) && !response.error && response.jsonrpc === '2.0' &&
          response.id === 1 && Object.hasOwn(response, 'result'), 'feasibility_rpc_identity_mismatch');
        return response.result;
      };
      requireFact(BigInt(rpc('chain-id', 'eth_chainId', [])) === BigInt(identity.localChainId), 'feasibility_chain_mismatch');
      const block = object(rpc('source-block', 'eth_getBlockByNumber', [manifest.source.blockNumber, false]));
      requireFact(BigInt(block.number) === BigInt(identity.sourceBlockNumber) &&
        cleanHash(block.hash) === identity.sourceBlockHash, 'feasibility_block_mismatch');
      const observations = [...contractRows.map(([id, label, field]) => ({ label, address: contracts[id].address,
        codeHash: contracts[id][field] })), { label: 'usdc-implementation', address: contracts.usdc.implementation,
        codeHash: contracts.usdc.implementationCodeHash }];
      for (const contract of observations) {
        const code = rpc(`code-${contract.label}`, 'eth_getCode', [contract.address, manifest.source.blockNumber]);
        requireFact(typeof code === 'string' && /^0x(?:[0-9a-f]{2})+$/i.test(code) &&
          cleanHash(keccak256(code as Hex)) === cleanHash(contract.codeHash), 'feasibility_contract_code_mismatch');
      }
      const storage = rpc('usdc-implementation-slot', 'eth_getStorageAt',
        [contracts.usdc.address, contracts.usdc.implementationSlot, manifest.source.blockNumber]);
      requireFact(storage === `0x${contracts.usdc.implementation.slice(2).toLowerCase().padStart(64, '0')}`,
        'feasibility_usdc_implementation_mismatch');
    }

    const database = doc('observer-database.raw.json');
    requireFact(database.session?.length === 1 && database.session[0].current_user === 'bef_observer' &&
      database.session[0].session_user === 'bef_observer' && database.session[0].transaction_read_only === 'on' &&
      database.role?.length === 1 && database.memberships?.length === 0, 'feasibility_observer_identity_invalid');
    const role = database.role[0];
    requireFact(role.rolname === 'bef_observer' && role.db_create === false && role.db_connect === true &&
      ['rolsuper', 'rolinherit', 'rolcreaterole', 'rolcreatedb', 'rolreplication', 'rolbypassrls'].every((key) => role[key] === false),
      'feasibility_observer_privileges_invalid');
    requireFact(database.tablePrivileges?.length === 3 &&
      ['bef_schema_migration', 'bef_environment', 'bef_generation'].every((name) => {
        const rows = database.tablePrivileges.filter((entry: Document) => entry.table_name === name);
        return rows.length === 1 && rows[0].can_select === true &&
          ['can_insert', 'can_update', 'can_delete', 'can_truncate', 'can_reference', 'can_trigger'].every((key) => rows[0][key] === false);
      }), 'feasibility_observer_table_privileges_invalid');
    requireFact(Array.isArray(database.migrations) && database.migrations.length > 0 && database.migrations.length <= 128,
      'feasibility_migration_inventory_invalid');
    const migrationFiles = [];
    for (let index = 0; index < database.migrations.length; index += 1) {
      const row = object(database.migrations[index]);
      requireFact(row.migration_id === String(index + 1).padStart(3, '0') &&
        typeof row.filename === 'string' && /^\d{3}_[a-z0-9_]+\.sql$/.test(row.filename), 'feasibility_migration_identity_invalid');
      const path = `infrastructure/benchmark-environment/migrations/${row.filename}`;
      const sha256 = digest(await containedBytes(root, path));
      requireFact(sha256 === row.sha256, 'feasibility_migration_hash_mismatch');
      migrationFiles.push({ path, sha256 });
    }
    const lineage = sha256CanonicalTaskJson({ applicationSourceSha256: identity.x402ServiceSha256, migrationFiles });
    requireFact(identity.applicationSchemaVersion === `bef-db-migrations-001-${String(database.migrations.length).padStart(3, '0')}-${lineage.slice(0, 16)}`,
      'feasibility_schema_lineage_mismatch');
    requireFact(Array.isArray(database.environments) && database.environments.length === 2 &&
      ['bef-env-a', 'bef-env-b'].every((envId) => database.environments.filter((row: Document) => row.env_id === envId &&
        row.chain_id === String(identity.localChainId) && row.manifest_sha256 === identity.environmentManifestSha256).length === 1),
      'feasibility_database_environment_mismatch');
    requireFact(Array.isArray(database.generations) && database.generations.every((row: Document) =>
      ['bef-env-a', 'bef-env-b'].includes(row.env_id) && row.status === 'fenced' &&
      typeof row.generation_id === 'string' && row.fenced_at && Number.isFinite(Date.parse(row.fenced_at))) &&
      new Set(database.generations.map((row: Document) => row.generation_id)).size === database.generations.length,
      'feasibility_generation_fence_unverified');
    requireFact(consumed.size === documents.size, 'feasibility_artifact_inventory_invalid');
    return { status: 'verified', executionIdentityHash: input.expectedIdentityHash, actualBoundary: true };
  } catch (error) {
    const reason = error instanceof Error && /^feasibility_[a-z_]+(?::[a-z0-9._-]+)?$/.test(error.message)
      ? error.message : 'feasibility_evidence_unavailable';
    return { status: reason === 'feasibility_evidence_unavailable' ? 'unavailable' : 'mismatch', reason };
  }
}
