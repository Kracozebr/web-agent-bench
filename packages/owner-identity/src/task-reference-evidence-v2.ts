/**
 * Independent retained-reference reader. This proves a local reference boundary,
 * never an admitted owner run, participant grant, task grade or mainnet result.
 */
import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { open, realpath } from 'node:fs/promises';
import { dirname, isAbsolute, relative, resolve, sep } from 'node:path';
import { canonicalTaskJson, sha256CanonicalTaskJson, type EvidenceReference,
  type ReferencePathVerification, type TaskCase, type TaskReleaseManifest } from './task-release.js';
import { V2ReferenceError, v2Require, type V2Action, type V2Block, type V2Document,
  type V2RawDocument, type V2ReferenceContext, type V2State, type V2GoalProof } from './task-reference-evidence-v2-types.js';

const HASH = /^[0-9a-f]{64}$/;
const HASH32 = /^0x[0-9a-f]{64}$/i;
const ADDRESS = /^0x[0-9a-f]{40}$/i;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const sha = (bytes: Uint8Array) => createHash('sha256').update(bytes).digest('hex');
const equal = (left: unknown, right: unknown) => canonicalTaskJson(left) === canonicalTaskJson(right);
const lower = (value: unknown) => String(value ?? '').toLowerCase();
const plans: Record<string, string[]> = {
  S1: ['transfer'], S2: ['inspect_offer'], S3: ['inspect_catalog'], S4: ['revoke'],
  M1: ['inspect_offer', 'pay', 'retrieve'], M2: ['inspect_catalog', 'pay', 'retrieve'],
  M3: ['approve', 'swap', 'unwrap'], M4: ['wrap', 'approve', 'swap'],
  H1: ['inspect_catalog', 'pay', 'retrieve', 'pay', 'retrieve', 'pay', 'retrieve'],
  H2: Array<string>(6).fill('transfer'), H3: ['inspect_offer', 'pay', 'retrieve', 'wrap', 'approve', 'swap'],
  U1: ['inspect_catalog', 'pay', 'retrieve', 'pay', 'retrieve', 'transfer', 'transfer', 'approve', 'swap', 'unwrap'],
};

function object(value: unknown, code: string): V2Document {
  v2Require(value && typeof value === 'object' && !Array.isArray(value), code);
  return value as V2Document;
}
function header(headers: unknown, key: string): unknown {
  const entries = Object.entries(object(headers, 'v2_reference_headers_missing'));
  return entries.find(([name]) => name.toLowerCase() === key)?.[1];
}
function number(value: unknown, code: string): bigint {
  v2Require(typeof value === 'string' && (/^0x(?:0|[1-9a-f][0-9a-f]*)$/i.test(value)
    || /^(?:0|[1-9][0-9]*)$/.test(value)), code);
  return BigInt(value);
}
function abiWord(value: unknown): string {
  v2Require(typeof value === 'string' && /^0x[0-9a-f]{64}$/i.test(value), 'v2_reference_abi_word_missing', 'unavailable');
  return BigInt(value).toString();
}
function sortedState(balances: V2State['balances'], allowances: V2State['allowances'],
  delivered: readonly string[], fulfilled: readonly string[]): V2State {
  const balanceKey = (item: V2State['balances'][number]) => `${lower(item.account)}|${item.assetId}`;
  const allowanceKey = (item: V2State['allowances'][number]) => `${lower(item.owner)}|${item.tokenAssetId}|${lower(item.spender)}`;
  const compare = (a: string, b: string) => a < b ? -1 : a > b ? 1 : 0;
  return { balances: [...balances].sort((a, b) => compare(balanceKey(a), balanceKey(b))),
    allowances: [...allowances].sort((a, b) => compare(allowanceKey(a), allowanceKey(b))),
    deliveredComponentIds: [...new Set(delivered)].sort(), fulfilledObligationIds: [...new Set(fulfilled)].sort() };
}

async function readPinned(root: string, path: string, expectedHash: string): Promise<{ bytes: Buffer; value: V2Document }> {
  v2Require(typeof path === 'string' && path.length <= 512 && path.trim() === path && !isAbsolute(path)
    && !path.includes('\\') && !path.includes(':') && path.split('/').every((part) => part && part !== '.' && part !== '..')
    && HASH.test(expectedHash), 'v2_reference_path_or_hash_invalid');
  const actual = await realpath(resolve(root, path));
  const rel = relative(root, actual);
  v2Require(rel && !isAbsolute(rel) && rel !== '..' && !rel.startsWith(`..${sep}`), 'v2_reference_path_escape');
  const handle = await open(actual, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const before = await handle.stat();
    v2Require(before.isFile() && before.size > 0 && before.size <= 8 * 1024 * 1024, 'v2_reference_file_invalid');
    const bytes = Buffer.alloc(before.size + 1);
    let offset = 0;
    while (offset < bytes.length) {
      const { bytesRead } = await handle.read(bytes, offset, bytes.length - offset, offset);
      if (!bytesRead) break;
      offset += bytesRead;
    }
    const after = await handle.stat();
    v2Require(offset === before.size && after.size === before.size && after.mtimeMs === before.mtimeMs
      && after.ctimeMs === before.ctimeMs, 'v2_reference_file_changed');
    const content = bytes.subarray(0, offset);
    v2Require(sha(content) === expectedHash, 'v2_reference_artifact_hash_mismatch');
    return { bytes: content, value: object(JSON.parse(content.toString('utf8')), 'v2_reference_document_invalid') };
  } finally { await handle.close(); }
}

export type V2ReferenceVerifierInput = {
  repositoryRoot: string;
  identity: TaskReleaseManifest['executionIdentity'];
  profilePolicy: { path: string; sha256: string };
  evidence: EvidenceReference;
  taskCase: TaskCase;
  executionIdentityHash: string;
};

/** The loader exposes raw facts only. Goal modules must derive goals, not trust capture flags. */
export async function loadV2ReferenceContext(input: V2ReferenceVerifierInput): Promise<V2ReferenceContext> {
  const root = await realpath(input.repositoryRoot);
  const { taskCase, identity, evidence } = input;
  const { caseHash, ...caseFields } = taskCase;
  v2Require(sha256CanonicalTaskJson(caseFields) === caseHash && taskCase.executionIdentityHash === input.executionIdentityHash
    && sha256CanonicalTaskJson(identity) === input.executionIdentityHash, 'v2_reference_case_identity_mismatch');
  v2Require(evidence.boundary === 'actual_tool_http_x402_local_evm_application_store'
    && equal(evidence, taskCase.referencePath.evidence), 'v2_reference_evidence_binding_mismatch');
  const envelopeInput = await readPinned(root, evidence.path, evidence.sha256), envelope = envelopeInput.value;
  v2Require(envelope.schemaVersion === 'bts-task-case-evidence-composition/v2'
    && envelope.purpose === 'reference_execution_trace' && envelope.taskId === taskCase.taskId
    && envelope.mode === taskCase.mode && envelope.caseId === taskCase.caseId
    && envelope.executionIdentityHash === input.executionIdentityHash, 'v2_reference_envelope_binding_mismatch');
  const baseline = (await readPinned(root, taskCase.initialStateEvidence.path, taskCase.initialStateEvidence.sha256)).value;
  v2Require(taskCase.initialStateEvidence.boundary === evidence.boundary
    && baseline.schemaVersion === envelope.schemaVersion && baseline.purpose === 'initial_state_projection'
    && baseline.taskId === taskCase.taskId && baseline.mode === taskCase.mode && baseline.caseId === taskCase.caseId
    && baseline.executionIdentityHash === input.executionIdentityHash
    && baseline.taskStateSha256 === taskCase.initialState.stateSha256
    && equal(baseline.probe, envelope.probe) && equal(baseline.rawReferences, envelope.rawReferences),
  'v2_reference_initial_evidence_binding_mismatch');
  const probeRef = object(envelope.probe, 'v2_reference_probe_ref_missing');
  const probeInput = await readPinned(root, probeRef.path, probeRef.sha256), probe = probeInput.value;
  v2Require(probe.schemaVersion === 'bts-difficulty-v2-reference-probe/v1' && probe.status === 'captured'
    && probe.taskId === taskCase.taskId && probe.mode === taskCase.mode
    && probe.participantToolProtocol === 'separate_payment_delivery_v2'
    && probe.noTaskGrade === true && probe.noReleaseActivation === true && probe.noAcceptanceClaim === true,
  'v2_reference_probe_contract_mismatch');
  const sources = object(probe.sourceDigests, 'v2_reference_source_pins_missing');
  v2Require(sources.matches === true && sources.before.appSourceSha256 === identity.x402ServiceSha256
    && sources.before.manifestSha256 === identity.environmentManifestSha256
    && Object.entries(sources.before).every(([key, value]) => HASH.test(String(value)) && sources.after[key] === value),
  'v2_reference_source_pins_mismatch');
  const generation = object(probe.environment, 'v2_reference_generation_missing');
  v2Require(UUID.test(generation.generationId) && ADDRESS.test(generation.payerAddress)
    && typeof generation.envId === 'string' && typeof generation.participantId === 'string', 'v2_reference_generation_invalid');
  const captureRoot = dirname(probeRef.path).replaceAll('\\', '/');
  v2Require(Array.isArray(probe.artifacts) && probe.artifacts.length > 0 && probe.artifacts.length <= 512
    && Array.isArray(probe.observations), 'v2_reference_inventory_invalid');
  const order = new Map<string, number>();
  probe.observations.forEach((item: V2Document, index: number) => {
    v2Require(typeof item.sourceArtifact === 'string' && !order.has(item.sourceArtifact), 'v2_reference_observation_order_invalid');
    order.set(item.sourceArtifact, index);
  });
  const documents: V2RawDocument[] = [], rawBytes = new Map<string, Buffer>(), byPath = new Map<string, V2RawDocument>();
  const envelopeRefs = new Map<string, V2Document>();
  v2Require(Array.isArray(envelope.rawReferences), 'v2_reference_envelope_inventory_missing');
  for (const ref of envelope.rawReferences) {
    v2Require(!envelopeRefs.has(ref.path), 'v2_reference_duplicate_raw_reference'); envelopeRefs.set(ref.path, ref);
  }
  for (const artifact of probe.artifacts) {
    v2Require(typeof artifact.path === 'string' && !byPath.has(artifact.path), 'v2_reference_duplicate_artifact');
    const path = `${captureRoot}/${artifact.path}`;
    const listed = envelopeRefs.get(path);
    v2Require(listed && listed.sha256 === artifact.sha256 && listed.boundary === artifact.boundary,
      'v2_reference_raw_inventory_binding_mismatch');
    const loaded = await readPinned(root, path, artifact.sha256);
    const doc = { path: artifact.path, sha256: artifact.sha256, boundary: artifact.boundary,
      order: order.get(artifact.path) ?? -1, value: loaded.value };
    documents.push(doc); byPath.set(doc.path, doc); rawBytes.set(doc.path, loaded.bytes);
  }
  v2Require(envelopeRefs.size === documents.length, 'v2_reference_unindexed_raw_reference');
  const raw = (path: string) => {
    const doc = byPath.get(path); v2Require(doc, 'v2_reference_raw_artifact_missing', 'unavailable'); return doc.value;
  };
  const manifestRef = object(probe.manifest, 'v2_reference_manifest_ref_missing');
  v2Require(byPath.get(manifestRef.path)?.sha256 === identity.environmentManifestSha256
    && manifestRef.sha256 === identity.environmentManifestSha256, 'v2_reference_manifest_hash_mismatch');
  const manifest = raw(manifestRef.path);
  v2Require(sha256CanonicalTaskJson(manifest.tools) === identity.toolSurfaceSha256
    && manifest.tools.participantProtocol === probe.participantToolProtocol, 'v2_reference_tool_surface_mismatch');
  const profileRef = object(probe.difficultyProfile, 'v2_reference_profile_ref_missing');
  v2Require(byPath.get(profileRef.evidencePath)?.sha256 === profileRef.evidenceSha256
    && profileRef.evidenceSha256 === profileRef.sourceSha256 && profileRef.sourceSha256 === sources.before.profileSha256
    && raw(profileRef.evidencePath).runtimeManifest?.sha256 === identity.environmentManifestSha256,
  'v2_reference_profile_copy_mismatch');
  const endpointBindings = documents.filter((doc) => doc.value.schemaVersion === 'bef-rpc-endpoint-binding/v1'
    && doc.value.environmentId === generation.envId && doc.value.boundary === 'local-chain-readonly-proxy');
  v2Require(endpointBindings.length === 1, 'v2_reference_rpc_endpoint_binding_missing', 'unavailable');
  const endpointDoc = endpointBindings[0]!, endpoint = endpointDoc.value;
  const endpointHealth = raw(endpoint.healthArtifactPath);
  v2Require(endpoint.endpointRef?.scheme === 'http'
    && ['127.0.0.1', 'localhost', '::1'].includes(lower(endpoint.endpointRef.host))
    && Number.isInteger(endpoint.endpointRef.port) && endpoint.endpointRef.port > 0 && endpoint.endpointRef.port <= 65535
    && byPath.get(endpoint.healthArtifactPath)?.sha256 === endpoint.healthArtifactSha256
    && equal(endpoint.health, endpointHealth) && endpointHealth.status === 'ok'
    && endpointHealth.boundary === 'local-chain-readonly-proxy' && endpointHealth.envId === generation.envId
    && endpointHealth.manifestSha256 === identity.environmentManifestSha256, 'v2_reference_rpc_endpoint_identity_mismatch');
  const policyInput = await readPinned(root, input.profilePolicy.path, input.profilePolicy.sha256), policy = policyInput.value;
  v2Require(policy.profileId === identity.profileId && policy.boundary === 'isolated_local_bef_anvil_fork'
    && equal(envelope.policyInput, { ...input.profilePolicy }), 'v2_reference_policy_binding_mismatch');
  const capability = documents.find((doc) => doc.value.schemaVersion === 'bef-http-observation/v1'
    && doc.value.response?.body?.schemaVersion === 'bef-probe-capabilities/v1')?.value;
  const capabilityBody = capability?.response?.body;
  v2Require(capability?.response?.status === 200 && capabilityBody.envId === generation.envId
    && capabilityBody.manifestSha256 === identity.environmentManifestSha256
    && capabilityBody.applicationSourceSha256 === identity.x402ServiceSha256, 'v2_reference_capability_identity_mismatch');
  const local = object(capabilityBody.services?.localRpc, 'v2_reference_local_fork_proof_missing');
  v2Require(lower(local.clientVersion).includes(`anvil/v${manifest.local.anvilVersion}`.toLowerCase())
    && number(local.chainId, 'v2_reference_chain_id_invalid') === BigInt(identity.localChainId)
    && lower(local.executionNetwork) === lower(manifest.local.executionNetwork)
    && lower(local.hardFork) === lower(manifest.local.hardfork)
    && number(local.forkBlockNumber, 'v2_reference_fork_height_invalid') === BigInt(identity.localForkBlockNumber)
    && lower(local.forkBlockHash).replace(/^0x/, '') === identity.sourceBlockHash, 'v2_reference_local_fork_identity_mismatch');
  const role = documents.find((doc) => doc.value.queryName === 'observer-role-effective-privileges')?.value;
  v2Require(role?.readOnly === true && role.databaseRole === 'bef_observer' && role.role?.role_name === 'bef_observer'
    && Object.entries(role.role).every(([key, value]) => key === 'role_name' || value === false)
    && Array.isArray(role.rows) && role.rows.length > 0 && role.rows.every((row: V2Document) => row.can_select === true
      && Object.entries(row).every(([key, value]) => key === 'table_name' || key === 'can_select' || value === false)),
  'v2_reference_observer_privileges_mismatch');
  const generationRoute = `/internal/admin/environments/${generation.envId}/generations`;
  const created = documents.filter((doc) => doc.value.schemaVersion === 'bef-http-observation/v1'
    && doc.value.request?.method === 'POST' && doc.value.request?.path === generationRoute
    && doc.value.response?.body?.generationId === generation.generationId);
  v2Require(created.length === 1 && created[0]!.order >= 0, 'v2_reference_generation_creation_missing', 'unavailable');
  const create = created[0]!, createBody = create.value.response.body;
  v2Require(create.value.response.status >= 200 && create.value.response.status < 300
    && createBody.envId === generation.envId && lower(createBody.payerAddress) === lower(generation.payerAddress)
    && create.value.request.body?.participantId === generation.participantId, 'v2_reference_generation_creation_mismatch');
  const fenceRoute = `${generationRoute}/${generation.generationId}/fence`;
  const fences = documents.filter((doc) => doc.order > create.order && doc.value.schemaVersion === 'bef-http-observation/v1'
    && doc.value.request?.method === 'POST' && doc.value.request?.path === fenceRoute);
  v2Require(fences.length >= 1 && fences.every((doc) => doc.value.response?.status === 200
    && doc.value.response.body?.status === 'fenced' && doc.value.response.body.signerErased === true),
  'v2_reference_generation_fence_missing', 'unavailable');
  const fenceOrder = Math.min(...fences.map((doc) => doc.order));
  const actualDocuments = documents.filter((doc) => doc.order > create.order && doc.order < fenceOrder);
  v2Require(!actualDocuments.some((doc) => doc.value.schemaVersion === 'bef-http-observation/v1'
    && doc.value.request?.method === 'POST' && /\/reset$/.test(String(doc.value.request?.path))), 'v2_reference_reset_inside_actual_path');
  const generationRows = documents.filter((doc) => doc.order > create.order && doc.value.queryName === 'generation-by-id'
    && doc.value.envId === generation.envId && doc.value.generationId === generation.generationId);
  v2Require(generationRows.some((doc) => doc.order > fenceOrder && doc.value.readOnly === true
    && doc.value.databaseRole === 'bef_observer' && doc.value.transactionReadOnly === 'on'
    && doc.value.rows?.length === 1 && doc.value.rows[0].status === 'fenced'
    && doc.value.rows[0].generation_id === generation.generationId && doc.value.rows[0].participant_id === generation.participantId
    && lower(doc.value.rows[0].payer_address) === lower(generation.payerAddress)), 'v2_reference_independent_fence_missing', 'unavailable');
  const actions = probe.captureReferences?.participantActions as V2Action[];
  v2Require(Array.isArray(actions) && actions.length === plans[taskCase.taskId]!.length
    && actions.length === taskCase.referencePath.actionCount && actions.length === probe.participantActionCount
    && equal(actions, envelope.participantActions), 'v2_reference_action_count_or_binding_mismatch');
  const seen = new Set<string>();
  actions.forEach((action, index) => {
    v2Require(action.kind === plans[taskCase.taskId]![index] && UUID.test(action.operationId), 'v2_reference_action_plan_mismatch');
    if (action.kind === 'retrieve') v2Require(index > 0 && actions[index - 1]!.kind === 'pay'
      && actions[index - 1]!.operationId === action.operationId, 'v2_reference_retrieve_payment_binding_mismatch');
    else { v2Require(!seen.has(action.operationId), 'v2_reference_reused_operation'); seen.add(action.operationId); }
    const doc = byPath.get(action.rawResponsePath);
    v2Require(doc && doc.sha256 === action.rawResponseSha256
      && ['actual-tool-http', 'actual-tool-http-raw-response'].includes(doc.boundary)
      && doc.value.operationId === action.operationId, 'v2_reference_action_raw_response_mismatch');
  });
  const rpc = (method: string): readonly V2Document[] => actualDocuments.filter((doc) => doc.value.schemaVersion === 'bef-rpc-observation/v1'
    && doc.value.method === method && doc.value.boundary === 'local-chain-readonly-proxy'
    && doc.value.endpointBoundary === 'local-chain-readonly-proxy' && doc.value.environmentId === generation.envId
    && doc.value.endpointIdentityArtifact === endpointDoc.path && equal(doc.value.endpointRef, endpoint.endpointRef)).map((doc) => doc.value);
  const choose = (values: unknown[], code: string): V2Document => {
    v2Require(values.length > 0, code, 'unavailable'); const first = object(values[0], code);
    v2Require(values.every((value) => equal(value, first)), 'v2_reference_contradictory_rpc_result'); return first;
  };
  const receipt = (tx: string) => {
    v2Require(HASH32.test(tx), 'v2_reference_transaction_hash_invalid');
    const value = choose(rpc('eth_getTransactionReceipt').filter((doc) => lower(doc.result?.transactionHash) === lower(tx)).map((doc) => doc.result),
      'v2_reference_receipt_missing');
    v2Require(lower(value.status) === '0x1' && HASH32.test(value.blockHash) && ADDRESS.test(value.from)
      && ADDRESS.test(value.to) && Array.isArray(value.logs), 'v2_reference_receipt_invalid'); return value;
  };
  const transaction = (tx: string) => choose(rpc('eth_getTransactionByHash').filter((doc) => lower(doc.result?.hash) === lower(tx))
    .map((doc) => doc.result), 'v2_reference_transaction_missing');
  const block = (target: V2Block) => {
    v2Require(HASH32.test(target.hash), 'v2_reference_block_hash_invalid');
    const matches = rpc('eth_getBlockByNumber').filter((doc) => doc.result && lower(doc.result.hash) === lower(target.hash)
      && number(doc.params?.[0], 'v2_reference_block_parameter_invalid') === number(target.number, 'v2_reference_block_number_invalid'));
    v2Require(matches.length > 0 && matches.every((doc) => number(doc.result.number, 'v2_reference_block_number_invalid')
      === number(target.number, 'v2_reference_block_number_invalid')), 'v2_reference_block_missing', 'unavailable');
    return matches[0]!.result as V2Document;
  };
  const wordAddress = (address: string) => { v2Require(ADDRESS.test(address), 'v2_reference_account_invalid'); return address.slice(2).toLowerCase().padStart(64, '0'); };
  const amountResult = (values: unknown[], abi: boolean): string => {
    v2Require(values.length > 0, 'v2_reference_state_read_missing', 'unavailable');
    const amounts = values.map((value) => abi ? abiWord(value) : number(value, 'v2_reference_native_quantity_invalid').toString());
    v2Require(amounts.every((value) => value === amounts[0]), 'v2_reference_contradictory_state'); return amounts[0]!;
  };
  const stateAt: V2ReferenceContext['stateAt'] = (shape, target, delivered = [], fulfilled = []) => {
    block(target);
    const atBlock = (value: unknown) => number(value, 'v2_reference_state_block_invalid') === number(target.number, 'v2_reference_state_block_invalid');
    const account = (value: string) => value === 'participant' ? generation.payerAddress : value;
    const assets = new Map(identity.assets.map((asset) => [asset.assetId, asset]));
    const balances = shape.balances.map((item) => {
      const asset = assets.get(item.assetId); v2Require(asset, 'v2_reference_asset_missing');
      const address = account(item.account); wordAddress(address);
      let amountUnits: string;
      if (asset.kind === 'native') amountUnits = amountResult(rpc('eth_getBalance')
        .filter((doc) => lower(doc.params?.[0]) === lower(address) && atBlock(doc.params?.[1])).map((doc) => doc.result), false);
      else {
        const data = `0x70a08231${wordAddress(address)}`;
        amountUnits = amountResult(rpc('eth_call').filter((doc) => lower(doc.params?.[0]?.to) === lower(asset.address)
          && lower(doc.params?.[0]?.data) === data && atBlock(doc.params?.[1])).map((doc) => doc.result), true);
      }
      return { account: item.account, assetId: item.assetId, amountUnits };
    });
    const allowances = shape.allowances.map((item) => {
      const asset = assets.get(item.tokenAssetId); v2Require(asset?.kind === 'erc20', 'v2_reference_allowance_asset_invalid');
      const data = `0xdd62ed3e${wordAddress(account(item.owner))}${wordAddress(item.spender)}`;
      const amountUnits = amountResult(rpc('eth_call').filter((doc) => lower(doc.params?.[0]?.to) === lower(asset.address)
        && lower(doc.params?.[0]?.data) === data && atBlock(doc.params?.[1])).map((doc) => doc.result), true);
      return { ...item, amountUnits };
    });
    return sortedState(balances, allowances, delivered, fulfilled);
  };
  const database = (): readonly V2Document[] => actualDocuments.filter((doc) => doc.value.schemaVersion === 'bef-db-observation/v1'
    && doc.value.envId === generation.envId && doc.value.generationId === generation.generationId
    && doc.value.readOnly === true && doc.value.databaseRole === 'bef_observer' && doc.value.transactionReadOnly === 'on').map((doc) => doc.value);
  const http = (action: V2Action): readonly V2Document[] => actualDocuments.filter((doc) => doc.value.schemaVersion === 'bef-http-observation/v1'
    && doc.value.boundary === 'actual-tool-http' && (doc.value.response?.body?.operationId === action.operationId
      || lower(header(doc.value.response?.headers, 'x-bef-operation-id')) === lower(action.operationId))).map((doc) => doc.value);
  const actionBody = (action: V2Action) => {
    const body = raw(action.rawResponsePath), witnesses = http(action);
    v2Require(witnesses.some((doc) => doc.response.status >= 200 && doc.response.status < 300
      && equal(doc.response.body, body) && header(doc.request.headers, 'x-bef-generation') === generation.generationId),
    'v2_reference_action_http_witness_missing', 'unavailable'); return body;
  };
  actions.forEach(actionBody);
  // AICODE-NOTE: amounts in the evidence envelope are only shape/locator inputs.
  // stateAt obtains every amount from exact address/token/calldata/block RPC reads.
  return { taskCase, identity, manifest, policy, probe, envelope, generation: generation as V2ReferenceContext['generation'],
    actions, documents, actualDocuments, raw, action: actionBody, http, rpc, receipt, transaction, block, stateAt, database };
}

export async function verifyTaskReferenceEvidenceV2(input: V2ReferenceVerifierInput): Promise<ReferencePathVerification> {
  try {
    const context = await loadV2ReferenceContext(input);
    const basic = ['S1', 'S2', 'S3', 'S4', 'M3'].includes(input.taskCase.taskId);
    const modulePath = basic ? './task-reference-evidence-v2-basic.js' : './task-reference-evidence-v2-advanced.js';
    const module = await import(modulePath) as Record<string, unknown>;
    const handler = module[basic ? 'verifyBasicV2ReferenceGoal' : 'verifyAdvancedV2ReferenceGoal'];
    v2Require(typeof handler === 'function', 'v2_reference_goal_verifier_unavailable', 'unavailable');
    const proof = await (handler as (context: V2ReferenceContext) => Promise<V2GoalProof>)(context);
    v2Require(typeof proof?.initiallySolved === 'boolean' && typeof proof.solvable === 'boolean'
      && Array.isArray(proof.deliveredComponentIds) && proof.deliveredComponentIds.every((id) => typeof id === 'string')
      && Array.isArray(proof.fulfilledObligationIds) && proof.fulfilledObligationIds.every((id) => typeof id === 'string'),
    'v2_reference_goal_proof_invalid');
    if (proof.initiallySolved) return { status: 'initially_solved', reason: 'v2_reference_initial_objective_already_satisfied' };
    if (!proof.solvable) return { status: 'unsolvable', reason: 'v2_reference_goal_not_satisfied' };
    const { stateSha256: _stateHash, ...initialShape } = input.taskCase.initialState;
    const finalShape = object(context.envelope.finalState, 'v2_reference_final_shape_missing') as V2State;
    const stateKeys = (state: V2State) => ({ balances: state.balances.map((row) => `${lower(row.account)}|${row.assetId}`).sort(),
      allowances: state.allowances.map((row) => `${lower(row.owner)}|${row.tokenAssetId}|${lower(row.spender)}`).sort() });
    v2Require(equal(stateKeys(initialShape), stateKeys(finalShape)), 'v2_reference_state_scope_changed');
    const initial = context.stateAt(initialShape, proof.initialBlock);
    const final = context.stateAt(finalShape, proof.finalBlock, proof.deliveredComponentIds, proof.fulfilledObligationIds);
    v2Require(equal(initial, initialShape) && sha256CanonicalTaskJson(initial) === input.taskCase.initialState.stateSha256
      && sha256CanonicalTaskJson(initial) === input.taskCase.referencePath.initialStateSha256
      && sha256CanonicalTaskJson(final) === input.taskCase.referencePath.finalStateSha256, 'v2_reference_observed_state_hash_mismatch');
    return { status: 'verified', caseHash: input.taskCase.caseHash, executionIdentityHash: input.executionIdentityHash,
      toolSurfaceSha256: input.identity.toolSurfaceSha256, actionCount: context.actions.length,
      initialStateSha256: sha256CanonicalTaskJson(initial), finalStateSha256: sha256CanonicalTaskJson(final),
      solvable: true, initiallySolved: false, actualBoundary: true };
  } catch (error) {
    if (error instanceof V2ReferenceError) {
      if (error.disposition === 'initially_solved') return { status: 'initially_solved', reason: error.code };
      if (error.disposition === 'unsolvable') return { status: 'unsolvable', reason: error.code };
      return { status: error.disposition, reason: error.code };
    }
    return { status: 'unavailable', reason: 'v2_reference_evidence_unavailable' };
  }
}
