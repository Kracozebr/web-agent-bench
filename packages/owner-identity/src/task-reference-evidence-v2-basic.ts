/**
 * Semantic checks for the basic retained BTS reference paths. Only hash-checked
 * HTTP, RPC and read-only DB observations in the selected generation are proof.
 */
import { createHash } from 'node:crypto';
import { canonicalTaskJson, sha256CanonicalTaskJson, type TaskCase } from './task-release.js';
import { V2ReferenceError, type V2ReferenceError as V2ReferenceErrorType,
  type V2Action, type V2Block, type V2Document,
  type V2GoalProof, type V2ReferenceContext, type V2State } from './task-reference-evidence-v2-types.js';

const TRANSFER_TOPIC = '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';
const APPROVAL_TOPIC = '0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925';
const SWAP_TOPIC = '0xc42079f94a6350d7e6235f29174924f928cc2ac818eb64fed8004e115fbcca67';
const WITHDRAWAL_TOPIC = '0x7fcf532c15f0a6db0bd6d0e038bea71d30d808c7d98cb3bf7268a95bf5081b65';
const HASH32 = /^0x[0-9a-f]{64}$/i;
const ADDRESS = /^0x[0-9a-f]{40}$/i;

type BasicTaskCase = Extract<TaskCase, { taskId: 'S1' | 'S2' | 'S3' | 'S4' | 'M3' }>;
type TxProof = { action: V2Action; body: V2Document; http: V2Document; httpOrder: number;
  transactionHash: string; receipt: V2Document; transaction: V2Document; block: V2Block; gasCostWei: bigint };

function v2Require(condition: unknown, code: string,
  disposition: V2ReferenceErrorType['disposition'] = 'mismatch'): asserts condition {
  if (!condition) throw new V2ReferenceError(code, disposition);
}

function object(value: unknown, code: string,
  disposition: V2ReferenceErrorType['disposition'] = 'mismatch'): V2Document {
  v2Require(value !== null && typeof value === 'object' && !Array.isArray(value), code, disposition);
  return value as V2Document;
}

function list(value: unknown, code: string): V2Document[] {
  v2Require(Array.isArray(value), code);
  return value as V2Document[];
}

function lower(value: unknown): string { return String(value ?? '').toLowerCase(); }

function equal(left: unknown, right: unknown): boolean {
  return canonicalTaskJson(left) === canonicalTaskJson(right);
}

function integer(value: unknown, code: string): bigint {
  v2Require(typeof value === 'string' && (/^0x(?:0|[1-9a-f][0-9a-f]*)$/i.test(value)
    || /^(?:0|[1-9][0-9]*)$/.test(value)), code);
  return BigInt(value);
}

function wordInteger(value: unknown, code: string): bigint {
  v2Require(typeof value === 'string' && /^0x[0-9a-f]{64}$/i.test(value), code, 'unavailable');
  return BigInt(value);
}

function wordAddress(value: unknown, code: string): string {
  v2Require(typeof value === 'string' && /^0x[0-9a-f]{64}$/i.test(value), code, 'unavailable');
  const found = `0x${value.slice(-40)}`;
  v2Require(ADDRESS.test(found), code);
  return found.toLowerCase();
}

function sha256(bytes: Uint8Array): string { return createHash('sha256').update(bytes).digest('hex'); }

function taskStateShape(taskCase: BasicTaskCase): V2State {
  const { stateSha256: _stateSha256, ...shape } = taskCase.initialState;
  return shape;
}

function stateAmount(state: V2State, account: string, assetId: string): bigint {
  const matches = state.balances.filter((item) => lower(item.account) === lower(account) && item.assetId === assetId);
  v2Require(matches.length === 1, `v2_basic_state_balance_missing_${assetId}`, 'unavailable');
  return integer(matches[0]!.amountUnits, 'v2_basic_state_balance_invalid');
}

function stateAllowance(state: V2State, owner: string, tokenAssetId: string, spender: string): bigint {
  const matches = state.allowances.filter((item) => lower(item.owner) === lower(owner)
    && item.tokenAssetId === tokenAssetId && lower(item.spender) === lower(spender));
  v2Require(matches.length === 1, `v2_basic_state_allowance_missing_${tokenAssetId}`, 'unavailable');
  return integer(matches[0]!.amountUnits, 'v2_basic_state_allowance_invalid');
}

function assetAddress(ctx: V2ReferenceContext, assetId: string): string {
  const asset = ctx.identity.assets.find((item) => item.assetId === assetId);
  v2Require(asset?.kind === 'erc20' && typeof asset.address === 'string' && ADDRESS.test(asset.address),
    `v2_basic_asset_address_missing_${assetId}`, 'unavailable');
  return asset.address;
}

function contractAddress(ctx: V2ReferenceContext, contractId: string): string {
  const contract = ctx.identity.contracts.find((item) => item.contractId === contractId);
  v2Require(contract && ADDRESS.test(contract.address), `v2_basic_contract_missing_${contractId}`, 'unavailable');
  return contract.address;
}

function requireActionPlan(ctx: V2ReferenceContext, expected: readonly string[]): V2Action[] {
  v2Require(ctx.actions.length === expected.length && ctx.actions.every((action, index) => action.kind === expected[index]),
    'v2_basic_action_plan_mismatch');
  return [...ctx.actions];
}

function httpWitness(ctx: V2ReferenceContext, action: V2Action): { body: V2Document; http: V2Document; order: number } {
  const body = object(ctx.action(action), 'v2_basic_action_body_missing');
  const witnesses = ctx.http(action).filter((item) => item.response?.status >= 200 && item.response?.status < 300
    && equal(item.response?.body, body)
    && header(item.request?.headers, 'x-bef-generation') === ctx.generation.generationId);
  v2Require(witnesses.length === 1, 'v2_basic_actual_http_witness_missing', 'unavailable');
  const matching = ctx.actualDocuments.filter((doc) => doc.value.schemaVersion === 'bef-http-observation/v1'
    && doc.value.boundary === 'actual-tool-http' && equal(doc.value.response?.body, body)
    && header(doc.value.request?.headers, 'x-bef-generation') === ctx.generation.generationId);
  v2Require(matching.length === 1, 'v2_basic_actual_http_order_missing', 'unavailable');
  return { body, http: witnesses[0]!, order: matching[0]!.order };
}

function header(headers: unknown, key: string): unknown {
  if (!headers || typeof headers !== 'object' || Array.isArray(headers)) return undefined;
  return Object.entries(headers as V2Document).find(([name]) => name.toLowerCase() === key)?.[1];
}

function blockAtPath(ctx: V2ReferenceContext, suffix: RegExp, code: string): V2Block {
  const matches = ctx.actualDocuments.filter((doc) => doc.value.schemaVersion === 'bef-rpc-observation/v1'
    && doc.value.method === 'eth_getBlockByNumber' && doc.value.boundary === 'local-chain-readonly-proxy'
    && suffix.test(doc.path));
  v2Require(matches.length === 1, code, 'unavailable');
  const result = object(matches[0]!.value.result, `${code}_result_missing`);
  const block = { number: String(result.number ?? ''), hash: String(result.hash ?? '') };
  v2Require(HASH32.test(block.hash) && block.number.length > 0, `${code}_invalid`);
  const independentlyMatched = ctx.block(block);
  v2Require(lower(independentlyMatched.hash) === lower(block.hash)
    && integer(independentlyMatched.number, `${code}_number_invalid`) === integer(block.number, `${code}_number_invalid`),
  `${code}_rpc_binding_mismatch`);
  return block;
}

function compareBlocks(left: V2Block, right: V2Block): boolean {
  return integer(left.number, 'v2_basic_block_number_invalid') === integer(right.number, 'v2_basic_block_number_invalid')
    && lower(left.hash) === lower(right.hash);
}

function operationOrder(ctx: V2ReferenceContext, operationId: string): number {
  const matches = ctx.actualDocuments.filter((doc) => doc.value.schemaVersion === 'bef-http-observation/v1'
    && doc.value.boundary === 'actual-tool-http'
    && (doc.value.response?.body?.operationId === operationId || lower(header(doc.value.response?.headers, 'x-bef-operation-id')) === lower(operationId)));
  v2Require(matches.length === 1, 'v2_basic_operation_http_order_missing', 'unavailable');
  return matches[0]!.order;
}

function databaseDocuments(ctx: V2ReferenceContext): Array<{ value: V2Document; order: number }> {
  const raw = ctx.actualDocuments.filter((doc) => doc.value.schemaVersion === 'bef-db-observation/v1');
  const allowed = ctx.database();
  v2Require(raw.length > 0 && allowed.length === raw.length, 'v2_basic_readonly_database_missing', 'unavailable');
  for (const item of raw) {
    v2Require(item.value.boundary === 'readonly-database' && item.value.readOnly === true
      && item.value.databaseRole === 'bef_observer' && item.value.transactionReadOnly === 'on'
      && item.value.envId === ctx.generation.envId && item.value.generationId === ctx.generation.generationId,
    'v2_basic_database_scope_mismatch');
    v2Require(allowed.some((candidate) => equal(candidate, item.value)), 'v2_basic_database_accessor_mismatch');
  }
  return raw.map((doc) => ({ value: doc.value, order: doc.order }));
}

function rowsFrom(value: unknown, keys: readonly string[] = []): V2Document[] {
  if (Array.isArray(value)) return value as V2Document[];
  if (!value || typeof value !== 'object') return [];
  const record = value as V2Document;
  for (const key of keys) if (Array.isArray(record[key])) return record[key] as V2Document[];
  return [];
}

function operationRows(doc: V2Document): V2Document[] {
  return rowsFrom(doc.rows, ['operations', 'operation']);
}

function transactionCost(doc: V2Document): V2Document | null {
  const rows = doc.rows;
  if (!rows || typeof rows !== 'object' || Array.isArray(rows)) return null;
  const candidate = (rows as V2Document).transactionCost;
  return candidate && typeof candidate === 'object' && !Array.isArray(candidate) ? candidate as V2Document : null;
}

function dbOperation(ctx: V2ReferenceContext, operationId: string): V2Document {
  const found = databaseDocuments(ctx).flatMap(({ value }) => operationRows(value)
    .filter((row) => row.operation_id === operationId
      && (row.env_id === undefined || row.env_id === ctx.generation.envId)
      && (row.generation_id === undefined || row.generation_id === ctx.generation.generationId)));
  v2Require(found.length > 0, 'v2_basic_operation_database_row_missing', 'unavailable');
  const first = found[0]!;
  v2Require(found.every((row) => equal(row, first)), 'v2_basic_operation_database_rows_contradict');
  return first;
}

function verifyReadCensus(ctx: V2ReferenceContext, action: V2Action, kind: 'offer' | 'catalog', responseHash: string): void {
  const actionOrder = operationOrder(ctx, action.operationId);
  const censuses = databaseDocuments(ctx).filter(({ value }) =>
    value.queryName === 'reference-case-operation-payment-delivery-cost-effect-census');
  const before = censuses.filter((item) => item.order < actionOrder).sort((a, b) => b.order - a.order)[0];
  const after = censuses.filter((item) => item.order > actionOrder).sort((a, b) => b.order - a.order)[0];
  v2Require(before && after, 'v2_basic_read_census_interval_missing', 'unavailable');
  const beforeRows = object(before.value.rows, 'v2_basic_read_census_before_rows_missing');
  const beforeCounts = object(beforeRows.counts, 'v2_basic_read_census_before_counts_missing');
  for (const key of ['operations', 'payments', 'deliveries', 'denials', 'x402Observations', 'selectedExecutions',
    'selectedExecutionEvents', 'transactionCosts', 'participantCosts']) {
    v2Require(integer(String(beforeCounts[key]), `v2_basic_read_census_${key}_invalid`) === 0n,
      `v2_basic_read_census_not_empty_before_${key}`);
  }
  const afterRows = object(after.value.rows, 'v2_basic_read_census_after_rows_missing');
  const counts = object(afterRows.counts, 'v2_basic_read_census_after_counts_missing');
  const expectedCounts: Record<string, bigint> = {
    operations: 1n, offerOperations: kind === 'offer' ? 1n : 0n,
    purchaseOperations: 0n, nonOfferOperations: kind === 'catalog' ? 1n : 0n,
    payments: 0n, deliveries: 0n, denials: 0n, x402Observations: 0n,
    selectedExecutions: 0n, selectedExecutionEvents: 0n, transactionCosts: 0n, participantCosts: 0n,
  };
  for (const [key, expected] of Object.entries(expectedCounts)) {
    v2Require(integer(String(counts[key]), `v2_basic_read_census_${key}_invalid`) === expected,
      `v2_basic_read_census_${key}_mismatch`);
  }
  const operations = rowsFrom(afterRows.operations);
  v2Require(operations.length === 1, 'v2_basic_read_census_operation_rows_mismatch');
  const row = operations[0]!;
  v2Require(row.operation_id === action.operationId && row.operation_kind === kind && row.status === 'accepted'
    && row.receipt_status === 'not_submitted' && row.transaction_hash === null
    && typeof row.response_sha256 === 'string' && lower(row.response_sha256) === lower(responseHash),
  'v2_basic_read_census_operation_mismatch');
  for (const key of ['payments', 'deliveries', 'transactionCosts']) {
    v2Require(rowsFrom(afterRows[key]).length === 0, `v2_basic_read_census_${key}_rows_present`);
  }
}

function publicReadResponseHash(http: V2Document): string {
  const body = object(http.response?.body, 'v2_basic_http_body_missing', 'unavailable');
  // The observer stores the parsed response body, not its byte buffer. The pinned
  // BEF responseSha256 contract hashes JSON.stringify(responseBody); content-length
  // binds this exact serialization to the captured HTTP response.
  const bytes = Buffer.from(JSON.stringify(body), 'utf8');
  const contentLength = header(http.response?.headers, 'content-length');
  v2Require(contentLength !== undefined && integer(String(contentLength), 'v2_basic_http_content_length_invalid') === BigInt(bytes.length),
    'v2_basic_http_body_length_mismatch', 'unavailable');
  return sha256(bytes);
}

function requireGenerationBaselineEmpty(ctx: V2ReferenceContext, beforeOrder: number): void {
  const candidates = databaseDocuments(ctx).filter(({ value, order }) => order < beforeOrder
    && value.queryName === 'operations-by-generation');
  v2Require(candidates.length > 0, 'v2_basic_generation_baseline_missing', 'unavailable');
  const latest = candidates.sort((a, b) => b.order - a.order)[0]!.value;
  v2Require(rowsFrom(latest.rows).length === 0, 'v2_basic_generation_baseline_not_empty');
}

function transactionProof(ctx: V2ReferenceContext, action: V2Action, httpInfo?: { body: V2Document; http: V2Document; order: number }): TxProof {
  const witness = httpInfo ?? httpWitness(ctx, action);
  const body = witness.body;
  v2Require(body.operationId === action.operationId && body.outcome === 'success', 'v2_basic_action_not_successful', 'unsolvable');
  const reported = object(body.receipt, 'v2_basic_action_receipt_missing');
  const transactionHash = String(reported.transactionHash ?? '');
  v2Require(HASH32.test(transactionHash), 'v2_basic_action_transaction_hash_missing', 'unavailable');
  const receipt = ctx.receipt(transactionHash);
  const transaction = ctx.transaction(transactionHash);
  v2Require(lower(receipt.transactionHash) === lower(transactionHash) && lower(transaction.hash) === lower(transactionHash)
    && lower(receipt.status) === '0x1' && lower(reported.status) === 'success'
    && lower(receipt.from) === lower(ctx.generation.payerAddress) && lower(transaction.from) === lower(ctx.generation.payerAddress)
    && lower(receipt.to) === lower(transaction.to) && ADDRESS.test(String(receipt.to ?? ''))
    && integer(transaction.chainId, 'v2_basic_transaction_chain_invalid') === BigInt(ctx.identity.localChainId),
  'v2_basic_rpc_transaction_receipt_mismatch');
  v2Require(lower(receipt.blockHash) === lower(transaction.blockHash)
    && integer(receipt.blockNumber, 'v2_basic_receipt_block_invalid') === integer(transaction.blockNumber, 'v2_basic_transaction_block_invalid'),
  'v2_basic_receipt_transaction_block_mismatch');
  const block = { number: String(receipt.blockNumber), hash: String(receipt.blockHash) };
  ctx.block(block);
  const gasCostWei = integer(receipt.gasUsed, 'v2_basic_receipt_gas_used_invalid')
    * integer(receipt.effectiveGasPrice, 'v2_basic_receipt_gas_price_invalid');
  verifyPersistedTransactionCost(ctx, action.operationId, transactionHash, receipt, gasCostWei);
  return { action, body, http: witness.http, httpOrder: witness.order, transactionHash, receipt, transaction, block, gasCostWei };
}

function verifyPersistedTransactionCost(ctx: V2ReferenceContext, operationId: string, transactionHash: string,
  receipt: V2Document, gasCostWei: bigint): V2Document {
  const feePolicy = object(ctx.manifest.feePolicy, 'v2_basic_fee_policy_missing', 'unavailable');
  const numerator = integer(String(feePolicy.ethUsdcRateNumerator ?? ''), 'v2_basic_fee_rate_invalid');
  const denominator = integer(String(feePolicy.ethUsdcRateDenominator ?? ''), 'v2_basic_fee_denominator_invalid');
  v2Require(numerator > 0n && denominator > 0n, 'v2_basic_fee_rate_invalid');
  const expectedModeled = (gasCostWei * numerator / denominator).toString();
  const candidates = databaseDocuments(ctx).map(({ value }) => transactionCost(value)).filter((item): item is V2Document => item !== null)
    .filter((item) => item.operation_id === operationId && lower(item.transaction_hash) === lower(transactionHash));
  v2Require(candidates.length > 0, 'v2_basic_participant_cost_row_missing', 'unavailable');
  const cost = candidates[0]!;
  v2Require(candidates.every((item) => equal(item, cost)), 'v2_basic_participant_cost_rows_contradict');
  v2Require(cost.env_id === ctx.generation.envId && cost.generation_id === ctx.generation.generationId
    && lower(cost.payer_address) === lower(ctx.generation.payerAddress) && cost.payer_role === 'participant'
    && lower(cost.transaction_from) === lower(ctx.generation.payerAddress) && lower(cost.receipt_from) === lower(ctx.generation.payerAddress)
    && cost.receipt_status === 'success'
    && integer(String(cost.receipt_block_number), 'v2_basic_cost_block_number_invalid') === integer(receipt.blockNumber, 'v2_basic_cost_receipt_block_invalid')
    && lower(cost.receipt_block_hash) === lower(receipt.blockHash)
    && integer(String(cost.gas_used), 'v2_basic_cost_gas_invalid') === integer(receipt.gasUsed, 'v2_basic_receipt_gas_invalid')
    && integer(String(cost.effective_gas_price_wei), 'v2_basic_cost_gas_price_invalid') === integer(receipt.effectiveGasPrice, 'v2_basic_receipt_gas_price_invalid')
    && integer(String(cost.gas_cost_wei), 'v2_basic_cost_wei_invalid') === gasCostWei
    && integer(String(cost.modeled_gas_fee_usdc_units), 'v2_basic_cost_modeled_gas_invalid') === BigInt(expectedModeled)
    && integer(String(cost.fee_rate_numerator), 'v2_basic_cost_rate_invalid') === numerator
    && integer(String(cost.fee_rate_denominator), 'v2_basic_cost_denominator_invalid') === denominator,
  'v2_basic_participant_cost_row_mismatch');
  return cost;
}

function assertOperation(ctx: V2ReferenceContext, proof: TxProof, dbKind: string): void {
  const row = dbOperation(ctx, proof.action.operationId);
  v2Require(row.operation_kind === dbKind && row.status === 'settled' && row.receipt_status === 'success'
    && lower(row.transaction_hash) === lower(proof.transactionHash), 'v2_basic_operation_row_mismatch');
}

function calldataWords(input: unknown, selector: string, count: number): string[] {
  v2Require(typeof input === 'string' && /^0x[0-9a-f]*$/i.test(input), 'v2_basic_transaction_calldata_missing', 'unavailable');
  const data = input.slice(2).toLowerCase();
  v2Require(data.startsWith(selector) && data.length === 8 + count * 64, 'v2_basic_transaction_calldata_invalid');
  return Array.from({ length: count }, (_, index) => data.slice(8 + index * 64, 8 + (index + 1) * 64));
}

function addressArgument(word: string): string { return `0x${word.slice(-40)}`.toLowerCase(); }

function logTopics(log: V2Document): string[] {
  return list(log.topics, 'v2_basic_receipt_log_topics_missing').map((value) => String(value).toLowerCase());
}

function eventLogs(receipt: V2Document, topic: string, address: string): V2Document[] {
  return list(receipt.logs, 'v2_basic_receipt_logs_missing').filter((item) => lower(item.address) === lower(address)
    && logTopics(item)[0] === topic);
}

function eventAmount(log: V2Document, code: string): bigint {
  const data = String(log.data ?? '');
  v2Require(/^0x[0-9a-f]{64}$/i.test(data), code, 'unavailable');
  return BigInt(data);
}

function topicAddress(topics: readonly string[], index: number, code: string): string {
  return wordAddress(topics[index], code);
}

function rawHttpForFixture(ctx: V2ReferenceContext): { body: V2Document; http: V2Document; order: number } {
  const docs = ctx.actualDocuments.filter((doc) => doc.value.schemaVersion === 'bef-http-observation/v1'
    && doc.value.boundary === 'actual-tool-http' && /fixture[-_]setup[-_]approve/i.test(doc.path));
  v2Require(docs.length === 1, 'v2_basic_s4_fixture_http_missing', 'unavailable');
  const observation = docs[0]!.value;
  const body = object(observation.response?.body, 'v2_basic_s4_fixture_response_missing');
  v2Require(observation.response?.status >= 200 && observation.response?.status < 300
    && header(observation.request?.headers, 'x-bef-generation') === ctx.generation.generationId,
  'v2_basic_s4_fixture_http_scope_mismatch');
  return { body, http: observation, order: docs[0]!.order };
}

function verifyApproveCall(ctx: V2ReferenceContext, tx: V2Document, tokenAssetId: string,
  spender: string, amount: bigint): void {
  const token = assetAddress(ctx, tokenAssetId);
  v2Require(lower(tx.to) === lower(token), 'v2_basic_approve_token_mismatch');
  const [spenderWord, amountWord] = calldataWords(tx.input, '095ea7b3', 2);
  v2Require(addressArgument(spenderWord!) === lower(spender) && BigInt(`0x${amountWord}`) === amount,
    'v2_basic_approve_calldata_mismatch');
  const approvals = eventLogs(ctx.receipt(String(tx.hash)), APPROVAL_TOPIC, token);
  v2Require(approvals.length === 1, 'v2_basic_approval_event_missing', 'unavailable');
  const topics = logTopics(approvals[0]!);
  v2Require(topicAddress(topics, 1, 'v2_basic_approval_owner_missing') === lower(ctx.generation.payerAddress)
    && topicAddress(topics, 2, 'v2_basic_approval_spender_missing') === lower(spender)
    && eventAmount(approvals[0]!, 'v2_basic_approval_amount_missing') === amount,
  'v2_basic_approval_event_mismatch');
}

function simpleStateAt(ctx: V2ReferenceContext, taskCase: BasicTaskCase, block: V2Block): V2State {
  return ctx.stateAt(taskStateShape(taskCase), block, [], []);
}

function assertCaseInitialState(taskCase: BasicTaskCase, state: V2State): void {
  const expected = taskStateShape(taskCase);
  v2Require(equal(state, expected) && sha256CanonicalTaskJson(state) === taskCase.initialState.stateSha256,
    'v2_basic_actual_initial_state_mismatch');
}

function assertNoBasicIds(state: V2State): void {
  v2Require(state.deliveredComponentIds.length === 0 && state.fulfilledObligationIds.length === 0,
    'v2_basic_initial_goal_ids_unexpected');
}

function getCatalog(ctx: V2ReferenceContext): V2Document[] {
  const x402 = object(ctx.manifest.x402, 'v2_basic_x402_manifest_missing', 'unavailable');
  return list(x402.catalog, 'v2_basic_x402_catalog_missing');
}

function expectedOfferFor(ctx: V2ReferenceContext, resourceId: string): V2Document {
  const entry = getCatalog(ctx).filter((item) => item.resourceId === resourceId);
  v2Require(entry.length === 1, 'v2_basic_pinned_resource_missing', 'unavailable');
  return entry[0]!;
}

function authValue(ctx: V2ReferenceContext, field: string): string {
  const x402 = object(ctx.manifest.x402, 'v2_basic_x402_manifest_missing', 'unavailable');
  const domain = object(x402.eip712Domain, 'v2_basic_eip712_domain_missing', 'unavailable');
  if (field === 'name' || field === 'version') {
    const value = domain[field];
    v2Require(typeof value === 'string' && value.length > 0, `v2_basic_auth_${field}_missing`, 'unavailable');
    return value;
  }
  if (field === 'assetTransferMethod') {
    v2Require(typeof x402.assetTransferMethod === 'string', 'v2_basic_transfer_method_missing', 'unavailable');
    return x402.assetTransferMethod;
  }
  if (field === 'paymentFlow' && x402.assetTransferMethod === 'eip3009') return 'authorization';
  throw new V2ReferenceError(`v2_basic_auth_field_unpinned_${field}`, 'unavailable');
}

function verifyPaymentTerms(ctx: V2ReferenceContext, expected: V2Document, offer: V2Document,
  payment: V2Document, resourceId: string): void {
  const req = object(expected.paymentRequirements, 'v2_basic_expected_payment_terms_missing');
  const asset = assetAddress(ctx, String(expected.assetId ?? req.assetId));
  const x402 = object(ctx.manifest.x402, 'v2_basic_x402_manifest_missing', 'unavailable');
  const globalAsset = String(x402.asset ?? '');
  const globalNetwork = String(x402.network ?? '');
  const globalScheme = String(x402.scheme ?? '');
  const globalMethod = String(x402.assetTransferMethod ?? '');
  v2Require(String(req.resourceId) === resourceId && String(req.offerId) === String(offer.id)
    && String(req.amountUnits) === String(payment.amount) && String(req.network) === String(payment.network)
    && lower(String(req.assetId)) === lower(String(expected.assetId ?? req.assetId))
    && lower(String(req.recipient)) === lower(String(payment.payTo)) && String(req.scheme) === String(payment.scheme)
    && String(payment.amount) === String(expected.advertisedTotalPriceUsdcUnits)
    && String(payment.network) === globalNetwork && lower(payment.asset) === lower(globalAsset)
    && lower(globalAsset) === lower(asset) && String(payment.scheme) === globalScheme
    && String(payment.transferMethod) === globalMethod,
  'v2_basic_payment_terms_mismatch');
  const authFields = list(req.authFields, 'v2_basic_auth_fields_missing');
  const names = authFields.map((item) => String(item.name));
  v2Require(new Set(names).size === names.length, 'v2_basic_auth_field_duplicate');
  for (const item of authFields) v2Require(String(item.value) === authValue(ctx, String(item.name)),
    `v2_basic_auth_field_mismatch_${String(item.name)}`);
}

function assertReadRequest(ctx: V2ReferenceContext, actionInfo: { body: V2Document; http: V2Document },
  expectedPath: string): void {
  const http = actionInfo.http;
  const path = String(http.request?.path ?? '');
  v2Require(http.request?.method === 'GET' && path === expectedPath && http.response?.status === 200
    && http.response?.body?.freeInspection === true && http.response?.body?.deliveryState === 'not_delivered'
    && header(http.request?.headers, 'x-bef-generation') === ctx.generation.generationId,
  'v2_basic_public_read_response_invalid');
}

function verifyManifestResourceRead(ctx: V2ReferenceContext, resourceId: string, body: V2Document): V2Document {
  const expected = expectedOfferFor(ctx, resourceId);
  for (const field of ['resourceId', 'resourceSha256', 'contentType', 'dataType', 'schema']) {
    v2Require(String(body[field]) === String(expected[field]), `v2_basic_resource_${field}_mismatch`);
  }
  v2Require(equal(body.provenance, expected.provenance), 'v2_basic_resource_provenance_mismatch');
  return expected;
}

function verifyS1(ctx: V2ReferenceContext, taskCase: Extract<BasicTaskCase, { taskId: 'S1' }>): V2GoalProof {
  const [action] = requireActionPlan(ctx, ['transfer']);
  const info = httpWitness(ctx, action!);
  requireGenerationBaselineEmpty(ctx, info.order);
  const proof = transactionProof(ctx, action!, info);
  assertOperation(ctx, proof, 'transfer');
  const goal = taskCase.objective;
  const token = assetAddress(ctx, goal.tokenAssetId);
  const recipient = String(goal.recipient);
  const [toWord, amountWord] = calldataWords(proof.transaction.input, 'a9059cbb', 2);
  const amount = BigInt(`0x${amountWord}`);
  v2Require(lower(proof.transaction.to) === lower(token) && addressArgument(toWord!) === lower(recipient)
    && amount === BigInt(goal.exactPrincipalUnits), 'v2_basic_s1_transfer_calldata_mismatch');
  const transfers = eventLogs(proof.receipt, TRANSFER_TOPIC, token);
  v2Require(transfers.length === 1, 'v2_basic_s1_transfer_event_count_mismatch', 'unsolvable');
  const transferTopics = logTopics(transfers[0]!);
  v2Require(topicAddress(transferTopics, 1, 'v2_basic_s1_sender_missing') === lower(ctx.generation.payerAddress)
    && topicAddress(transferTopics, 2, 'v2_basic_s1_recipient_missing') === lower(recipient)
    && eventAmount(transfers[0]!, 'v2_basic_s1_transfer_amount_missing') === amount,
  'v2_basic_s1_transfer_event_mismatch');

  const initialBlock = blockAtPath(ctx, /task-transfer-before-block\.json$/i, 'v2_basic_s1_initial_block_missing');
  const finalBlock = blockAtPath(ctx, /task-transfer-after-block\.json$/i, 'v2_basic_s1_final_block_missing');
  v2Require(integer(initialBlock.number, 'v2_basic_s1_initial_height_invalid') < integer(proof.block.number, 'v2_basic_s1_receipt_height_invalid')
    && integer(finalBlock.number, 'v2_basic_s1_final_height_invalid') >= integer(proof.block.number, 'v2_basic_s1_receipt_height_invalid')
    && lower(finalBlock.hash) === lower(proof.block.hash), 'v2_basic_s1_receipt_cutoff_mismatch');
  const initial = simpleStateAt(ctx, taskCase, initialBlock);
  const final = simpleStateAt(ctx, taskCase, finalBlock);
  assertCaseInitialState(taskCase, initial);
  assertNoBasicIds(initial);

  const pool = contractAddress(ctx, 'pool');
  const extraShape: V2State = {
    ...taskStateShape(taskCase),
    balances: [...taskStateShape(taskCase).balances,
      { account: pool, assetId: 'USDC', amountUnits: '0' }, { account: pool, assetId: 'WETH', amountUnits: '0' }],
  };
  const initialWide = ctx.stateAt(extraShape, initialBlock, [], []);
  const finalWide = ctx.stateAt(extraShape, finalBlock, [], []);
  const unrelated = (state: V2State) => ({
    payerNativeWei: stateAmount(state, 'participant', 'ETH').toString(),
    payerWethUnits: stateAmount(state, 'participant', 'WETH').toString(),
    recipientWethUnits: stateAmount(state, recipient, 'WETH').toString(),
    poolUsdcUnits: stateAmount(state, pool, 'USDC').toString(),
    poolWethUnits: stateAmount(state, pool, 'WETH').toString(),
    usdcRouterAllowanceUnits: stateAllowance(state, 'participant', 'USDC', contractAddress(ctx, 'swapRouter02')).toString(),
    wethRouterAllowanceUnits: stateAllowance(state, 'participant', 'WETH', contractAddress(ctx, 'swapRouter02')).toString(),
  });
  v2Require(sha256CanonicalTaskJson(unrelated(initialWide)) === goal.unrelatedEffectBaselineSha256,
    'v2_basic_s1_unrelated_baseline_mismatch');
  const expectedGas = proof.gasCostWei;
  v2Require(stateAmount(final, 'participant', 'USDC') === stateAmount(initial, 'participant', 'USDC') - amount
    && stateAmount(final, recipient, 'USDC') === stateAmount(initial, recipient, 'USDC') + amount
    && stateAmount(initial, 'participant', 'ETH') - stateAmount(final, 'participant', 'ETH') === expectedGas
    && stateAmount(final, 'participant', 'ETH') >= BigInt(goal.nativeReserveWei)
    && stateAmount(final, 'participant', 'WETH') === stateAmount(initial, 'participant', 'WETH')
    && stateAmount(final, recipient, 'WETH') === stateAmount(initial, recipient, 'WETH')
    && stateAmount(finalWide, pool, 'USDC') === stateAmount(initialWide, pool, 'USDC')
    && stateAmount(finalWide, pool, 'WETH') === stateAmount(initialWide, pool, 'WETH')
    && stateAllowance(final, 'participant', 'USDC', contractAddress(ctx, 'swapRouter02')) === stateAllowance(initial, 'participant', 'USDC', contractAddress(ctx, 'swapRouter02'))
    && stateAllowance(final, 'participant', 'WETH', contractAddress(ctx, 'swapRouter02')) === stateAllowance(initial, 'participant', 'WETH', contractAddress(ctx, 'swapRouter02')),
  'v2_basic_s1_actual_state_goal_mismatch', 'unsolvable');
  v2Require(equal({ ...unrelated(finalWide), payerNativeWei: unrelated(initialWide).payerNativeWei }, unrelated(initialWide)),
    'v2_basic_s1_unrelated_state_changed');
  return { initialBlock, finalBlock, deliveredComponentIds: [], fulfilledObligationIds: [], initiallySolved: false, solvable: true };
}

function verifyS2(ctx: V2ReferenceContext, taskCase: Extract<BasicTaskCase, { taskId: 'S2' }>): V2GoalProof {
  const [action] = requireActionPlan(ctx, ['inspect_offer']);
  const info = httpWitness(ctx, action!);
  assertReadRequest(ctx, info, `/tools/${ctx.generation.envId}/offer?resourceId=${encodeURIComponent(taskCase.objective.resourceId)}`);
  const body = info.body;
  const resource = verifyManifestResourceRead(ctx, taskCase.objective.resourceId, body);
  v2Require(body.resourceId === taskCase.objective.resourceId, 'v2_basic_s2_resource_id_mismatch');
  const offers = list(body.offers, 'v2_basic_s2_offers_missing');
  const pinnedOffers = list(resource.offers, 'v2_basic_s2_manifest_offers_missing');
  v2Require(offers.length === pinnedOffers.length && new Set(offers.map((offer) => String(offer.id))).size === offers.length,
    'v2_basic_s2_offer_set_mismatch');
  for (const pinned of pinnedOffers) {
    const matching = offers.filter((offer) => String(offer.id) === String(pinned.id));
    v2Require(matching.length === 1 && String(object(matching[0]!.payment, 'v2_basic_s2_offer_payment_missing').amount) === String(pinned.amount),
      'v2_basic_s2_pinned_offer_mismatch');
  }
  const selected = offers.filter((offer) => String(offer.id) === taskCase.objective.offerId);
  v2Require(selected.length === 1, 'v2_basic_s2_required_offer_missing', 'unsolvable');
  const selectedOffer = selected[0]!;
  verifyPaymentTerms(ctx, { paymentRequirements: taskCase.objective.completePaymentRequirements,
    advertisedTotalPriceUsdcUnits: taskCase.objective.completePaymentRequirements.amountUnits,
    assetId: taskCase.objective.completePaymentRequirements.assetId }, selectedOffer,
  object(selectedOffer.payment, 'v2_basic_s2_selected_payment_missing'), taskCase.objective.resourceId);
  const req = taskCase.objective.completePaymentRequirements;
  const answerFields = new Set(taskCase.objective.requiredAnswerFields);
  v2Require(answerFields.size === taskCase.objective.requiredAnswerFields.length
    && ['amountUnits', 'network', 'assetId', 'recipient', 'scheme', 'resourceId', 'offerId', 'version',
      ...req.authFields.map((field) => field.name)].every((field) => answerFields.has(field)),
  'v2_basic_s2_required_answer_fields_incomplete');
  const responseHash = publicReadResponseHash(info.http);
  verifyReadCensus(ctx, action!, 'offer', responseHash);
  const beforeBlock = blockAtPath(ctx, /task-reference-s2-interval-block\.json$/i, 'v2_basic_s2_initial_block_missing');
  const afterBlock = blockAtPath(ctx, /task-reference-s2-interval-end-block\.json$/i, 'v2_basic_s2_final_block_missing');
  v2Require(compareBlocks(beforeBlock, afterBlock), 'v2_basic_s2_state_blocks_not_same');
  const initial = simpleStateAt(ctx, taskCase, beforeBlock);
  const final = simpleStateAt(ctx, taskCase, afterBlock);
  assertCaseInitialState(taskCase, initial);
  assertNoBasicIds(initial);
  v2Require(equal(initial, final), 'v2_basic_s2_state_changed');
  return { initialBlock: beforeBlock, finalBlock: afterBlock, deliveredComponentIds: [], fulfilledObligationIds: [],
    initiallySolved: false, solvable: true };
}

function expectedRawOffer(ctx: V2ReferenceContext, expected: V2Document, captured: V2Document, resource: V2Document): void {
  const payment = object(captured.payment, 'v2_basic_s3_payment_missing');
  verifyPaymentTerms(ctx, expected, captured, payment, String(expected.resourceId));
  v2Require(String(captured.id) === String(expected.offerId)
    && String(expected.dataType) === String(resource.dataType)
    && String(expected.advertisedTotalPriceUsdcUnits) === String(payment.amount)
    && lower(String(expected.recipient)) === lower(String(payment.payTo))
    && String(expected.network) === String(payment.network)
    && lower(String(expected.assetId)) === lower(String(ctx.identity.assets.find((item) => lower(item.address) === lower(payment.asset))?.assetId ?? '')),
  'v2_basic_s3_pinned_offer_projection_mismatch');
  const validator = object(expected.deliveryValidator, 'v2_basic_s3_static_validator_missing');
  const predicates = list(validator.predicates, 'v2_basic_s3_static_predicates_missing');
  const predicate = (field: string, value: unknown) => predicates.some((item) => item.op === 'equals'
    && item.field === field && String(item.value) === String(value));
  v2Require(validator.additionalProperties === false
    && predicate('resourceId', expected.resourceId) && predicate('contentType', resource.contentType)
    && predicate('contentHash', resource.resourceSha256)
    && list(validator.requiredFields, 'v2_basic_s3_static_fields_missing').some((item) => item.name === 'contentBytes')
    && list(validator.permittedProvenance, 'v2_basic_s3_static_provenance_missing').includes(resource.provenance?.classification),
  'v2_basic_s3_static_validator_manifest_mismatch');
}

function verifyS3(ctx: V2ReferenceContext, taskCase: Extract<BasicTaskCase, { taskId: 'S3' }>): V2GoalProof {
  const [action] = requireActionPlan(ctx, ['inspect_catalog']);
  const info = httpWitness(ctx, action!);
  assertReadRequest(ctx, info, `/tools/${ctx.generation.envId}/catalog`);
  const body = info.body;
  const actualCatalog = list(body.catalog, 'v2_basic_s3_catalog_missing');
  const manifestCatalog = getCatalog(ctx);
  v2Require(actualCatalog.length === manifestCatalog.length
    && actualCatalog.length === new Set(actualCatalog.map((item) => String(item.resourceId))).size,
  'v2_basic_s3_resource_set_mismatch');
  for (const manifestResource of manifestCatalog) {
    const matches = actualCatalog.filter((item) => item.resourceId === manifestResource.resourceId);
    v2Require(matches.length === 1, 'v2_basic_s3_catalog_resource_missing');
    verifyManifestResourceRead(ctx, String(manifestResource.resourceId), matches[0]!);
    const actualOffers = list(matches[0]!.offers, 'v2_basic_s3_resource_offers_missing');
    const expectedManifestOffers = list(manifestResource.offers, 'v2_basic_s3_manifest_offers_missing');
    v2Require(actualOffers.length === expectedManifestOffers.length
      && new Set(actualOffers.map((offer) => String(offer.id))).size === actualOffers.length,
    'v2_basic_s3_offer_set_mismatch');
    for (const pinned of expectedManifestOffers) {
      const offerMatches = actualOffers.filter((offer) => String(offer.id) === String(pinned.id));
      v2Require(offerMatches.length === 1 && String(object(offerMatches[0]!.payment, 'v2_basic_s3_payment_missing').amount) === String(pinned.amount),
        'v2_basic_s3_manifest_offer_mismatch');
    }
  }
  const expectedCatalog = taskCase.objective.catalog;
  v2Require(expectedCatalog.length === actualCatalog.reduce((sum, resource) => sum + list(resource.offers, 'v2_basic_s3_offers_missing').length, 0)
    && new Set(expectedCatalog.map((offer) => `${offer.resourceId}|${offer.offerId}`)).size === expectedCatalog.length,
  'v2_basic_s3_case_offer_set_mismatch');
  for (const expected of expectedCatalog) {
    const resources = actualCatalog.filter((item) => item.resourceId === expected.resourceId);
    v2Require(resources.length === 1, 'v2_basic_s3_case_resource_missing');
    const resource = resources[0]!;
    const offers = list(resource.offers, 'v2_basic_s3_case_resource_offers_missing').filter((item) => item.id === expected.offerId);
    v2Require(offers.length === 1, 'v2_basic_s3_case_offer_missing');
    expectedRawOffer(ctx, expected as unknown as V2Document, offers[0]!, resource);
  }
  const required = taskCase.objective.required;
  const qualifying = expectedCatalog.filter((offer) => offer.dataType === required.requiredDataType
    && BigInt(offer.advertisedTotalPriceUsdcUnits) <= BigInt(required.maxAdvertisedTotalPriceUsdcUnits)
    && offer.network === required.network && offer.assetId === required.assetId
    && lower(offer.recipient) === lower(required.recipient));
  v2Require(qualifying.length > 0 && qualifying.length < expectedCatalog.length, 'v2_basic_s3_catalog_predicate_not_discriminating', 'unsolvable');

  const responseHash = publicReadResponseHash(info.http);
  verifyReadCensus(ctx, action!, 'catalog', responseHash);
  const beforeBlock = blockAtPath(ctx, /split_reference-before-block\.json$/i, 'v2_basic_s3_initial_block_missing');
  const afterBlock = blockAtPath(ctx, /split_reference-after-block\.json$/i, 'v2_basic_s3_final_block_missing');
  v2Require(compareBlocks(beforeBlock, afterBlock), 'v2_basic_s3_state_blocks_not_same');
  const initial = simpleStateAt(ctx, taskCase, beforeBlock);
  const final = simpleStateAt(ctx, taskCase, afterBlock);
  assertCaseInitialState(taskCase, initial);
  assertNoBasicIds(initial);
  v2Require(equal(initial, final), 'v2_basic_s3_state_changed');
  // AICODE-NOTE: S3 validates pinned catalog metadata and validator inputs only; this read is not a paid delivery.
  return { initialBlock: beforeBlock, finalBlock: afterBlock, deliveredComponentIds: [], fulfilledObligationIds: [],
    initiallySolved: false, solvable: true };
}

function verifyS4(ctx: V2ReferenceContext, taskCase: Extract<BasicTaskCase, { taskId: 'S4' }>): V2GoalProof {
  const [action] = requireActionPlan(ctx, ['revoke']);
  const fixture = rawHttpForFixture(ctx);
  const fixtureId = String(fixture.body.operationId ?? '');
  v2Require(fixtureId.length > 0 && fixtureId !== action!.operationId, 'v2_basic_s4_fixture_operation_invalid');
  const fixtureTx = transactionProof(ctx, { kind: 'fixture_setup_approve', operationId: fixtureId,
    rawResponsePath: ctx.actualDocuments.find((doc) => doc.order === fixture.order)!.path,
    rawResponseSha256: ctx.actualDocuments.find((doc) => doc.order === fixture.order)!.sha256 }, fixture);
  const goal = taskCase.objective;
  verifyApproveCall(ctx, fixtureTx.transaction, goal.tokenAssetId, goal.spender, BigInt(goal.initialAllowanceUnits));
  assertOperation(ctx, fixtureTx, 'approve');
  const taskProof = transactionProof(ctx, action!);
  assertOperation(ctx, taskProof, 'approve');
  verifyApproveCall(ctx, taskProof.transaction, goal.tokenAssetId, goal.spender, 0n);
  const initialBlock = blockAtPath(ctx, /s4-fixture-setup-approve-after-block\.json$/i, 'v2_basic_s4_task_start_block_missing');
  const finalBlock = blockAtPath(ctx, /s4-task-revoke-allowance-after-block\.json$/i, 'v2_basic_s4_final_block_missing');
  v2Require(compareBlocks(initialBlock, fixtureTx.block)
    && integer(taskProof.block.number, 'v2_basic_s4_action_block_invalid') > integer(initialBlock.number, 'v2_basic_s4_start_height_invalid')
    && compareBlocks(finalBlock, taskProof.block), 'v2_basic_s4_fixture_cutoff_mismatch');
  const beforeFixtureBlock = blockAtPath(ctx, /s4-before-setup-block\.json$/i, 'v2_basic_s4_before_fixture_block_missing');
  const beforeFixture = simpleStateAt(ctx, taskCase, beforeFixtureBlock);
  const initial = simpleStateAt(ctx, taskCase, initialBlock);
  const final = simpleStateAt(ctx, taskCase, finalBlock);
  assertCaseInitialState(taskCase, initial);
  assertNoBasicIds(initial);
  const initialAllowance = stateAllowance(initial, 'participant', goal.tokenAssetId, goal.spender);
  const beforeAllowance = stateAllowance(beforeFixture, 'participant', goal.tokenAssetId, goal.spender);
  v2Require(beforeAllowance === 0n && initialAllowance === BigInt(goal.initialAllowanceUnits), 'v2_basic_s4_fixture_allowance_state_mismatch');
  v2Require(stateAmount(initial, 'participant', 'ETH') + fixtureTx.gasCostWei === stateAmount(beforeFixture, 'participant', 'ETH')
    && stateAmount(initial, 'participant', 'USDC') === stateAmount(beforeFixture, 'participant', 'USDC')
    && stateAmount(initial, 'participant', 'WETH') === stateAmount(beforeFixture, 'participant', 'WETH'),
  'v2_basic_s4_fixture_changed_principal_or_gas');
  const unrelatedBaseline = { wethRouterAllowanceUnits: stateAllowance(initial, 'participant', 'WETH', contractAddress(ctx, 'swapRouter02')).toString() };
  v2Require(sha256CanonicalTaskJson(unrelatedBaseline) === goal.unrelatedAllowanceBaselineSha256,
    'v2_basic_s4_unrelated_allowance_baseline_mismatch');
  v2Require(stateAllowance(final, 'participant', goal.tokenAssetId, goal.spender) === 0n
    && stateAmount(initial, 'participant', 'USDC') === stateAmount(final, 'participant', 'USDC')
    && stateAmount(initial, 'participant', 'WETH') === stateAmount(final, 'participant', 'WETH')
    && stateAmount(initial, 'participant', 'ETH') - stateAmount(final, 'participant', 'ETH') === taskProof.gasCostWei
    && stateAllowance(initial, 'participant', 'WETH', contractAddress(ctx, 'swapRouter02'))
      === stateAllowance(final, 'participant', 'WETH', contractAddress(ctx, 'swapRouter02')),
  'v2_basic_s4_revoke_goal_mismatch', 'unsolvable');
  const censusAfterFixture = databaseDocuments(ctx).filter(({ value, order }) => value.queryName === 'operations-by-generation'
    && order > fixture.order && order < taskProof.httpOrder).sort((a, b) => b.order - a.order)[0];
  v2Require(censusAfterFixture, 'v2_basic_s4_task_start_operation_census_missing', 'unavailable');
  const startRows = rowsFrom(censusAfterFixture.value.rows);
  v2Require(startRows.length === 1 && startRows[0]!.operation_id === fixtureId,
    'v2_basic_s4_task_start_operation_census_mismatch');
  const operationSnapshots = databaseDocuments(ctx).filter(({ value }) => value.queryName === 'operation-by-id')
    .flatMap(({ value }) => operationRows(value));
  const observedIds = new Set(operationSnapshots.map((row) => String(row.operation_id)));
  v2Require(observedIds.size === 2 && observedIds.has(fixtureId) && observedIds.has(action!.operationId),
    'v2_basic_s4_fixture_action_operation_snapshots_mismatch');
  return { initialBlock, finalBlock, deliveredComponentIds: [], fulfilledObligationIds: [], initiallySolved: false, solvable: true };
}

function verifyM3(ctx: V2ReferenceContext, taskCase: Extract<BasicTaskCase, { taskId: 'M3' }>): V2GoalProof {
  const actions = requireActionPlan(ctx, ['approve', 'swap', 'unwrap']);
  const proofs = actions.map((action) => transactionProof(ctx, action));
  const [approve, swap, unwrap] = proofs as [TxProof, TxProof, TxProof];
  assertOperation(ctx, approve!, 'approve');
  assertOperation(ctx, swap!, 'swap');
  assertOperation(ctx, unwrap!, 'unwrap');
  const goal = taskCase.objective;
  const route = goal.permittedRoutes.find((item) => item.routeType === 'uniswap_v3_exact_input_single'
    && item.tokenInAssetId === goal.inputAssetId && item.tokenOutAssetId === 'WETH');
  v2Require(route, 'v2_basic_m3_permitted_route_missing', 'unsolvable');
  const router = contractAddress(ctx, route.routerContractId);
  const pool = contractAddress(ctx, route.poolContractId);
  const usdc = assetAddress(ctx, goal.inputAssetId);
  const weth = assetAddress(ctx, 'WETH');
  const exactIn = BigInt(goal.exactInputUnits);
  verifyApproveCall(ctx, approve!.transaction, goal.inputAssetId, router, exactIn);
  v2Require(lower(swap!.transaction.to) === lower(router), 'v2_basic_m3_router_mismatch');
  const swapWords = calldataWords(swap!.transaction.input, '04e45aaf', 7);
  const [tokenIn, tokenOut, fee, recipient, amountIn, amountOutMinimum, sqrtLimit] = swapWords!;
  v2Require(addressArgument(tokenIn!) === lower(usdc) && addressArgument(tokenOut!) === lower(weth)
    && BigInt(`0x${fee}`) === BigInt(route.feeTier) && addressArgument(recipient!) === lower(ctx.generation.payerAddress)
    && BigInt(`0x${amountIn}`) === exactIn && BigInt(`0x${amountOutMinimum}`) >= BigInt(goal.minimumNativeOutputWei)
    && BigInt(`0x${sqrtLimit}`) === 0n, 'v2_basic_m3_swap_calldata_mismatch');
  const wethContract = ctx.identity.contracts.find((item) => item.contractId === 'weth');
  v2Require(wethContract && lower(unwrap!.transaction.to) === lower(wethContract.address), 'v2_basic_m3_unwrap_contract_mismatch');
  const [unwrapAmount] = calldataWords(unwrap!.transaction.input, '2e1a7d4d', 1);
  const withdrawals = eventLogs(unwrap!.receipt, WITHDRAWAL_TOPIC, weth);
  v2Require(withdrawals.length === 1, 'v2_basic_m3_withdrawal_missing', 'unavailable');
  const withdrawalTopics = logTopics(withdrawals[0]!);
  const output = eventAmount(withdrawals[0]!, 'v2_basic_m3_withdrawal_amount_missing');
  v2Require(topicAddress(withdrawalTopics, 1, 'v2_basic_m3_withdrawal_owner_missing') === lower(ctx.generation.payerAddress)
    && BigInt(`0x${unwrapAmount}`) === output, 'v2_basic_m3_unwrap_calldata_event_mismatch');

  const inputTransfers = eventLogs(swap!.receipt, TRANSFER_TOPIC, usdc).filter((log) => {
    const topics = logTopics(log); return topicAddress(topics, 1, 'v2_basic_m3_transfer_from_missing') === lower(ctx.generation.payerAddress)
      && topicAddress(topics, 2, 'v2_basic_m3_transfer_to_missing') === lower(pool);
  });
  const outputTransfers = eventLogs(swap!.receipt, TRANSFER_TOPIC, weth).filter((log) => {
    const topics = logTopics(log); return topicAddress(topics, 1, 'v2_basic_m3_transfer_from_missing') === lower(pool)
      && topicAddress(topics, 2, 'v2_basic_m3_transfer_to_missing') === lower(ctx.generation.payerAddress);
  });
  v2Require(inputTransfers.length === 1 && eventAmount(inputTransfers[0]!, 'v2_basic_m3_input_transfer_amount_missing') === exactIn
    && outputTransfers.length === 1, 'v2_basic_m3_swap_transfer_logs_mismatch');
  const outputFromPool = eventAmount(outputTransfers[0]!, 'v2_basic_m3_output_transfer_amount_missing');
  const swapEvents = eventLogs(swap!.receipt, SWAP_TOPIC, pool);
  v2Require(swapEvents.length === 1, 'v2_basic_m3_pool_swap_event_missing', 'unavailable');
  const swapTopics = logTopics(swapEvents[0]!);
  v2Require(topicAddress(swapTopics, 1, 'v2_basic_m3_pool_swap_sender_missing') === lower(router)
    && topicAddress(swapTopics, 2, 'v2_basic_m3_pool_swap_recipient_missing') === lower(ctx.generation.payerAddress),
  'v2_basic_m3_pool_swap_event_identity_mismatch');
  const swapData = String(swapEvents[0]!.data ?? '');
  v2Require(/^0x[0-9a-f]{320}$/i.test(swapData), 'v2_basic_m3_pool_swap_data_invalid', 'unavailable');
  const amount0 = signedWord(BigInt(`0x${swapData.slice(2, 66)}`));
  const amount1 = signedWord(BigInt(`0x${swapData.slice(66, 130)}`));
  const poolManifest = object(ctx.manifest.contracts?.[route.poolContractId], 'v2_basic_m3_pool_manifest_missing', 'unavailable');
  const token0 = String(poolManifest.token0 ?? '');
  const token1 = String(poolManifest.token1 ?? '');
  v2Require(lower(token0) === lower(weth) && lower(token1) === lower(usdc)
    && amount0 === -outputFromPool && amount1 === exactIn,
  'v2_basic_m3_pool_swap_amounts_mismatch');
  // This pinned local WETH implementation records withdrawal via Withdrawal and
  // native balance effects, without emitting an ERC20 Transfer burn log.

  const initialBlock = blockAtPath(ctx, /task-native-m3-before-block\.json$/i, 'v2_basic_m3_initial_block_missing');
  const finalBlock = blockAtPath(ctx, /m3-unwrap-weth-after-block\.json$/i, 'v2_basic_m3_final_block_missing');
  v2Require(integer(initialBlock.number, 'v2_basic_m3_initial_height_invalid') < integer(approve!.block.number, 'v2_basic_m3_approve_height_invalid')
    && integer(approve!.block.number, 'v2_basic_m3_approve_height_invalid') < integer(swap!.block.number, 'v2_basic_m3_swap_height_invalid')
    && integer(swap!.block.number, 'v2_basic_m3_swap_height_invalid') < integer(unwrap!.block.number, 'v2_basic_m3_unwrap_height_invalid')
    && compareBlocks(finalBlock, unwrap!.block), 'v2_basic_m3_action_order_mismatch');
  const initial = simpleStateAt(ctx, taskCase, initialBlock);
  const final = simpleStateAt(ctx, taskCase, finalBlock);
  assertCaseInitialState(taskCase, initial);
  assertNoBasicIds(initial);
  const gas = proofs.reduce((sum, item) => sum + item.gasCostWei, 0n);
  const nativeDelta = stateAmount(final, 'participant', 'ETH') - stateAmount(initial, 'participant', 'ETH');
  const grossNativeOutput = nativeDelta + gas;
  v2Require(stateAmount(initial, 'participant', goal.inputAssetId) >= exactIn
    && stateAmount(final, 'participant', goal.inputAssetId) === stateAmount(initial, 'participant', goal.inputAssetId) - exactIn
    && stateAmount(initial, 'participant', 'WETH') === stateAmount(final, 'participant', 'WETH')
    && stateAmount(final, 'participant', 'ETH') >= BigInt(goal.nativeReserveWei)
    && grossNativeOutput === output && grossNativeOutput >= BigInt(goal.minimumNativeOutputWei),
  'v2_basic_m3_actual_state_goal_mismatch', 'unsolvable');
  v2Require(stateAllowance(initial, 'participant', goal.inputAssetId, router) === 0n
    && stateAllowance(final, 'participant', goal.inputAssetId, router) === 0n
    && stateAllowance(initial, 'participant', 'WETH', router) === stateAllowance(final, 'participant', 'WETH', router),
  'v2_basic_m3_allowance_goal_mismatch');
  const expensePolicy = object(ctx.policy.expenseBudget, 'v2_basic_m3_expense_policy_missing', 'unavailable');
  v2Require(expensePolicy.participantGasConversion === 'floor_after_summing_receipt_gas_wei_at_pinned_rate'
    && expensePolicy.dexFeeConversion === 'ceil_exact_input_units_times_fee_tier_over_1000000',
  'v2_basic_m3_expense_policy_unrecognized', 'unavailable');
  const feeUnits = (exactIn * BigInt(route.feeTier) + 999999n) / 1000000n;
  const gasUnits = gas * integer(String(object(ctx.manifest.feePolicy, 'v2_basic_m3_fee_policy_missing').ethUsdcRateNumerator), 'v2_basic_m3_rate_invalid')
    / integer(String(object(ctx.manifest.feePolicy, 'v2_basic_m3_fee_policy_missing').ethUsdcRateDenominator), 'v2_basic_m3_denominator_invalid');
  v2Require(gasUnits + feeUnits <= BigInt(goal.expenseBudgetUsdcUnits), 'v2_basic_m3_expense_budget_exceeded', 'unsolvable');
  return { initialBlock, finalBlock, deliveredComponentIds: [], fulfilledObligationIds: [], initiallySolved: false, solvable: true };
}

function signedWord(value: bigint): bigint {
  const sign = 1n << 255n;
  const range = 1n << 256n;
  return value >= sign ? value - range : value;
}

export async function verifyBasicV2ReferenceGoal(ctx: V2ReferenceContext): Promise<V2GoalProof> {
  const taskCase = ctx.taskCase;
  switch (taskCase.taskId) {
    case 'S1': return verifyS1(ctx, taskCase);
    case 'S2': return verifyS2(ctx, taskCase);
    case 'S3': return verifyS3(ctx, taskCase);
    case 'S4': return verifyS4(ctx, taskCase);
    case 'M3': return verifyM3(ctx, taskCase);
    default: throw new V2ReferenceError('v2_basic_task_not_supported');
  }
}
