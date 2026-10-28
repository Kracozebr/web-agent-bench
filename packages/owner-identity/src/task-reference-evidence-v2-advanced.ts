import { createHash } from 'node:crypto';
import { canonicalTaskJson } from './task-release.js';
import { V2ReferenceError, v2Require, type V2Action, type V2Block, type V2Document,
  type V2GoalProof, type V2RawDocument, type V2ReferenceContext, type V2State } from './task-reference-evidence-v2-types.js';

const ADDRESS = /^0x[0-9a-f]{40}$/i;
const HASH = /^0x[0-9a-f]{64}$/i;
const UINT = /^(?:0|[1-9][0-9]*)$/;
const TRANSFER_TOPIC = '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';
const APPROVAL_TOPIC = '0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925';
const V3_SWAP_TOPIC = '0xc42079f94a6350d7e6235f29174924f928cc2ac818eb64fed8004e115fbcca67';
const DEPOSIT_TOPIC = '0xe1fffcc4923d04b559f4d29a8bfc6cda04eb5b0d3c460751c2402c5c5cc9109c';
const WITHDRAWAL_TOPIC = '0x7fcf532c15f0a6db0bd6d0e038bea71d30d808c7d98cb3bf7268a95bf5081b65';
const ACTION_PLANS: Record<string, readonly string[]> = {
  M1: ['inspect_offer', 'pay', 'retrieve'],
  M2: ['inspect_catalog', 'pay', 'retrieve'],
  H1: ['inspect_catalog', 'pay', 'retrieve', 'pay', 'retrieve', 'pay', 'retrieve'],
  H2: ['transfer', 'transfer', 'transfer', 'transfer', 'transfer', 'transfer'],
  M4: ['wrap', 'approve', 'swap'],
  H3: ['inspect_offer', 'pay', 'retrieve', 'wrap', 'approve', 'swap'],
  U1: ['inspect_catalog', 'pay', 'retrieve', 'pay', 'retrieve', 'transfer', 'transfer', 'approve', 'swap', 'unwrap'],
};

type PaymentResult = { resourceId: string; componentId: string; transactionHash: string; block: V2Block; amount: bigint };
type NativeResult = { kind: string; operationId: string; txHash: string; block: V2Block; receipt: V2Document; transaction: V2Document; selected: V2Document };
type TradeResult = NativeResult & { routeId: string; inputAmount: bigint; outputAmount: bigint; feeTier: number; outputAssetId: string };

function isObject(value: unknown): value is V2Document {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value));
}
function obj(value: unknown, code: string, disposition: V2ReferenceError['disposition'] = 'unavailable'): V2Document {
  v2Require(isObject(value), code, disposition); return value;
}
function arr(value: unknown, code: string, disposition: V2ReferenceError['disposition'] = 'unavailable'): any[] {
  v2Require(Array.isArray(value), code, disposition); return value;
}
function str(value: unknown, code: string, disposition: V2ReferenceError['disposition'] = 'unavailable'): string {
  v2Require(typeof value === 'string' && value.length > 0, code, disposition); return value;
}
function uint(value: unknown, code: string, disposition: V2ReferenceError['disposition'] = 'unavailable'): bigint {
  v2Require(typeof value === 'string' && (UINT.test(value) || /^0x(?:0|[1-9a-f][0-9a-f]*)$/i.test(value)), code, disposition);
  return BigInt(value);
}
function lower(value: unknown): string { return String(value ?? '').toLowerCase(); }
function hashKey(value: unknown): string { return lower(value).replace(/^0x/, ''); }
function same(left: unknown, right: unknown): boolean { return canonicalTaskJson(left) === canonicalTaskJson(right); }
function hashBytes(bytes: Uint8Array): string { return createHash('sha256').update(bytes).digest('hex'); }
function requireEqual(left: unknown, right: unknown, code: string): void { v2Require(same(left, right), code); }
function header(headers: unknown, name: string): unknown {
  if (!isObject(headers)) return undefined;
  return Object.entries(headers).find(([key]) => key.toLowerCase() === name.toLowerCase())?.[1];
}
function word(input: string, index: number, code: string): string {
  const body = input.replace(/^0x/i, '');
  const start = 8 + index * 64;
  v2Require(/^[0-9a-f]+$/i.test(body) && body.length >= start + 64, code, 'unavailable');
  return body.slice(start, start + 64).toLowerCase();
}
function wordAddress(input: string, index: number, code: string): string {
  return `0x${word(input, index, code).slice(-40)}`;
}
function wordUint(input: string, index: number, code: string): bigint { return BigInt(`0x${word(input, index, code)}`); }
function dataField(value: unknown, path: string, code: string): unknown {
  let current: unknown = value;
  for (const part of path.split('.')) {
    v2Require(isObject(current) && Object.prototype.hasOwnProperty.call(current, part), code, 'unavailable');
    current = current[part];
  }
  return current;
}
function blockLocator(value: unknown, code: string): V2Block {
  const item = obj(value, code);
  const number = uint(item.number ?? item.blockNumber, code).toString();
  const hash = str(item.hash ?? item.blockHash, code);
  v2Require(HASH.test(hash), code);
  return { number, hash: hash.toLowerCase() };
}
function assetAddress(ctx: V2ReferenceContext, assetId: string, code: string): string {
  const asset = ctx.identity.assets.find((item) => item.assetId === assetId);
  v2Require(asset && asset.kind === 'erc20' && typeof asset.address === 'string' && ADDRESS.test(asset.address), code, 'unavailable');
  return asset.address;
}
function resolvedAccount(requested: string, payerAddress?: string): { participantAlias: boolean; exactAccount: string } {
  return { participantAlias: requested === 'participant'
    || (payerAddress !== undefined && lower(requested) === lower(payerAddress)), exactAccount: requested };
}
function stateAccountMatches(rowAccount: string, requested: string, payerAddress?: string): boolean {
  const target = resolvedAccount(requested, payerAddress);
  return rowAccount === 'participant' ? target.participantAlias : lower(rowAccount) === lower(target.exactAccount);
}
export function advancedStateAccountMatches(rowAccount: string, requested: string, payerAddress?: string): boolean {
  return stateAccountMatches(rowAccount, requested, payerAddress);
}
function nativeBalance(state: V2State, account: string, code: string, payerAddress?: string): bigint {
  const rows = state.balances.filter((item) => stateAccountMatches(item.account, account, payerAddress) && item.assetId === 'ETH');
  v2Require(rows.length === 1, code, 'unavailable'); return uint(rows[0]!.amountUnits, code);
}
function stateBalance(state: V2State, account: string, assetId: string, code: string, payerAddress?: string): bigint {
  const rows = state.balances.filter((item) => stateAccountMatches(item.account, account, payerAddress) && item.assetId === assetId);
  v2Require(rows.length === 1, code, 'unavailable'); return uint(rows[0]!.amountUnits, code);
}
function stateAllowance(state: V2State, owner: string, assetId: string, spender: string, code: string,
  payerAddress?: string): bigint {
  const rows = state.allowances.filter((item) => stateAccountMatches(item.owner, owner, payerAddress)
    && item.tokenAssetId === assetId && lower(item.spender) === lower(spender));
  v2Require(rows.length === 1, code, 'unavailable'); return uint(rows[0]!.amountUnits, code);
}

function profile(ctx: V2ReferenceContext): V2Document {
  const reference = obj(ctx.probe.difficultyProfile, 'v2_advanced_profile_reference_missing');
  const path = str(reference.evidencePath, 'v2_advanced_profile_path_missing');
  const source = ctx.raw(path);
  v2Require(source.schemaVersion === 'bts-task-case-input-profile/v2' && source.profileId === reference.profileId
    && reference.sourceSha256 === reference.evidenceSha256, 'v2_advanced_profile_binding_mismatch');
  return source;
}
function profileTask(ctx: V2ReferenceContext): V2Document { return obj(profile(ctx).tasks?.[ctx.taskCase.taskId], 'v2_advanced_profile_task_missing'); }

function actionBody(ctx: V2ReferenceContext, action: V2Action): V2Document {
  return obj(ctx.action(action), 'v2_advanced_action_body_missing');
}
function requireHttpAction(ctx: V2ReferenceContext, action: V2Action, pathSuffix: string): V2Document {
  const body = actionBody(ctx, action);
  const matches = ctx.http(action).filter((observation) => observation.response?.status >= 200 && observation.response?.status < 300
    && observation.request?.method === 'POST' && observation.request?.path.endsWith(pathSuffix)
    && lower(header(observation.request?.headers, 'X-BEF-Generation')) === lower(ctx.generation.generationId)
    && same(observation.response?.body, body));
  v2Require(matches.length === 1, 'v2_advanced_action_http_binding_missing', 'unavailable');
  return body;
}
function requireReadHttp(ctx: V2ReferenceContext, action: V2Action, route: string, body: V2Document): void {
  const matches = ctx.http(action).filter((observation) => observation.response?.status === 200
    && observation.request?.method === 'GET' && observation.request?.path.includes(route)
    && lower(header(observation.request?.headers, 'X-BEF-Generation')) === lower(ctx.generation.generationId)
    && same(observation.response?.body, body));
  v2Require(matches.length === 1, 'v2_advanced_public_read_http_binding_missing', 'unavailable');
}
function selectedOffer(read: V2Document, resourceId: string, offerId: string, catalog: boolean): V2Document {
  if (catalog) {
    const resources = arr(read.catalog, 'v2_advanced_catalog_missing');
    const resource = resources.find((item) => item.resourceId === resourceId);
    v2Require(resource, 'v2_advanced_catalog_resource_missing', 'unavailable');
    const offer = arr(resource.offers, 'v2_advanced_catalog_offers_missing').find((item) => item.id === offerId);
    v2Require(offer, 'v2_advanced_catalog_offer_missing', 'unavailable');
    return { resource, offer };
  }
  v2Require(read.resourceId === resourceId, 'v2_advanced_offer_resource_mismatch');
  const offer = arr(read.offers, 'v2_advanced_public_offers_missing').find((item) => item.id === offerId);
  v2Require(offer, 'v2_advanced_public_offer_missing', 'unavailable');
  return { resource: read, offer };
}
function publicTermsMatch(ctx: V2ReferenceContext, terms: V2Document, requirements: V2Document | undefined,
  resourceId: string, offerId: string, amountExpected?: string): bigint {
  const amount = uint(terms.amount, 'v2_advanced_offer_amount_invalid');
  const pinnedPayTo = ctx.manifest.x402?.facilitatorAddress ?? ctx.manifest.x402?.offers?.[0]?.payTo;
  v2Require(terms.scheme === 'exact' && terms.network === ctx.manifest.x402?.network
    && lower(terms.asset) === lower(ctx.manifest.x402?.asset)
    && ADDRESS.test(String(terms.payTo)) && (pinnedPayTo === undefined || lower(terms.payTo) === lower(pinnedPayTo))
    && terms.transferMethod === ctx.manifest.x402?.assetTransferMethod, 'v2_advanced_offer_terms_not_pinned');
  if (amountExpected !== undefined) v2Require(amount === uint(amountExpected, 'v2_advanced_expected_amount_invalid'), 'v2_advanced_offer_amount_mismatch');
  if (requirements) {
    const requiredAsset = assetAddress(ctx, String(requirements.assetId), 'v2_advanced_requirement_asset_missing');
    v2Require(requirements.resourceId === resourceId && requirements.offerId === offerId
      && requirements.scheme === terms.scheme && requirements.network === terms.network
      && lower(requiredAsset) === lower(terms.asset) && lower(requirements.recipient) === lower(terms.payTo)
      && uint(requirements.amountUnits, 'v2_advanced_requirement_amount_invalid') === amount,
    'v2_advanced_case_payment_requirements_mismatch');
    const expectedAuth = new Map<string, string>([
      ['assetTransferMethod', String(ctx.manifest.x402.assetTransferMethod)],
      ['paymentFlow', 'authorization'],
      ['name', String(ctx.manifest.x402.eip712Domain?.name ?? '')],
      ['version', String(ctx.manifest.x402.eip712Domain?.version ?? '')],
    ]);
    for (const field of arr(requirements.authFields ?? [], 'v2_advanced_auth_fields_missing')) {
      const name = str(field.name, 'v2_advanced_auth_field_name_missing');
      const expected = expectedAuth.get(name);
      v2Require(expected !== undefined && String(field.value) === expected, 'v2_advanced_auth_field_unverifiable', 'unavailable');
    }
  }
  return amount;
}
function responseHashFromBytes(encoded: string, expected: string, code: string): { bytes: Buffer; parsed: V2Document } {
  v2Require(typeof encoded === 'string' && encoded.length > 0 && /^[A-Za-z0-9+/]*={0,2}$/.test(encoded), code, 'unavailable');
  const bytes = Buffer.from(encoded, 'base64');
  v2Require(bytes.length > 0 && bytes.toString('base64') === encoded && hashBytes(bytes) === expected, code);
  return { bytes, parsed: obj(JSON.parse(bytes.toString('utf8')), code) };
}
function validateField(value: unknown, type: string, code: string): boolean {
  switch (type) {
    case 'string': return typeof value === 'string';
    case 'decimal': return typeof value === 'string' && UINT.test(value);
    case 'boolean': return typeof value === 'boolean';
    case 'address': return typeof value === 'string' && ADDRESS.test(value);
    case 'sha256': return typeof value === 'string' && /^[0-9a-f]{64}$/i.test(value);
    default: v2Require(false, code); return false;
  }
}
function validateDeliveryValidator(ctx: V2ReferenceContext, validatorValue: unknown, envelope: V2Document,
  delivered: V2Document, resource: V2Document): void {
  const validator = obj(validatorValue, 'v2_advanced_delivery_validator_missing');
  const standardEnvelope = validator.validatorVersion === 'bef-delivery-envelope-validator/v1'
    && validator.payloadSchemaVersion === 'bef-delivery-envelope/v1';
  const routeEnvelope = ctx.taskCase.taskId === 'H3' && validator.validatorVersion === 'bef-route-delivery-validator/v1'
    && validator.payloadSchemaVersion === 'bef-route-delivery/v1';
  v2Require((standardEnvelope || routeEnvelope) && validator.additionalProperties === false,
    'v2_advanced_delivery_validator_version_invalid');
  const fields = arr(validator.requiredFields, 'v2_advanced_delivery_fields_missing');
  const expectedFieldSet = fields.map((field) => str(obj(field, 'v2_advanced_field_invalid').name, 'v2_advanced_field_name_missing'));
  const envelopeFieldSet = expectedFieldSet.filter((name) => Object.prototype.hasOwnProperty.call(envelope, name));
  v2Require(new Set(expectedFieldSet).size === fields.length && envelopeFieldSet.length === Object.keys(envelope).length
    && Object.keys(envelope).every((key) => envelopeFieldSet.includes(key))
    && (routeEnvelope ? expectedFieldSet.length === envelopeFieldSet.length + 1 && expectedFieldSet.includes('routeCode')
      : expectedFieldSet.length === envelopeFieldSet.length), 'v2_advanced_delivery_schema_fields_mismatch');
  for (const fieldValue of fields) {
    const field = obj(fieldValue, 'v2_advanced_field_invalid');
    const name = String(field.name);
    const fieldValueObserved = Object.prototype.hasOwnProperty.call(envelope, name) ? envelope[name]
      : dataField(delivered, `content.${name}`, 'v2_advanced_payload_field_missing');
    v2Require(validateField(fieldValueObserved, String(field.type), 'v2_advanced_delivery_field_type_invalid'),
      'v2_advanced_delivery_field_type_invalid');
    if (Array.isArray(field.enumValues)) v2Require(field.enumValues.includes(fieldValueObserved), 'v2_advanced_delivery_field_enum_invalid');
  }
  for (const predicateValue of arr(validator.predicates, 'v2_advanced_delivery_predicates_missing')) {
    const predicate = obj(predicateValue, 'v2_advanced_delivery_predicate_invalid');
    const value = dataField(envelope, String(predicate.field), 'v2_advanced_delivery_predicate_field_missing');
    if (predicate.op === 'equals') v2Require(value === predicate.value, 'v2_advanced_delivery_predicate_failed');
    else if (predicate.op === 'one_of') v2Require(arr(predicate.values, 'v2_advanced_delivery_one_of_invalid').includes(value), 'v2_advanced_delivery_predicate_failed');
    else if (predicate.op === 'decimal_gte') v2Require(uint(value, 'v2_advanced_delivery_decimal_invalid') >= uint(predicate.value, 'v2_advanced_delivery_decimal_invalid'), 'v2_advanced_delivery_predicate_failed');
    else if (predicate.op === 'decimal_lte') v2Require(uint(value, 'v2_advanced_delivery_decimal_invalid') <= uint(predicate.value, 'v2_advanced_delivery_decimal_invalid'), 'v2_advanced_delivery_predicate_failed');
    else v2Require(false, 'v2_advanced_delivery_predicate_operator_invalid');
  }
  const payloadProvenance = isObject(delivered.provenance) ? delivered.provenance : undefined;
  v2Require(payloadProvenance !== undefined || (!Object.prototype.hasOwnProperty.call(delivered, 'provenance')
    && delivered.schema === 'web-agent-bench/resource/v1'), 'v2_advanced_resource_provenance_missing');
  const provenance = payloadProvenance ?? obj(resource.provenance, 'v2_advanced_pinned_resource_provenance_missing');
  const allowed = arr(validator.permittedProvenance, 'v2_advanced_provenance_policy_missing');
  const profileSources = arr(ctx.policy.permittedProvenanceIds, 'v2_advanced_profile_provenance_missing');
  v2Require(typeof provenance.classification === 'string' && allowed.includes(provenance.classification)
    && profileSources.includes(provenance.classification) && resource.provenance?.classification === provenance.classification,
  'v2_advanced_resource_provenance_not_permitted');
}

function manifestResource(ctx: V2ReferenceContext, resourceId: string): V2Document {
  const catalog = arr(ctx.manifest.x402?.catalog, 'v2_advanced_manifest_catalog_missing');
  const item = catalog.find((value) => value.resourceId === resourceId);
  v2Require(item, 'v2_advanced_manifest_resource_missing', 'unavailable'); return obj(item, 'v2_advanced_manifest_resource_invalid');
}
function validateReadResource(ctx: V2ReferenceContext, publicResource: V2Document, resourceId: string): V2Document {
  const pinned = manifestResource(ctx, resourceId);
  v2Require(publicResource.resourceId === resourceId && publicResource.resourceSha256 === pinned.resourceSha256
    && publicResource.contentType === pinned.contentType && publicResource.schema === pinned.schema
    && publicResource.dataType === pinned.dataType && same(publicResource.provenance, pinned.provenance),
  'v2_advanced_public_resource_not_manifest_pinned');
  return pinned;
}
function databaseRows(ctx: V2ReferenceContext, queryName: string, operationId?: string): V2Document[] {
  const output: V2Document[] = [];
  for (const observation of ctx.database()) {
    if (observation.queryName !== queryName) continue;
    const rawRows = observation.rows;
    const rows = Array.isArray(rawRows) ? rawRows : isObject(rawRows) ? [rawRows] : [];
    for (const value of rows) {
      if (!isObject(value)) continue;
      const rowOperationId = value.operation_id ?? value.operationId;
      if (operationId === undefined || rowOperationId === operationId) output.push(value);
    }
  }
  return output;
}
function requireSingleById(rows: readonly V2Document[], idKey: string, code: string): V2Document {
  const distinct = new Map<string, V2Document>();
  for (const row of rows) {
    const id = str(row[idKey], code);
    const old = distinct.get(id);
    if (old) {
      // Snapshots may repeat across independent reads; immutable fields must remain identical.
      for (const key of Object.keys(row)) if (key !== 'observed_at' && key !== 'delivered_at'
        && old[key] !== undefined && row[key] !== undefined) {
        v2Require(same(old[key], row[key]), code);
      }
    } else distinct.set(id, row);
  }
  v2Require(distinct.size === 1, code, 'unavailable'); return [...distinct.values()][0]!;
}
function persistedSelectionMatches(kind: string, persisted: unknown, selected: V2Document): boolean {
  if (!isObject(persisted)) return false;
  let expected: V2Document | undefined;
  if (kind === 'wrap') expected = { kind, gasLimit: selected.gasLimit, amountWei: selected.amountWei };
  else if (kind === 'approve') expected = { kind, gasLimit: selected.gasLimit, amountUnits: selected.amountUnits,
    tokenAssetId: selected.tokenAssetId };
  else if (kind === 'unwrap') expected = { kind, gasLimit: selected.gasLimit, amountWei: selected.amountWei };
  else if (kind === 'swap') expected = { kind, feeTier: selected.fee, gasLimit: selected.gasLimit,
    recipient: selected.recipient, inputAssetId: selected.inputAssetId, amountInUnits: selected.amountInUnits,
    outputAssetId: selected.outputAssetId, amountOutMinimumUnits: selected.amountOutMinimumUnits };
  if (!expected) return false;
  return same(persisted, expected);
}
function logTransfer(ctx: V2ReferenceContext, receipt: V2Document, token: string, from: string, to: string,
  amount: bigint, code: string): void {
  const matches = arr(receipt.logs, `${code}_logs_missing`).filter((log) => lower(log.address) === lower(token)
    && lower(log.topics?.[0]) === TRANSFER_TOPIC && lower(`0x${String(log.topics?.[1] ?? '').slice(-40)}`) === lower(from)
    && lower(`0x${String(log.topics?.[2] ?? '').slice(-40)}`) === lower(to)
    && /^0x[0-9a-f]{64}$/i.test(String(log.data)) && BigInt(log.data) === amount);
  v2Require(matches.length === 1, code);
}
function readPaymentChallenge(ctx: V2ReferenceContext, action: V2Action, resourceId: string, offerId: string,
  readHandle: V2Document, acceptedTerms: V2Document): V2Document {
  const observations = [...ctx.http(action)].sort((a, b) => {
    const left = Number(a.request?.monotonicStartMs ?? 0), right = Number(b.request?.monotonicStartMs ?? 0);
    return left - right;
  }).filter((doc) => doc.request?.method === 'POST' && doc.request?.path.endsWith('/pay')
    && lower(header(doc.request?.headers, 'X-BEF-Generation')) === lower(ctx.generation.generationId));
  const challenge = observations.find((doc) => doc.response?.status === 402);
  const success = observations.find((doc) => doc.response?.status === 200 && doc.response?.body?.operationId === action.operationId);
  v2Require(challenge && success && challenge !== success, 'v2_advanced_pay_challenge_missing', 'unavailable');
  const challengeBody = obj(challenge.request?.body, 'v2_advanced_pay_request_missing');
  const successBody = obj(success.request?.body, 'v2_advanced_retry_request_missing');
  const bodyReadHandle = obj(challengeBody.readHandle, 'v2_advanced_pay_read_handle_missing');
  const accepted = obj(challengeBody.acceptedTerms, 'v2_advanced_pay_accepted_terms_missing');
  const acceptedKeys = Object.keys(accepted).sort();
  const expectedKeys = ['amount', 'asset', 'network', 'payTo', 'scheme', 'transferMethod'].sort();
  v2Require(challengeBody.resourceId === resourceId && challengeBody.offerId === offerId
    && same(bodyReadHandle, readHandle) && same(acceptedKeys, expectedKeys)
    && accepted.scheme === acceptedTerms.scheme && accepted.network === acceptedTerms.network
    && lower(accepted.asset) === lower(acceptedTerms.asset) && String(accepted.amount) === String(acceptedTerms.amount)
    && lower(accepted.payTo) === lower(acceptedTerms.payTo)
    && accepted.transferMethod === acceptedTerms.transferMethod, 'v2_advanced_pay_challenge_terms_mismatch');
  requireEqual(successBody, challengeBody, 'v2_advanced_signed_retry_changed_terms');
  const challengeKey = header(challenge.request?.headers, 'Idempotency-Key');
  const retryKey = header(success.request?.headers, 'Idempotency-Key');
  v2Require(typeof challengeKey === 'string' && challengeKey.length > 0 && challengeKey === retryKey
    && success.request?.headers?.['PAYMENT-SIGNATURE-present'] === true
    && same(success.response?.body, actionBody(ctx, action)), 'v2_advanced_pay_retry_binding_invalid');
  return success.response.body as V2Document;
}
function validatePaidDelivery(ctx: V2ReferenceContext, readAction: V2Action, payAction: V2Action,
  retrieveAction: V2Action, component: V2Document, options: { catalog: boolean; expectedOfferId?: string; expectedAmount?: string;
    requirements?: V2Document; permittedSources?: readonly string[] }): PaymentResult {
  const read = actionBody(ctx, readAction);
  requireReadHttp(ctx, readAction, options.catalog ? '/catalog' : '/offer?', read);
  const resourceId = str(component.resourceId, 'v2_advanced_component_resource_missing');
  const pinned = manifestResource(ctx, resourceId);
  const selected = options.expectedOfferId
    ? selectedOffer(read, resourceId, options.expectedOfferId, options.catalog)
    : (() => { throw new V2ReferenceError('v2_advanced_offer_selection_missing', 'unavailable'); })();
  const publicResource = obj(selected.resource, 'v2_advanced_public_resource_missing');
  validateReadResource(ctx, publicResource, resourceId);
  const readHandle = obj(read.readHandle, 'v2_advanced_read_handle_missing');
  v2Require(readHandle.operationId === readAction.operationId && readHandle.kind === (options.catalog ? 'catalog' : 'offer'),
    'v2_advanced_read_handle_invalid');
  const advertised = obj(selected.offer, 'v2_advanced_selected_offer_missing');
  const terms = obj(advertised.payment, 'v2_advanced_public_payment_terms_missing');
  const amount = publicTermsMatch(ctx, terms, options.requirements, resourceId, options.expectedOfferId,
    options.expectedAmount ?? (options.requirements ? String(options.requirements.amountUnits) : undefined));
  const payBody = readPaymentChallenge(ctx, payAction, resourceId, options.expectedOfferId, readHandle, terms);
  const pay = obj(payBody.payment, 'v2_advanced_payment_body_missing');
  v2Require(payBody.operationId === payAction.operationId && payBody.status === 'payment_confirmed'
    && payBody.deliveryHandle === payAction.operationId && pay.receiptStatus === 'success'
    && String(pay.amount) === amount.toString() && lower(pay.asset) === lower(terms.asset)
    && pay.network === terms.network && lower(pay.payTo) === lower(terms.payTo)
    && HASH.test(String(pay.transactionHash)), 'v2_advanced_payment_response_invalid');
  const retrieve = actionBody(ctx, retrieveAction);
  const retrievals = ctx.http(retrieveAction).filter((doc) => doc.request?.method === 'GET'
    && doc.request?.path.includes(`/retrieve?operationId=${encodeURIComponent(payAction.operationId)}`)
    && doc.response?.status === 200 && lower(header(doc.request?.headers, 'X-BEF-Generation')) === lower(ctx.generation.generationId)
    && same(doc.response?.body, retrieve));
  v2Require(retrieveAction.operationId === payAction.operationId && retrievals.length === 1
    && retrieve.operationId === payAction.operationId && retrieve.resourceId === resourceId,
  'v2_advanced_retrieve_operation_binding_invalid');
  v2Require(retrieve.contentType === pinned.contentType && retrieve.contentHash === pinned.resourceSha256,
    'v2_advanced_delivery_content_pin_mismatch');
  const decoded = responseHashFromBytes(String(retrieve.contentBytes), String(retrieve.contentHash), 'v2_advanced_delivery_bytes_invalid');
  const delivered = decoded.parsed;
  const payloadProvenanceMatches = Object.prototype.hasOwnProperty.call(delivered, 'provenance')
    ? same(delivered.provenance, pinned.provenance)
    : delivered.schema === 'web-agent-bench/resource/v1' && !Object.prototype.hasOwnProperty.call(delivered, 'provenance');
  v2Require(delivered.resourceId === resourceId && delivered.schema === pinned.schema && payloadProvenanceMatches
    && isObject(delivered.content) && same(delivered, retrieve.content), 'v2_advanced_delivery_payload_binding_mismatch');
  const envelope = { resourceId: retrieve.resourceId, contentType: retrieve.contentType,
    contentHash: retrieve.contentHash, contentBytes: retrieve.contentBytes };
  validateDeliveryValidator(ctx, component.validator, envelope, delivered, pinned);
  if (options.permittedSources) {
    const sources = arr(component.sourceIds, 'v2_advanced_component_sources_missing');
    const permitted = options.permittedSources;
    const provenance = isObject(delivered.provenance) ? delivered.provenance : pinned.provenance;
    v2Require(sources.length > 0 && sources.every((source) => permitted.includes(source))
      && permitted.includes(String(provenance?.classification)), 'v2_advanced_component_source_not_permitted');
  }
  const txHash = String(pay.transactionHash).toLowerCase();
  const receipt = obj(ctx.receipt(txHash), 'v2_advanced_payment_receipt_missing');
  v2Require(lower(receipt.transactionHash) === txHash && lower(receipt.status) === '0x1'
    && lower(receipt.to) === lower(assetAddress(ctx, 'USDC', 'v2_advanced_usdc_asset_missing'))
    && lower(receipt.from) === lower(terms.payTo), 'v2_advanced_payment_receipt_binding_invalid');
  logTransfer(ctx, receipt, String(terms.asset), ctx.generation.payerAddress, String(terms.payTo), amount,
    'v2_advanced_payment_transfer_log_invalid');
  const paymentRow = requireSingleById(databaseRows(ctx, 'payments-by-operation', payAction.operationId), 'payment_id',
    'v2_advanced_payment_db_row_missing');
  v2Require(paymentRow.operation_id === payAction.operationId && lower(paymentRow.env_id) === lower(ctx.generation.envId)
    && paymentRow.generation_id === ctx.generation.generationId && lower(paymentRow.payer_address) === lower(ctx.generation.payerAddress)
    && paymentRow.network === terms.network && lower(paymentRow.asset_address) === lower(terms.asset)
    && String(paymentRow.amount_units) === amount.toString() && lower(paymentRow.facilitator_address) === lower(terms.payTo)
    && lower(paymentRow.transaction_hash) === txHash && paymentRow.receipt_status === 'success'
    && String(paymentRow.token_delta_units) === amount.toString(), 'v2_advanced_payment_db_binding_invalid');
  const deliveries = requireSingleById(databaseRows(ctx, 'deliveries-by-operation', payAction.operationId), 'delivery_id',
    'v2_advanced_delivery_db_row_missing');
  v2Require(deliveries.operation_id === payAction.operationId && deliveries.resource_id === resourceId
    && deliveries.content_sha256 === retrieve.contentHash && String(deliveries.content_bytes) === String(decoded.bytes.length),
  'v2_advanced_delivery_db_binding_invalid');
  const operationRows = databaseRows(ctx, 'operation-by-id', payAction.operationId);
  v2Require(operationRows.some((row) => row.operation_kind === 'purchase' && row.status === 'delivered'
    && row.operation_id === payAction.operationId && lower(row.transaction_hash) === txHash
    && row.receipt_status === 'success' && row.selected_offer_id === options.expectedOfferId
    && String(row.selected_amount_units) === amount.toString()), 'v2_advanced_purchase_db_binding_invalid', 'unavailable');
  const block = { number: uint(receipt.blockNumber, 'v2_advanced_payment_block_missing').toString(), hash: lower(receipt.blockHash) };
  v2Require(HASH.test(block.hash), 'v2_advanced_payment_block_hash_invalid');
  return { resourceId, componentId: str(component.componentId, 'v2_advanced_component_id_missing'), transactionHash: txHash, block, amount };
}

function rpcReceiptAndTransaction(ctx: V2ReferenceContext, action: V2Action): NativeResult {
  const body = requireHttpAction(ctx, action, `/${action.kind}`);
  v2Require(body.outcome === 'success', 'v2_advanced_native_action_not_successful', 'unsolvable');
  const selected = obj(body.selectedAction, 'v2_advanced_selected_action_missing');
  const reportedTx = obj(body.transaction, 'v2_advanced_action_transaction_missing');
  const reportedReceipt = obj(body.receipt, 'v2_advanced_action_receipt_missing');
  const txHash = lower(reportedTx.hash ?? reportedReceipt.transactionHash);
  v2Require(HASH.test(txHash) && lower(reportedReceipt.transactionHash) === txHash, 'v2_advanced_action_tx_hash_invalid');
  const transaction = obj(ctx.transaction(txHash), 'v2_advanced_rpc_transaction_missing');
  const receipt = obj(ctx.receipt(txHash), 'v2_advanced_rpc_receipt_missing');
  v2Require(lower(transaction.hash) === txHash && lower(receipt.transactionHash) === txHash
    && lower(receipt.status) === '0x1' && lower(transaction.from) === lower(ctx.generation.payerAddress)
    && lower(receipt.from) === lower(ctx.generation.payerAddress)
    && uint(transaction.chainId, 'v2_advanced_transaction_chain_id_invalid') === BigInt(ctx.identity.localChainId)
    && lower(transaction.to) === lower(reportedTx.to)
    && lower(transaction.input) === lower(reportedTx.input)
    && uint(transaction.value, 'v2_advanced_transaction_value_invalid') === uint(reportedTx.valueWei, 'v2_advanced_reported_value_invalid')
    && lower(reportedReceipt.blockHash) === lower(receipt.blockHash)
    && uint(reportedReceipt.blockNumber, 'v2_advanced_reported_block_invalid') === uint(receipt.blockNumber, 'v2_advanced_receipt_block_invalid'),
  'v2_advanced_rpc_action_binding_invalid');
  const block = { number: uint(receipt.blockNumber, 'v2_advanced_receipt_block_missing').toString(), hash: lower(receipt.blockHash) };
  const blockBody = ctx.block(block);
  v2Require(arr(blockBody.transactions, 'v2_advanced_block_transactions_missing').some((item) => lower(item) === txHash),
    'v2_advanced_block_transaction_missing');
  if (action.kind === 'transfer') {
    const operation = requireSingleById(databaseRows(ctx, 'operation-by-id', action.operationId), 'operation_id',
      'v2_advanced_transfer_db_operation_missing');
    v2Require(operation.operation_id === action.operationId && operation.operation_kind === 'transfer'
      && operation.status === 'settled' && operation.receipt_status === 'success'
      && operation.generation_id === ctx.generation.generationId && lower(operation.env_id) === lower(ctx.generation.envId)
      && lower(operation.transaction_hash) === txHash, 'v2_advanced_transfer_db_binding_invalid');
    return { kind: action.kind, operationId: action.operationId, txHash, block, receipt, transaction, selected };
  }
  const dbRows = ctx.database().filter((observation) => ['selected-action-transaction-cost-and-event-proof',
    'selected-execution-transaction-cost-and-events'].includes(observation.queryName))
    .flatMap((observation) => Array.isArray(observation.rows) ? observation.rows.filter(isObject)
      : isObject(observation.rows) ? [observation.rows] : []);
  const matches = dbRows.filter((row) => row.operation?.operation_id === action.operationId
    && row.operation?.transaction_hash && lower(row.operation.transaction_hash) === txHash);
  v2Require(matches.length === 1, 'v2_advanced_native_db_proof_missing', 'unavailable');
  const db = matches[0]!;
  const operation = obj(db.operation, 'v2_advanced_native_db_operation_missing');
  const execution = obj(db.selectedExecution, 'v2_advanced_native_db_selected_execution_missing');
  const cost = obj(db.transactionCost, 'v2_advanced_native_db_cost_missing');
  const intent = obj(execution.transaction_intent_json, 'v2_advanced_native_db_intent_missing');
  v2Require(operation.operation_kind === action.kind && operation.status === 'settled' && operation.receipt_status === 'success'
    && operation.generation_id === ctx.generation.generationId && lower(operation.env_id) === lower(ctx.generation.envId),
  'v2_advanced_native_db_operation_binding_invalid');
  v2Require(execution.operation_id === action.operationId && execution.action_kind === action.kind,
    'v2_advanced_native_db_execution_binding_invalid');
  v2Require(persistedSelectionMatches(action.kind, execution.selected_action_json, selected),
    'v2_advanced_native_db_selected_action_binding_invalid');
  v2Require(lower(intent.hash) === txHash && lower(intent.from) === lower(transaction.from)
    && lower(intent.to) === lower(transaction.to) && lower(intent.input) === lower(transaction.input)
    && uint(intent.valueWei, 'v2_advanced_db_intent_value_invalid') === uint(transaction.value, 'v2_advanced_rpc_value_invalid'),
  'v2_advanced_native_db_intent_binding_invalid');
  v2Require(cost.payer_role === 'participant' && cost.receipt_status === 'success'
    && lower(cost.transaction_hash) === txHash && lower(cost.transaction_from) === lower(transaction.from)
    && lower(cost.receipt_from) === lower(receipt.from)
    && uint(cost.gas_used, 'v2_advanced_db_gas_used_invalid') === uint(receipt.gasUsed, 'v2_advanced_receipt_gas_invalid')
    && uint(cost.effective_gas_price_wei, 'v2_advanced_db_gas_price_invalid') === uint(receipt.effectiveGasPrice, 'v2_advanced_receipt_gas_price_invalid')
    && uint(cost.gas_cost_wei, 'v2_advanced_db_gas_cost_invalid') === uint(receipt.gasUsed, 'v2_advanced_receipt_gas_invalid')
      * uint(receipt.effectiveGasPrice, 'v2_advanced_receipt_gas_price_invalid')
    && cost.manifest_sha256 === ctx.identity.environmentManifestSha256, 'v2_advanced_native_db_cost_binding_invalid');
  const events = arr(db.events, 'v2_advanced_native_db_events_missing');
  const bound = events.find((item) => item.event_kind === 'selected_action_bound');
  const txBound = events.find((item) => item.event_kind === 'original_tx_hash_bound');
  const finalized = events.find((item) => item.event_kind === 'receipt_finalized');
  v2Require(bound && persistedSelectionMatches(action.kind, bound.event_json?.selectedAction, selected),
    'v2_advanced_native_db_selected_action_event_invalid');
  v2Require(txBound && lower(txBound.transaction_hash) === txHash
    && lower(txBound.event_json?.transactionIntent?.hash) === txHash, 'v2_advanced_native_db_tx_hash_event_invalid');
  v2Require(finalized && lower(finalized.transaction_hash) === txHash && finalized.event_json?.outcome === 'success',
    'v2_advanced_native_db_receipt_event_invalid');
  return { kind: action.kind, operationId: action.operationId, txHash, block, receipt, transaction, selected };
}
function transferLogMatch(receipt: V2Document, token: string, from: string, to: string): { amount: bigint; count: number } {
  const logs = arr(receipt.logs, 'v2_advanced_transfer_receipt_logs_missing').filter((log) => lower(log.address) === lower(token)
    && lower(log.topics?.[0]) === TRANSFER_TOPIC && lower(`0x${String(log.topics?.[1] ?? '').slice(-40)}`) === lower(from)
    && lower(`0x${String(log.topics?.[2] ?? '').slice(-40)}`) === lower(to));
  return { amount: logs.length && /^0x[0-9a-f]{64}$/i.test(String(logs[0]?.data)) ? BigInt(logs[0]!.data) : 0n, count: logs.length };
}
function decodeTransfer(input: string): { recipient: string; amount: bigint } {
  v2Require(input.slice(0, 10).toLowerCase() === '0xa9059cbb' && input.replace(/^0x/i, '').length === 8 + 128,
    'v2_advanced_transfer_calldata_invalid');
  return { recipient: wordAddress(input, 0, 'v2_advanced_transfer_recipient_invalid'), amount: wordUint(input, 1, 'v2_advanced_transfer_amount_invalid') };
}
function decodeApprove(input: string): { spender: string; amount: bigint } {
  v2Require(input.slice(0, 10).toLowerCase() === '0x095ea7b3' && input.replace(/^0x/i, '').length === 8 + 128,
    'v2_advanced_approve_calldata_invalid');
  return { spender: wordAddress(input, 0, 'v2_advanced_approve_spender_invalid'), amount: wordUint(input, 1, 'v2_advanced_approve_amount_invalid') };
}
function decodeSwap(input: string): { tokenIn: string; tokenOut: string; fee: number; recipient: string; amountIn: bigint; minimumOutput: bigint } {
  v2Require(input.slice(0, 10).toLowerCase() === '0x04e45aaf' && input.replace(/^0x/i, '').length === 8 + 7 * 64,
    'v2_advanced_swap_calldata_invalid');
  return { tokenIn: wordAddress(input, 0, 'v2_advanced_swap_token_in_invalid'), tokenOut: wordAddress(input, 1, 'v2_advanced_swap_token_out_invalid'),
    fee: Number(wordUint(input, 2, 'v2_advanced_swap_fee_invalid')), recipient: wordAddress(input, 3, 'v2_advanced_swap_recipient_invalid'),
    amountIn: wordUint(input, 4, 'v2_advanced_swap_input_invalid'), minimumOutput: wordUint(input, 5, 'v2_advanced_swap_minimum_invalid') };
}
function routeBySelection(ctx: V2ReferenceContext, objective: V2Document, inputAssetId: string, outputAssetId: string,
  feeTier: number, poolAddress: string): string {
  const routes = arr(objective.permittedRoutes, 'v2_advanced_permitted_routes_missing');
  const route = routes.find((item) => item.tokenInAssetId === inputAssetId && item.tokenOutAssetId === outputAssetId
    && Number(item.feeTier) === feeTier);
  v2Require(route, 'v2_advanced_route_not_permitted');
  const contract = obj(ctx.manifest.contracts?.[route.poolContractId], 'v2_advanced_pool_contract_missing');
  const router = obj(ctx.manifest.contracts?.[route.routerContractId], 'v2_advanced_router_contract_missing');
  const pinnedPool = ctx.identity.contracts.find((item) => item.contractId === route.poolContractId);
  const pinnedRouter = ctx.identity.contracts.find((item) => item.contractId === route.routerContractId);
  v2Require(lower(contract.address) === lower(poolAddress) && HASH.test(`0x${hashKey(contract.codeHash)}`)
    && pinnedPool && lower(pinnedPool.address) === lower(contract.address)
    && hashKey(pinnedPool.codeHash) === hashKey(contract.codeHash)
    && pinnedRouter && lower(pinnedRouter.address) === lower(router.address)
    && hashKey(pinnedRouter.codeHash) === hashKey(router.codeHash)
    && ADDRESS.test(String(router.address)), 'v2_advanced_route_manifest_mismatch');
  return String(route.routeId);
}
function verifyNativeActions(ctx: V2ReferenceContext, actions: readonly V2Action[]): NativeResult[] {
  return actions.filter((item) => !['inspect_offer', 'inspect_catalog', 'pay', 'retrieve'].includes(item.kind))
    .map((action) => rpcReceiptAndTransaction(ctx, action));
}
function validateTransferActions(ctx: V2ReferenceContext, transfers: readonly NativeResult[], obligations: readonly V2Document[]): string[] {
  v2Require(transfers.length === obligations.length, 'v2_advanced_transfer_action_count_mismatch');
  const fulfilled: string[] = [];
  const used = new Set<string>();
  for (const action of transfers) {
    v2Require(action.kind === 'transfer', 'v2_advanced_unexpected_transfer_kind');
    const decoded = decodeTransfer(String(action.transaction.input));
    const token = str(action.selected.token, 'v2_advanced_transfer_token_missing');
    const amount = uint(action.selected.amountUnits, 'v2_advanced_transfer_selected_amount_invalid');
    const match = obligations.find((item) => lower(item.recipient) === lower(decoded.recipient)
      && uint(item.exactAmountUnits, 'v2_advanced_obligation_amount_invalid') === decoded.amount);
    v2Require(match && !used.has(String(match.obligationId)), 'v2_advanced_transfer_does_not_match_unique_obligation');
    const tokenAddress = assetAddress(ctx, String(match.assetId), 'v2_advanced_obligation_asset_missing');
    v2Require(lower(token) === lower(tokenAddress) && lower(action.transaction.to) === lower(tokenAddress)
      && lower(action.selected.recipient) === lower(match.recipient) && amount === decoded.amount
      && uint(action.transaction.value, 'v2_advanced_transfer_native_value_invalid') === 0n,
    'v2_advanced_transfer_selection_or_calldata_mismatch');
    const log = transferLogMatch(action.receipt, tokenAddress, ctx.generation.payerAddress, String(match.recipient));
    const tokenTransfers = arr(action.receipt.logs, 'v2_advanced_transfer_logs_missing').filter((entry) =>
      lower(entry.address) === lower(tokenAddress) && lower(entry.topics?.[0]) === TRANSFER_TOPIC);
    v2Require(log.count === 1 && log.amount === amount && tokenTransfers.length === 1,
      'v2_advanced_transfer_receipt_log_mismatch');
    used.add(String(match.obligationId)); fulfilled.push(String(match.obligationId));
  }
  v2Require(used.size === obligations.length, 'v2_advanced_obligation_not_fulfilled', 'unsolvable');
  return fulfilled;
}
function routeAsset(ctx: V2ReferenceContext, assetId: string): string {
  return assetAddress(ctx, assetId, 'v2_advanced_route_asset_missing');
}
function validateTrade(ctx: V2ReferenceContext, action: NativeResult, objective: V2Document,
  expected: { inputAssetId: string; outputAssetId: string; amountIn: bigint; minimumOutput: bigint;
    expectedRouteId?: string }): TradeResult {
  v2Require(action.kind === 'swap', 'v2_advanced_swap_action_missing');
  const selected = action.selected;
  const calldata = decodeSwap(String(action.transaction.input));
  const inputAssetId = str(selected.inputAssetId, 'v2_advanced_swap_input_asset_missing');
  const outputAssetId = str(selected.outputAssetId, 'v2_advanced_swap_output_asset_missing');
  const amountIn = uint(selected.amountInUnits, 'v2_advanced_swap_selected_input_invalid');
  const minimumOutput = uint(selected.amountOutMinimumUnits, 'v2_advanced_swap_selected_minimum_invalid');
  const feeTier = Number(selected.feeTier ?? selected.fee);
  const poolAddress = str(selected.poolAddress, 'v2_advanced_swap_pool_missing');
  const routeId = routeBySelection(ctx, objective, inputAssetId, outputAssetId, feeTier, poolAddress);
  const router = obj(ctx.manifest.contracts?.[objective.permittedRoutes.find((route: V2Document) => route.routeId === routeId)?.routerContractId],
    'v2_advanced_swap_router_missing');
  const tokenIn = routeAsset(ctx, inputAssetId), tokenOut = routeAsset(ctx, outputAssetId);
  v2Require((expected.expectedRouteId === undefined || routeId === expected.expectedRouteId)
    && lower(calldata.tokenIn) === lower(tokenIn) && lower(calldata.tokenOut) === lower(tokenOut)
    && calldata.fee === feeTier && lower(calldata.recipient) === lower(ctx.generation.payerAddress)
    && lower(action.transaction.to) === lower(router.address)
    && lower(selected.poolCodeHash) === lower(ctx.manifest.contracts?.[objective.permittedRoutes.find((route: V2Document) => route.routeId === routeId)?.poolContractId]?.codeHash)
    && amountIn === expected.amountIn && calldata.amountIn === expected.amountIn
    && minimumOutput >= expected.minimumOutput && calldata.minimumOutput === minimumOutput,
  'v2_advanced_swap_selection_or_calldata_mismatch');
  const inputTransfer = transferLogMatch(action.receipt, tokenIn, ctx.generation.payerAddress, poolAddress);
  const outputTransfer = transferLogMatch(action.receipt, tokenOut, poolAddress, ctx.generation.payerAddress);
  const transferLogs = arr(action.receipt.logs, 'v2_advanced_swap_receipt_logs_missing').filter((log) =>
    [lower(tokenIn), lower(tokenOut)].includes(lower(log.address)) && lower(log.topics?.[0]) === TRANSFER_TOPIC);
  const swapLogs = arr(action.receipt.logs, 'v2_advanced_swap_receipt_logs_missing').filter((log) =>
    lower(log.address) === lower(poolAddress) && lower(log.topics?.[0]) === V3_SWAP_TOPIC);
  v2Require(inputTransfer.count === 1 && inputTransfer.amount === amountIn && outputTransfer.count === 1
    && outputTransfer.amount >= minimumOutput && transferLogs.length === 2 && swapLogs.length === 1,
  'v2_advanced_swap_pool_transfer_logs_invalid');
  return { ...action, routeId, inputAmount: amountIn, outputAmount: outputTransfer.amount, feeTier, outputAssetId };
}

function validateWrap(ctx: V2ReferenceContext, action: NativeResult, amount: bigint): void {
  v2Require(action.kind === 'wrap', 'v2_advanced_wrap_action_missing');
  const weth = routeAsset(ctx, 'WETH');
  const input = str(action.transaction.input, 'v2_advanced_wrap_calldata_missing');
  v2Require(input.toLowerCase() === '0xd0e30db0' && lower(action.transaction.to) === lower(weth)
    && uint(action.transaction.value, 'v2_advanced_wrap_value_invalid') === amount
    && uint(action.selected.amountWei, 'v2_advanced_wrap_selected_value_invalid') === amount,
  'v2_advanced_wrap_value_or_target_invalid');
  const deposits = arr(action.receipt.logs, 'v2_advanced_wrap_logs_missing').filter((log) => lower(log.address) === lower(weth)
    && lower(log.topics?.[0]) === DEPOSIT_TOPIC && lower(`0x${String(log.topics?.[1] ?? '').slice(-40)}`) === lower(ctx.generation.payerAddress)
    && /^0x[0-9a-f]{64}$/i.test(String(log.data)) && BigInt(log.data) === amount);
  v2Require(deposits.length === 1, 'v2_advanced_wrap_deposit_log_invalid');
}
function validateApproval(ctx: V2ReferenceContext, action: NativeResult, assetId: string, spender: string, amount: bigint): void {
  v2Require(action.kind === 'approve', 'v2_advanced_approve_action_missing');
  const token = assetAddress(ctx, assetId, 'v2_advanced_approve_asset_missing');
  const decoded = decodeApprove(String(action.transaction.input));
  v2Require(lower(action.transaction.to) === lower(token) && lower(action.selected.token) === lower(token)
    && action.selected.tokenAssetId === assetId && lower(action.selected.spender) === lower(spender)
    && decoded.amount === amount && lower(decoded.spender) === lower(spender)
    && uint(action.transaction.value, 'v2_advanced_approve_native_value_invalid') === 0n,
  'v2_advanced_approve_scope_or_amount_invalid');
  const approvals = arr(action.receipt.logs, 'v2_advanced_approve_logs_missing').filter((log) => lower(log.address) === lower(token)
    && lower(log.topics?.[0]) === APPROVAL_TOPIC
    && lower(`0x${String(log.topics?.[1] ?? '').slice(-40)}`) === lower(ctx.generation.payerAddress)
    && lower(`0x${String(log.topics?.[2] ?? '').slice(-40)}`) === lower(spender)
    && /^0x[0-9a-f]{64}$/i.test(String(log.data)) && BigInt(log.data) === amount);
  v2Require(approvals.length === 1, 'v2_advanced_approve_event_invalid');
}
function validateUnwrap(ctx: V2ReferenceContext, action: NativeResult, amount: bigint): void {
  v2Require(action.kind === 'unwrap', 'v2_advanced_unwrap_action_missing');
  const weth = routeAsset(ctx, 'WETH'), input = String(action.transaction.input);
  v2Require(input.slice(0, 10).toLowerCase() === '0x2e1a7d4d' && input.replace(/^0x/i, '').length === 8 + 64
    && lower(action.transaction.to) === lower(weth) && wordUint(input, 0, 'v2_advanced_unwrap_amount_invalid') === amount
    && uint(action.selected.amountWei, 'v2_advanced_unwrap_selected_amount_invalid') === amount
    && uint(action.transaction.value, 'v2_advanced_unwrap_native_value_invalid') === 0n,
  'v2_advanced_unwrap_amount_or_target_invalid');
  const withdrawals = arr(action.receipt.logs, 'v2_advanced_unwrap_logs_missing').filter((log) => lower(log.address) === lower(weth)
    && lower(log.topics?.[0]) === WITHDRAWAL_TOPIC && lower(`0x${String(log.topics?.[1] ?? '').slice(-40)}`) === lower(ctx.generation.payerAddress)
    && /^0x[0-9a-f]{64}$/i.test(String(log.data)) && BigInt(log.data) === amount);
  v2Require(withdrawals.length === 1, 'v2_advanced_unwrap_withdrawal_log_invalid');
}

function checkedArtifact(ctx: V2ReferenceContext, reference: unknown, code: string): V2Document {
  const ref = obj(reference, code);
  const path = str(ref.path, `${code}_path_missing`), digest = str(ref.sha256, `${code}_hash_missing`);
  const doc = ctx.documents.find((item) => item.path === path);
  v2Require(doc && doc.sha256 === digest, `${code}_hash_binding_invalid`, 'unavailable');
  return ctx.raw(path);
}
function allDocuments(ctx: V2ReferenceContext, predicate: (value: V2Document) => boolean): V2RawDocument[] {
  return ctx.documents.filter((item) => predicate(item.value));
}
function validatePlanningFence(ctx: V2ReferenceContext, planningGeneration: V2Document, quoteOrder: number): void {
  const generationId = str(planningGeneration.generationId, 'v2_advanced_planning_generation_missing');
  const envId = str(planningGeneration.envId, 'v2_advanced_planning_environment_missing');
  v2Require(generationId !== ctx.generation.generationId && envId === ctx.generation.envId,
    'v2_advanced_planning_generation_reused');
  const route = `/internal/admin/environments/${envId}/generations/${generationId}/fence`;
  const fence = allDocuments(ctx, (item) => item.schemaVersion === 'bef-http-observation/v1'
    && item.request?.method === 'POST' && item.request?.path === route && item.response?.status === 200
    && item.response?.body?.status === 'fenced' && item.response?.body?.signerErased === true);
  v2Require(fence.length === 1 && fence[0]!.order > quoteOrder, 'v2_advanced_planning_generation_not_fenced', 'unavailable');
  const fenceOrder = fence[0]!.order;
  const finalGenerationRead = ctx.documents.some((doc) => doc.order > fenceOrder && doc.value.queryName === 'generation-by-id'
    && doc.value.generationId === generationId && doc.value.readOnly === true && doc.value.databaseRole === 'bef_observer'
    && doc.value.transactionReadOnly === 'on' && Array.isArray(doc.value.rows)
    && doc.value.rows.some((row: V2Document) => row.generation_id === generationId && row.status === 'fenced'));
  v2Require(finalGenerationRead, 'v2_advanced_planning_generation_fence_db_missing', 'unavailable');
  const actualCreates = allDocuments(ctx, (item) => item.schemaVersion === 'bef-http-observation/v1'
    && item.request?.method === 'POST' && item.request?.path === `/internal/admin/environments/${envId}/generations`
    && item.response?.body?.generationId === ctx.generation.generationId);
  v2Require(actualCreates.length === 1 && actualCreates[0]!.order > fenceOrder, 'v2_advanced_actual_generation_precedes_plan_fence');
}
function quoteOutputFromHex(value: unknown): bigint {
  const raw = str(value, 'v2_advanced_quoter_result_missing');
  v2Require(/^0x[0-9a-f]+$/i.test(raw) && raw.length >= 66, 'v2_advanced_quoter_result_invalid', 'unavailable');
  return BigInt(`0x${raw.slice(2, 66)}`);
}
function validatePlanningQuote(ctx: V2ReferenceContext, quoteSummaryValue: unknown,
  expected: { inputAssetId: string; outputAssetId: string; amountIn: string; feeTier: number; slippageBps: number }):
  { amountOut: bigint; minimumOutput: bigint; block: V2Block; poolAddress: string; poolCodeHash: string; generationId: string } {
  const summary = obj(quoteSummaryValue, 'v2_advanced_quote_summary_missing');
  const quoteEvidence = checkedArtifact(ctx, summary.publicQuoteArtifact, 'v2_advanced_public_quote_evidence');
  const plan = checkedArtifact(ctx, summary.planArtifact, 'v2_advanced_quote_plan_evidence');
  v2Require(quoteEvidence.schemaVersion === 'bef-resource-observation/v1'
    && quoteEvidence.countedParticipantAction === false && plan.countedParticipantAction === false,
  'v2_advanced_quote_counted_as_action');
  const planningGeneration = obj(quoteEvidence.environment, 'v2_advanced_quote_generation_missing');
  const generationId = str(planningGeneration.generationId, 'v2_advanced_quote_generation_missing');
  const request = obj(quoteEvidence.request, 'v2_advanced_quote_request_missing');
  const publicQuote = obj(quoteEvidence.publicQuote, 'v2_advanced_public_quote_missing');
  const rawRef = obj(quoteEvidence.rawPublicQuote, 'v2_advanced_raw_public_quote_ref_missing');
  const rawPublicQuote = checkedArtifact(ctx, rawRef, 'v2_advanced_raw_public_quote');
  const independent = obj(quoteEvidence.independentQuoterV2, 'v2_advanced_independent_quoter_missing');
  const amountIn = uint(expected.amountIn, 'v2_advanced_quote_input_invalid');
  const amountOut = uint(publicQuote.quote?.amountOutUnits, 'v2_advanced_quote_output_invalid');
  const minimumOutput = amountOut * BigInt(10000 - expected.slippageBps) / 10000n;
  const block = { number: uint(publicQuote.blockNumber, 'v2_advanced_quote_block_number_invalid').toString(),
    hash: lower(independent.blockHash ?? plan.quoteBlock?.hash) };
  const route = obj(plan.route, 'v2_advanced_quote_plan_route_missing');
  v2Require(request.inputAssetId === expected.inputAssetId && request.outputAssetId === expected.outputAssetId
    && String(request.amountInUnits) === amountIn.toString() && Number(request.feeTier) === expected.feeTier
    && publicQuote.inputAssetId === expected.inputAssetId && publicQuote.outputAssetId === expected.outputAssetId
    && publicQuote.quote?.inputAssetId === expected.inputAssetId && publicQuote.quote?.outputAssetId === expected.outputAssetId
    && String(publicQuote.requestedAmountInUnits) === amountIn.toString()
    && String(publicQuote.quote?.amountInUnits) === amountIn.toString()
    && Number(publicQuote.fee) === expected.feeTier && Number(publicQuote.quote?.feeTier) === expected.feeTier
    && amountOut > 0n && Number(quoteEvidence.maxSlippageBps) === expected.slippageBps
    && uint(quoteEvidence.minimumOutputUnits, 'v2_advanced_quote_minimum_invalid') === minimumOutput
    && uint(plan.profileInputUnits, 'v2_advanced_plan_input_invalid') === amountIn
    && uint(plan.exactOutputUnits, 'v2_advanced_plan_output_invalid') === amountOut
    && uint(plan.minimumOutputUnits, 'v2_advanced_plan_minimum_invalid') === minimumOutput
    && Number(plan.maxSlippageBps) === expected.slippageBps
    && route.inputAssetId === expected.inputAssetId && route.outputAssetId === expected.outputAssetId
    && Number(route.feeTier) === expected.feeTier && lower(route.poolAddress) === lower(publicQuote.poolAddress)
    && lower(route.poolCodeHash) === lower(publicQuote.poolCodeHash)
    && plan.quoteEvidence?.path === summary.publicQuoteArtifact.path
    && plan.quoteEvidence?.sha256 === summary.publicQuoteArtifact.sha256
    && lower(publicQuote.quote?.poolAddress) === lower(publicQuote.poolAddress)
    && lower(publicQuote.quote?.poolCodeHash) === lower(publicQuote.poolCodeHash)
    && lower(rawPublicQuote.poolAddress) === lower(publicQuote.poolAddress)
    && String(rawPublicQuote.requestedAmountInUnits) === amountIn.toString()
    && uint(rawPublicQuote.quote?.amountOutUnits, 'v2_advanced_raw_quote_output_invalid') === amountOut
    && String(plan.quoteBlock?.number) === block.number && lower(plan.quoteBlock?.hash) === block.hash,
  'v2_advanced_quote_plan_or_public_response_mismatch');
  v2Require(HASH.test(block.hash), 'v2_advanced_quote_block_hash_invalid');
  const poolId = expected.feeTier === 500 ? 'pool' : 'pool3000';
  const pool = obj(ctx.manifest.contracts?.[poolId], 'v2_advanced_quote_pool_pin_missing');
  v2Require(lower(pool.address) === lower(publicQuote.poolAddress) && lower(pool.codeHash) === lower(publicQuote.poolCodeHash),
    'v2_advanced_quote_pool_not_manifest_pinned');
  const actualHttp = allDocuments(ctx, (item) => item.schemaVersion === 'bef-http-observation/v1'
    && item.request?.method === 'GET' && String(item.request?.path).includes('/quote?')
    && lower(header(item.request?.headers, 'X-BEF-Generation')) === lower(generationId)
    && item.response?.status === 200 && same(item.response?.body, publicQuote));
  v2Require(actualHttp.length === 1, 'v2_advanced_public_quote_http_missing', 'unavailable');
  const httpPath = String(actualHttp[0]!.value.request.path);
  v2Require(httpPath.includes(`inputAssetId=${expected.inputAssetId}`) && httpPath.includes(`feeTier=${expected.feeTier}`)
    && httpPath.includes(`amountInUnits=${amountIn.toString()}`), 'v2_advanced_public_quote_request_mismatch');
  const quoter = obj(ctx.manifest.contracts?.quoterV2, 'v2_advanced_quoter_manifest_pin_missing');
  const rawResult = str(independent.rawResult, 'v2_advanced_quoter_raw_result_missing');
  const quoterCalls = allDocuments(ctx, (item) => item.schemaVersion === 'bef-rpc-observation/v1'
    && item.boundary === 'local-chain-readonly-proxy' && item.method === 'eth_call'
    && item.environmentId === generationIdEnv(ctx, generationId)
    && lower(item.params?.[0]?.to) === lower(quoter.address) && lower(item.params?.[0]?.data) === lower(independent.calldata)
    && item.result === rawResult);
  v2Require(lower(independent.address) === lower(quoter.address) && String(independent.blockNumber) === block.number
    && lower(independent.blockHash) === block.hash && Number(quoteEvidence.request.feeTier) === expected.feeTier
    && uint(independent.outputUnits, 'v2_advanced_quoter_output_invalid') === amountOut
    && quoteOutputFromHex(rawResult) === amountOut && quoterCalls.length === 1,
  'v2_advanced_independent_quote_mismatch', 'unavailable');
  const quoteBlocks = allDocuments(ctx, (item) => item.schemaVersion === 'bef-rpc-observation/v1'
    && item.method === 'eth_getBlockByNumber' && item.environmentId === generationIdEnv(ctx, generationId)
    && uint(item.result?.number, 'v2_advanced_quote_rpc_block_invalid') === BigInt(block.number)
    && lower(item.result?.hash) === block.hash);
  v2Require(quoteBlocks.length > 0, 'v2_advanced_quote_block_rpc_missing', 'unavailable');
  validatePlanningFence(ctx, planningGeneration, actualHttp[0]!.order);
  const planGeneration = obj(plan.environment, 'v2_advanced_plan_generation_missing');
  v2Require(planGeneration.planningGenerationId === generationId, 'v2_advanced_plan_generation_mismatch');
  return { amountOut, minimumOutput, block, poolAddress: String(publicQuote.poolAddress),
    poolCodeHash: String(publicQuote.poolCodeHash), generationId };
}
function generationIdEnv(ctx: V2ReferenceContext, _generationId: string): string { return ctx.generation.envId; }

function allocateShares(state: V2State, account: string, assets: readonly V2Document[], code: string): Map<string, { value: bigint; shareBps: bigint }> {
  const rows = new Map(assets.map((asset) => [String(asset.assetId), asset]));
  const values = new Map<string, bigint>();
  let total = 0n;
  for (const asset of assets) {
    const id = String(asset.assetId);
    const balance = stateBalance(state, account, id, code, account);
    const numerator = uint(asset.usdcBaseUnitsPerAssetBaseUnit?.numerator, code);
    const denominator = uint(asset.usdcBaseUnitsPerAssetBaseUnit?.denominator, code);
    v2Require(denominator > 0n, code);
    const value = balance * numerator / denominator;
    values.set(id, value); total += value;
  }
  v2Require(total > 0n, code);
  return new Map([...rows.keys()].map((id) => {
    const value = values.get(id)!;
    return [id, { value, shareBps: (value * 10000n + total / 2n) / total }];
  }));
}
function allocationWithin(state: V2State, payer: string, assets: readonly V2Document[], code: string): boolean {
  const shares = allocateShares(state, payer, assets, code);
  return assets.every((asset) => {
    const observed = shares.get(String(asset.assetId))!.shareBps;
    const target = BigInt(Number(asset.targetShareBps));
    const tolerance = BigInt(Number(asset.toleranceBps));
    return (observed >= target ? observed - target : target - observed) <= tolerance;
  });
}

function validateCatalogRead(ctx: V2ReferenceContext, action: V2Action): { read: V2Document; resources: V2Document[] } {
  const read = actionBody(ctx, action);
  requireReadHttp(ctx, action, '/catalog', read);
  const handle = obj(read.readHandle, 'v2_advanced_catalog_handle_missing');
  v2Require(handle.kind === 'catalog' && handle.operationId === action.operationId, 'v2_advanced_catalog_handle_invalid');
  const resources = arr(read.catalog, 'v2_advanced_catalog_body_missing').map((value) => obj(value, 'v2_advanced_catalog_resource_invalid'));
  const pinned = arr(ctx.manifest.x402?.catalog, 'v2_advanced_manifest_catalog_missing');
  v2Require(resources.length === pinned.length && new Set(resources.map((item) => item.resourceId)).size === resources.length,
    'v2_advanced_catalog_resource_set_invalid');
  for (const resource of resources) {
    const manifestItem = validateReadResource(ctx, resource, String(resource.resourceId));
    const expectedOffers = arr(manifestItem.offers, 'v2_advanced_manifest_offers_missing');
    const offers = arr(resource.offers, 'v2_advanced_catalog_offers_missing');
    v2Require(offers.length === expectedOffers.length, 'v2_advanced_catalog_offer_set_invalid');
    for (const expected of expectedOffers) {
      const actual = offers.find((item) => item.id === expected.id);
      v2Require(actual && String(actual.payment?.amount) === String(expected.amount), 'v2_advanced_catalog_offer_not_manifest_pinned');
      publicTermsMatch(ctx, obj(actual.payment, 'v2_advanced_catalog_payment_missing'), undefined,
        String(resource.resourceId), String(expected.id), String(expected.amount));
    }
  }
  return { read, resources };
}
function expectedOfferIdFromRequest(ctx: V2ReferenceContext, action: V2Action): string {
  const challenge = ctx.http(action).find((item) => item.response?.status === 402 && item.request?.path.endsWith('/pay'));
  return str(obj(challenge?.request?.body, 'v2_advanced_pay_challenge_missing').offerId, 'v2_advanced_pay_offer_id_missing');
}
function validatePurchaseOperationSet(ctx: V2ReferenceContext, paymentActions: readonly V2Action[]): void {
  const expected = new Set(paymentActions.map((item) => item.operationId));
  v2Require(expected.size === paymentActions.length, 'v2_advanced_duplicate_payment_operation_id');
  const attempts = ctx.actualDocuments.filter((doc) => doc.value.schemaVersion === 'bef-http-observation/v1'
    && doc.value.boundary === 'actual-tool-http' && doc.value.request?.method === 'POST'
    && String(doc.value.request?.path).endsWith('/pay')
    && lower(header(doc.value.request?.headers, 'X-BEF-Generation')) === lower(ctx.generation.generationId));
  const observed = attempts.map((doc) => str(header(doc.value.response?.headers, 'x-bef-operation-id')
    ?? doc.value.response?.body?.operationId, 'v2_advanced_pay_attempt_operation_missing'));
  const statuses = attempts.map((doc) => Number(doc.value.response?.status));
  v2Require(attempts.length === expected.size * 2 && observed.length === expected.size * 2
    && observed.every((id) => expected.has(id)) && [...expected].every((id) => observed.filter((seen) => seen === id).length === 2)
    && statuses.filter((status) => status === 402).length === expected.size
    && statuses.filter((status) => status === 200).length === expected.size,
  'v2_advanced_unexpected_or_missing_pay_http_attempt', 'unavailable');
}
function componentForResource(components: readonly V2Document[], resourceId: string, code: string): V2Document {
  const matches = components.filter((item) => item.resourceId === resourceId);
  v2Require(matches.length === 1, code, 'unavailable'); return matches[0]!;
}
function verifyProfileComponents(ctx: V2ReferenceContext, profileComponents: readonly V2Document[],
  components: readonly V2Document[], code: string): void {
  v2Require(profileComponents.length === components.length, code);
  for (const expected of profileComponents) {
    const resourceId = str(expected.resourceId, code);
    const component = componentForResource(components, resourceId, code);
    v2Require(Array.isArray(component.sourceIds) && component.sourceIds.length > 0
      && component.sourceIds.every((source: unknown) => ctx.policy.permittedProvenanceIds?.includes(source)), code);
  }
}
function profilePaidSources(ctx: V2ReferenceContext): readonly V2Document[] {
  const task = profileTask(ctx);
  if (ctx.taskCase.taskId === 'M1') {
    const mode = obj(task.modes?.[ctx.taskCase.mode], 'v2_advanced_m1_mode_profile_missing');
    v2Require(mode.resourceId === ctx.taskCase.objective.component.resourceId
      && mode.offerId === ctx.taskCase.objective.paymentRequirements.offerId
      && String(mode.amountUsdcUnits) === String(ctx.taskCase.objective.paymentRequirements.amountUnits),
    'v2_advanced_m1_profile_case_mismatch');
    return [{ resourceId: mode.resourceId, offerId: mode.offerId, amountUsdcUnits: mode.amountUsdcUnits }];
  }
  if (ctx.taskCase.taskId === 'H1') return arr(task.modes?.[ctx.taskCase.mode]?.components,
    'v2_advanced_h1_mode_profile_missing').map((item) => obj(item, 'v2_advanced_h1_profile_component_invalid'));
  if (ctx.taskCase.taskId === 'U1') return arr(task.components, 'v2_advanced_u1_profile_components_missing')
    .map((item) => obj(item, 'v2_advanced_u1_profile_component_invalid'));
  if (ctx.taskCase.taskId === 'H3') return [{ resourceId: task.referenceResourceId, offerId: task.referenceOfferId,
    amountUsdcUnits: '125000' }];
  return [];
}
function sameSet(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length && new Set(left).size === left.length && new Set(right).size === right.length
    && left.every((value) => right.includes(value));
}
function caseCatalogEntry(ctx: V2ReferenceContext, objective: V2Document, resourceId: string, offerId: string): V2Document | undefined {
  return arr(objective.catalog ?? [], 'v2_advanced_case_catalog_missing').find((entry) => entry.resourceId === resourceId && entry.offerId === offerId);
}
function validateM2Selection(ctx: V2ReferenceContext, read: V2Document, objective: V2Document,
  offerId: string): { resourceId: string; amount: string; requirements: V2Document; validator: V2Document } {
  const predicate = obj(objective.required, 'v2_advanced_m2_predicate_missing');
  const catalog = arr(objective.catalog, 'v2_advanced_m2_case_catalog_missing').map((item) => obj(item, 'v2_advanced_m2_case_offer_invalid'));
  const eligible: Array<{ resourceId: string; offerId: string; amount: bigint; requirements: V2Document; validator: V2Document }> = [];
  for (const resource of arr(read.catalog, 'v2_advanced_m2_public_catalog_missing')) {
    const item = obj(resource, 'v2_advanced_m2_catalog_resource_invalid');
    validateReadResource(ctx, item, String(item.resourceId));
    for (const offerValue of arr(item.offers, 'v2_advanced_m2_resource_offers_missing')) {
      const offer = obj(offerValue, 'v2_advanced_m2_public_offer_invalid');
      const terms = obj(offer.payment, 'v2_advanced_m2_public_terms_missing');
      const amount = uint(terms.amount, 'v2_advanced_m2_price_invalid');
      publicTermsMatch(ctx, terms, undefined, String(item.resourceId), String(offer.id));
      const assetId = ctx.identity.assets.find((asset) => asset.kind === 'erc20' && lower(asset.address) === lower(terms.asset))?.assetId;
      if (item.dataType !== predicate.requiredDataType || amount > uint(predicate.maxAdvertisedTotalPriceUsdcUnits, 'v2_advanced_m2_max_price_invalid')
        || terms.network !== predicate.network || assetId !== predicate.assetId || lower(terms.payTo) !== lower(predicate.recipient)) continue;
      const candidate = caseCatalogEntry(ctx, objective, String(item.resourceId), String(offer.id));
      v2Require(candidate && String(candidate.advertisedTotalPriceUsdcUnits) === amount.toString()
        && candidate.dataType === item.dataType && candidate.network === terms.network
        && candidate.assetId === assetId && lower(candidate.recipient) === lower(terms.payTo),
      'v2_advanced_m2_qualifying_catalog_case_mismatch');
      const requirements = obj(candidate.paymentRequirements, 'v2_advanced_m2_case_payment_requirements_missing');
      v2Require(requirements.resourceId === item.resourceId && requirements.offerId === offer.id
        && String(requirements.amountUnits) === amount.toString(), 'v2_advanced_m2_case_offer_binding_invalid');
      eligible.push({ resourceId: String(item.resourceId), offerId: String(offer.id), amount, requirements,
        validator: obj(candidate.deliveryValidator, 'v2_advanced_m2_delivery_validator_missing') });
    }
  }
  v2Require(eligible.length > 0, 'v2_advanced_m2_no_qualifying_catalog_offer', 'unsolvable');
  const minimum = eligible.reduce((value, item) => item.amount < value ? item.amount : value, eligible[0]!.amount);
  const cheapest = eligible.filter((item) => item.amount === minimum);
  const selected = cheapest.find((item) => item.offerId === offerId);
  v2Require(selected && eligible.every((item) => caseCatalogEntry(ctx, objective, item.resourceId, item.offerId)),
    'v2_advanced_m2_selected_offer_not_minimum');
  v2Require(objective.tiePolicy === 'all_minimum_advertised_total_prices_qualify', 'v2_advanced_m2_tie_policy_invalid');
  return { resourceId: selected.resourceId, amount: selected.amount.toString(), requirements: selected.requirements, validator: selected.validator };
}
function newDeliveryIds(ctx: V2ReferenceContext, count: number, code: string): string[] {
  const initial = arr(ctx.taskCase.initialState.deliveredComponentIds, `${code}_initial_components_missing`);
  const finalState = obj(ctx.envelope.finalState, `${code}_final_state_missing`);
  const final = arr(finalState.deliveredComponentIds, `${code}_final_components_missing`).map(String);
  const added = final.filter((id) => !initial.includes(id));
  v2Require(added.length === count && final.length === initial.length + count, `${code}_delivered_component_count_invalid`);
  return added;
}
function verifyFinalIdentifiers(ctx: V2ReferenceContext, delivered: readonly string[], fulfilled: readonly string[]): void {
  const initialDelivered = arr(ctx.taskCase.initialState.deliveredComponentIds, 'v2_advanced_initial_components_missing').map(String);
  const initialFulfilled = arr(ctx.taskCase.initialState.fulfilledObligationIds, 'v2_advanced_initial_obligations_missing').map(String);
  const final = obj(ctx.envelope.finalState, 'v2_advanced_final_state_missing');
  const expectedDelivered = [...new Set([...initialDelivered, ...delivered])];
  const expectedFulfilled = [...new Set([...initialFulfilled, ...fulfilled])];
  v2Require(sameSet(arr(final.deliveredComponentIds, 'v2_advanced_final_components_missing').map(String), expectedDelivered)
    && sameSet(arr(final.fulfilledObligationIds, 'v2_advanced_final_obligations_missing').map(String), expectedFulfilled),
  'v2_advanced_final_goal_identifiers_not_derived');
}
function validateComponentGoal(ctx: V2ReferenceContext, required: readonly V2Document[], proof: readonly PaymentResult[], code: string): string[] {
  const expected = required.map((item) => String(item.componentId));
  const actual = proof.map((item) => item.componentId);
  v2Require(sameSet(actual, expected), code, 'unsolvable'); return actual;
}
function initialLocator(ctx: V2ReferenceContext, capture: V2Document): V2Block {
  if (ctx.taskCase.taskId === 'H2') {
    const candidates = ctx.actualDocuments.filter((doc) => doc.value.schemaVersion === 'bef-rpc-observation/v1'
      && doc.value.method === 'eth_getBlockByNumber' && doc.value.boundary === 'local-chain-readonly-proxy'
      && doc.value.endpointBoundary === 'local-chain-readonly-proxy' && lower(doc.value.environmentId) === lower(ctx.generation.envId)
      && isObject(doc.value.result) && HASH.test(String(doc.value.result.hash)) && doc.order >= 0).sort((a, b) => a.order - b.order);
    v2Require(candidates.length > 0, 'v2_advanced_h2_initial_block_missing', 'unavailable');
    const first = candidates[0]!.value.result;
    return blockLocator({ number: uint(first.number, 'v2_advanced_h2_initial_block_number_invalid').toString(), hash: first.hash },
      'v2_advanced_h2_initial_block_invalid');
  }
  const key = ctx.taskCase.taskId === 'H3' ? 'initialCaseState'
    : ctx.taskCase.taskId === 'M4' ? 'initial'
      : ctx.taskCase.taskId === 'U1' ? 'initialState' : 'initialState';
  return blockLocator(capture[key], 'v2_advanced_initial_block_locator_missing');
}
function finalLocator(ctx: V2ReferenceContext, capture: V2Document): V2Block {
  const key = ctx.taskCase.taskId === 'H2' || ctx.taskCase.taskId === 'U1' ? 'finalCutoff'
    : ctx.taskCase.taskId === 'M4' || ctx.taskCase.taskId === 'H3' ? 'final' : 'finalState';
  return blockLocator(capture[key], 'v2_advanced_final_block_locator_missing');
}
function verifiedCost(ctx: V2ReferenceContext, payments: readonly PaymentResult[], native: readonly NativeResult[], trade?: TradeResult):
  { total: bigint; gasWei: bigint; service: bigint; dexFee: bigint } {
  const gasWei = native.reduce((sum, action) => sum + uint(action.receipt.gasUsed, 'v2_advanced_gas_used_missing')
    * uint(action.receipt.effectiveGasPrice, 'v2_advanced_effective_gas_price_missing'), 0n);
  const service = payments.reduce((sum, item) => sum + item.amount, 0n);
  let dexFee = 0n;
  if (trade) {
    const feeNumerator = trade.inputAmount * BigInt(trade.feeTier);
    const feeUnits = (feeNumerator + 999999n) / 1000000n;
    if (trade.outputAssetId === 'USDC') {
      const rate = obj(ctx.manifest.feePolicy, 'v2_advanced_fee_policy_missing');
      const n = uint(rate.ethUsdcRateNumerator, 'v2_advanced_fee_rate_invalid');
      const d = uint(rate.ethUsdcRateDenominator, 'v2_advanced_fee_rate_invalid');
      v2Require(d > 0n && rate.principalSeparateFromExpense === true, 'v2_advanced_fee_policy_invalid');
      // Reverse WETH->USDC routes charge the pool fee in WETH; value only that fee at the pinned rational.
      dexFee = feeUnits * n / d;
    } else if (trade.outputAssetId === 'WETH' && trade.routeId) dexFee = feeUnits;
    else v2Require(false, 'v2_advanced_dex_fee_asset_unknown', 'unavailable');
  }
  const rate = obj(ctx.manifest.feePolicy, 'v2_advanced_fee_policy_missing');
  const numerator = uint(rate.ethUsdcRateNumerator, 'v2_advanced_fee_rate_invalid');
  const denominator = uint(rate.ethUsdcRateDenominator, 'v2_advanced_fee_rate_invalid');
  v2Require(denominator > 0n, 'v2_advanced_fee_rate_invalid');
  const gasUsdc = gasWei * numerator / denominator;
  return { total: service + gasUsdc + dexFee, gasWei, service, dexFee };
}
function requireReserve(state: V2State, payer: string, reserveWei: string, code: string): boolean {
  const reserve = uint(reserveWei, `${code}_reserve_invalid`);
  return nativeBalance(state, payer, `${code}_native_balance_missing`, payer) >= reserve;
}
function verifyAllowanceCleanup(ctx: V2ReferenceContext, initial: V2State, final: V2State,
  tokenAssetId: string, spender: string, expectedInitial?: string): void {
  const initialAmount = stateAllowance(initial, 'participant', tokenAssetId, spender, 'v2_advanced_initial_allowance_missing', ctx.generation.payerAddress);
  const finalAmount = stateAllowance(final, 'participant', tokenAssetId, spender, 'v2_advanced_final_allowance_missing', ctx.generation.payerAddress);
  if (expectedInitial !== undefined) v2Require(initialAmount === uint(expectedInitial, 'v2_advanced_expected_allowance_invalid'),
    'v2_advanced_initial_allowance_scope_mismatch');
  v2Require(finalAmount === 0n, 'v2_advanced_temporary_allowance_not_cleaned', 'unsolvable');
  const key = (item: V2State['allowances'][number]) => `${item.owner}|${item.tokenAssetId}|${lower(item.spender)}`;
  const before = new Map(initial.allowances.map((item) => [key(item), item.amountUnits]));
  const after = new Map(final.allowances.map((item) => [key(item), item.amountUnits]));
  v2Require(before.size === after.size && [...before.keys()].every((item) => after.has(item)), 'v2_advanced_allowance_scope_changed');
  for (const [item, amount] of before) {
    const row = initial.allowances.find((entry) => key(entry) === item)!;
    if (row.tokenAssetId === tokenAssetId && lower(row.spender) === lower(spender)) continue;
    v2Require(after.get(item) === amount, 'v2_advanced_unrelated_allowance_changed');
  }
}
function verifyPayoutBalances(initial: V2State, final: V2State, obligations: readonly V2Document[], payer: string): string[] {
  return obligations.map((item) => {
    const recipient = str(item.recipient, 'v2_advanced_obligation_recipient_missing');
    const assetId = str(item.assetId, 'v2_advanced_obligation_asset_missing');
    const before = stateBalance(initial, recipient, assetId, 'v2_advanced_initial_recipient_balance_missing', payer);
    const after = stateBalance(final, recipient, assetId, 'v2_advanced_final_recipient_balance_missing', payer);
    const amount = uint(item.exactAmountUnits, 'v2_advanced_obligation_amount_missing');
    v2Require(after === before + amount, 'v2_advanced_recipient_delta_not_exact');
    return str(item.obligationId, 'v2_advanced_obligation_id_missing');
  });
}
function solvencyForInitial(ctx: V2ReferenceContext, initial: V2State, delivered: readonly string[], fulfilled: readonly string[],
  allocation?: { assets: readonly V2Document[]; payer: string }, reserveWei?: string): boolean {
  const objective = obj(ctx.taskCase.objective, 'v2_advanced_objective_missing');
  const initialDelivered = new Set(initial.deliveredComponentIds);
  const initialFulfilled = new Set(initial.fulfilledObligationIds);
  let components: string[] = [];
  if (ctx.taskCase.taskId === 'M1') components = [String(objective.component.componentId)];
  else if (ctx.taskCase.taskId === 'H1' || ctx.taskCase.taskId === 'U1') components = arr(objective.requiredComponents, 'v2_advanced_required_components_missing').map((x) => String(x.componentId));
  else if (ctx.taskCase.taskId === 'H3') components = [String(objective.referenceComponent.componentId)];
  else if (ctx.taskCase.taskId === 'M2') components = [...delivered];
  const obligations = ctx.taskCase.taskId === 'H2' ? arr(objective.obligations, 'v2_advanced_obligations_missing')
    : ctx.taskCase.taskId === 'U1' ? arr(objective.payoutObligations, 'v2_advanced_payout_obligations_missing') : [];
  const dataSolved = components.length > 0 && components.every((id) => initialDelivered.has(id));
  const payoutSolved = obligations.length > 0 && obligations.every((item) => initialFulfilled.has(String(item.obligationId)));
  const allocationSolved = allocation ? allocationWithin(initial, allocation.payer, allocation.assets, 'v2_advanced_initial_allocation_invalid') : true;
  const reserveSolved = reserveWei === undefined || requireReserve(initial, ctx.generation.payerAddress, reserveWei, 'v2_advanced_initial_reserve');
  if (ctx.taskCase.taskId === 'M1' || ctx.taskCase.taskId === 'M2' || ctx.taskCase.taskId === 'H1') return dataSolved;
  if (ctx.taskCase.taskId === 'H2') return payoutSolved && reserveSolved;
  if (ctx.taskCase.taskId === 'U1') return dataSolved && payoutSolved && allocationSolved && reserveSolved;
  // Trade cases require a new, receipt-bound route execution in this task generation.
  return false;
}

function unchangedAllowances(initial: V2State, final: V2State): boolean {
  const key = (item: V2State['allowances'][number]) => `${item.owner}|${item.tokenAssetId}|${lower(item.spender)}`;
  const before = new Map(initial.allowances.map((item) => [key(item), item.amountUnits]));
  const after = new Map(final.allowances.map((item) => [key(item), item.amountUnits]));
  return before.size === after.size && [...before].every(([item, amount]) => after.get(item) === amount);
}
function unchangedNonUsdcParticipantBalances(initial: V2State, final: V2State, payer: string): boolean {
  const key = (item: V2State['balances'][number]) => `${item.account}|${item.assetId}`;
  const before = new Map(initial.balances.map((item) => [key(item), item.amountUnits]));
  const after = new Map(final.balances.map((item) => [key(item), item.amountUnits]));
  if (before.size !== after.size || [...before.keys()].some((item) => !after.has(item))) return false;
  for (const [item, value] of before) {
    const row = initial.balances.find((entry) => key(entry) === item)!;
    const participant = stateAccountMatches(row.account, payer, payer);
    if (!(participant && row.assetId === 'USDC') && after.get(item) !== value) return false;
  }
  return true;
}
function assertActionPlan(ctx: V2ReferenceContext): void {
  const plan = ACTION_PLANS[ctx.taskCase.taskId];
  v2Require(plan && ctx.actions.length === plan.length && ctx.actions.length === ctx.taskCase.referencePath.actionCount
    && ctx.actions.every((action, index) => action.kind === plan[index]), 'v2_advanced_action_plan_mismatch');
  const used = new Set<string>();
  for (let index = 0; index < ctx.actions.length; index += 1) {
    const action = ctx.actions[index]!;
    v2Require(HASH.test(`0x${action.rawResponseSha256}`) && action.operationId.length >= 1,
      'v2_advanced_action_reference_invalid');
    if (action.kind === 'retrieve') {
      const previous = ctx.actions[index - 1];
      v2Require(previous?.kind === 'pay' && previous.operationId === action.operationId,
        'v2_advanced_pay_retrieve_idempotency_mismatch');
      continue;
    }
    v2Require(!used.has(action.operationId), 'v2_advanced_logical_operation_reused');
    used.add(action.operationId);
  }
}
function expectedNativeAmountFromProfile(ctx: V2ReferenceContext): bigint {
  const task = profileTask(ctx);
  if (ctx.taskCase.taskId === 'M4') return uint(task.modes?.[ctx.taskCase.mode]?.exactInputUnits, 'v2_advanced_m4_profile_input_missing');
  if (ctx.taskCase.taskId === 'H3') return uint(task.exactInputUnits, 'v2_advanced_h3_profile_input_missing');
  throw new V2ReferenceError('v2_advanced_trade_profile_input_not_applicable');
}
function expectedH3Route(ctx: V2ReferenceContext, delivered: V2Document): string {
  const objective = obj(ctx.taskCase.objective, 'v2_advanced_h3_objective_missing');
  const routeObjective = obj(objective.routeObjective, 'v2_advanced_h3_route_objective_missing');
  const selectedValue = dataField(delivered.content, String(routeObjective.referenceField), 'v2_advanced_h3_reference_field_missing');
  v2Require(typeof selectedValue === 'string', 'v2_advanced_h3_reference_value_invalid');
  const mapping = arr(routeObjective.expectedRouteByValue, 'v2_advanced_h3_route_mapping_missing')
    .find((item) => item.value === selectedValue);
  v2Require(mapping, 'v2_advanced_h3_reference_route_unmapped', 'unsolvable');
  const routeId = str(mapping.routeId, 'v2_advanced_h3_route_id_missing');
  v2Require(arr(routeObjective.allowedRouteIds, 'v2_advanced_h3_allowed_routes_missing').includes(routeId)
    && arr(objective.permittedRoutes, 'v2_advanced_h3_case_routes_missing').some((item) => item.routeId === routeId),
  'v2_advanced_h3_reference_route_not_permitted');
  return routeId;
}
function allowanceScopeForTrade(ctx: V2ReferenceContext, inputAssetId: string, spender: string): string | undefined {
  const objective = obj(ctx.taskCase.objective, 'v2_advanced_trade_objective_missing');
  if (ctx.taskCase.taskId === 'M4') {
    const scope = arr(objective.initialAllowanceScope, 'v2_advanced_m4_allowance_scope_missing');
    v2Require(scope.length === 1 && scope[0]!.owner === 'participant' && scope[0]!.tokenAssetId === inputAssetId
      && lower(scope[0]!.spender) === lower(spender), 'v2_advanced_m4_allowance_scope_invalid');
    return String(scope[0]!.amountUnits);
  }
  if (ctx.taskCase.taskId === 'U1') {
    const scope = arr(objective.temporarySpenderScope, 'v2_advanced_u1_spender_scope_missing');
    v2Require(scope.length === 1 && scope[0]!.owner === 'participant' && scope[0]!.tokenAssetId === inputAssetId
      && lower(scope[0]!.spender) === lower(spender), 'v2_advanced_u1_spender_scope_invalid');
    return undefined;
  }
  return undefined;
}

/**
 * Verifies an advanced retained reference from its independently loaded raw observations.
 * Capture booleans and amount summaries only identify artifact locations; they do not establish goals.
 */
export async function verifyAdvancedV2ReferenceGoal(ctx: V2ReferenceContext): Promise<V2GoalProof> {
  const taskId = ctx.taskCase.taskId;
  v2Require(Object.prototype.hasOwnProperty.call(ACTION_PLANS, taskId), 'v2_advanced_task_not_supported');
  if (['M2', 'H3', 'U1'].includes(taskId)) v2Require(ctx.taskCase.mode === 'ranked', 'v2_advanced_ranked_only_case_invalid');
  assertActionPlan(ctx);
  const capture = obj(ctx.probe.capture, 'v2_advanced_capture_missing');
  const objective = obj(ctx.taskCase.objective, 'v2_advanced_case_objective_missing');
  const profileSource = ['M1', 'M2', 'H1', 'M4', 'H3', 'U1'].includes(taskId) ? profile(ctx) : undefined;
  void profileSource;

  const payments: PaymentResult[] = [];
  let deliveredComponentIds: string[] = [];
  let fulfilledObligationIds: string[] = [];
  let catalogRead: V2Document | undefined;
  const firstRead = ctx.actions[0]!;
  const isCatalog = firstRead.kind === 'inspect_catalog';
  if (isCatalog) catalogRead = validateCatalogRead(ctx, firstRead).read;

  if (taskId === 'M1') {
    const component = obj(objective.component, 'v2_advanced_m1_component_missing');
    const req = obj(objective.paymentRequirements, 'v2_advanced_m1_payment_requirements_missing');
    const expected = profilePaidSources(ctx)[0]!;
    const sourceIds = arr(component.sourceIds, 'v2_advanced_m1_sources_missing');
    v2Require(sourceIds.length > 0 && sourceIds.every((id) => ctx.policy.permittedProvenanceIds?.includes(id)),
      'v2_advanced_m1_component_source_not_permitted');
    payments.push(validatePaidDelivery(ctx, firstRead, ctx.actions[1]!, ctx.actions[2]!, component,
      { catalog: false, expectedOfferId: String(expected.offerId), expectedAmount: String(expected.amountUsdcUnits),
        requirements: req, permittedSources: arr(ctx.policy.permittedProvenanceIds, 'v2_advanced_provenance_policy_missing').map(String) }));
    deliveredComponentIds = validateComponentGoal(ctx, [component], payments, 'v2_advanced_m1_required_component_missing');
  } else if (taskId === 'M2') {
    const publicRead = catalogRead!;
    const offerId = expectedOfferIdFromRequest(ctx, ctx.actions[1]!);
    const choice = validateM2Selection(ctx, publicRead, objective, offerId);
    const expectedComponentId = newDeliveryIds(ctx, 1, 'v2_advanced_m2')[0]!;
    const resource = arr(publicRead.catalog, 'v2_advanced_m2_catalog_missing').find((item) => item.resourceId === choice.resourceId)!;
    const component = { componentId: expectedComponentId, resourceId: choice.resourceId, validator: choice.validator,
      sourceIds: [String(resource.provenance.classification)] };
    payments.push(validatePaidDelivery(ctx, firstRead, ctx.actions[1]!, ctx.actions[2]!, component,
      { catalog: true, expectedOfferId: offerId, expectedAmount: choice.amount, requirements: choice.requirements,
        permittedSources: arr(ctx.policy.permittedProvenanceIds, 'v2_advanced_provenance_policy_missing').map(String) }));
    deliveredComponentIds = validateComponentGoal(ctx, [component], payments, 'v2_advanced_m2_required_component_missing');
  } else if (taskId === 'H1' || taskId === 'U1') {
    const components = arr(taskId === 'H1' ? objective.requiredComponents : objective.requiredComponents,
      'v2_advanced_required_components_missing').map((item) => obj(item, 'v2_advanced_component_invalid'));
    const expected = profilePaidSources(ctx);
    verifyProfileComponents(ctx, expected, components, `v2_advanced_${taskId.toLowerCase()}_profile_components_mismatch`);
    v2Require(expected.length === components.length, 'v2_advanced_profile_component_count_mismatch');
    const payIndexes = ctx.actions.map((action, index) => action.kind === 'pay' ? index : -1).filter((index) => index >= 0);
    v2Require(payIndexes.length === expected.length, 'v2_advanced_profile_payment_count_mismatch');
    for (const [index, payIndex] of payIndexes.entries()) {
      const configured = expected[index]!;
      const component = componentForResource(components, String(configured.resourceId), 'v2_advanced_component_resource_ambiguous');
      const retrieve = ctx.actions[payIndex + 1];
      v2Require(retrieve?.kind === 'retrieve' && retrieve.operationId === ctx.actions[payIndex]!.operationId,
        'v2_advanced_component_retrieve_pair_missing');
      const amount = String(configured.amountUsdcUnits ?? configured.amountUsdcUnits);
      payments.push(validatePaidDelivery(ctx, firstRead, ctx.actions[payIndex]!, retrieve, component,
        { catalog: true, expectedOfferId: String(configured.offerId), expectedAmount: amount,
          permittedSources: arr(taskId === 'H1' ? objective.permittedSources : ctx.policy.permittedProvenanceIds,
            'v2_advanced_component_permitted_sources_missing').map(String) }));
    }
    deliveredComponentIds = validateComponentGoal(ctx, components, payments, `v2_advanced_${taskId.toLowerCase()}_component_goal_missing`);
  } else if (taskId === 'H3') {
    const component = obj(objective.referenceComponent, 'v2_advanced_h3_reference_component_missing');
    const expected = profilePaidSources(ctx)[0]!;
    v2Require(component.resourceId === expected.resourceId, 'v2_advanced_h3_profile_resource_mismatch');
    const allowedSources = arr(ctx.policy.permittedProvenanceIds, 'v2_advanced_h3_permitted_sources_missing').map(String);
    payments.push(validatePaidDelivery(ctx, firstRead, ctx.actions[1]!, ctx.actions[2]!, component,
      { catalog: false, expectedOfferId: String(expected.offerId), expectedAmount: String(expected.amountUsdcUnits),
        permittedSources: allowedSources }));
    deliveredComponentIds = validateComponentGoal(ctx, [component], payments, 'v2_advanced_h3_reference_delivery_missing');
  }

  if (payments.length > 0) validatePurchaseOperationSet(ctx, ctx.actions.filter((action) => action.kind === 'pay'));
  const native = verifyNativeActions(ctx, ctx.actions);
  const nativeById = new Map(native.map((item) => [item.operationId, item]));
  const nativeByIndex = ctx.actions.map((action) => nativeById.get(action.operationId)).filter((item): item is NativeResult => item !== undefined);
  let trade: TradeResult | undefined;
  let quoteMinimum: bigint | undefined;
  let routeId: string | undefined;
  let reserveWei: string | undefined;
  let allowanceToken: string | undefined;
  let allowanceSpender: string | undefined;
  let initialAllowance: string | undefined;
  let obligations: V2Document[] = [];

  if (taskId === 'H2') {
    obligations = arr(objective.obligations, 'v2_advanced_h2_obligations_missing').map((item) => obj(item, 'v2_advanced_h2_obligation_invalid'));
    fulfilledObligationIds = validateTransferActions(ctx, nativeByIndex, obligations);
    reserveWei = String(objective.nativeReserveWei);
  } else if (taskId === 'M4') {
    const expectedInput = expectedNativeAmountFromProfile(ctx);
    const quoteSummary = obj(capture.quote, 'v2_advanced_m4_quote_missing');
    const inputAssetId = str(objective.inputAssetId, 'v2_advanced_m4_input_asset_missing');
    const outputAssetId = str(objective.outputAssetId, 'v2_advanced_m4_output_asset_missing');
    v2Require(inputAssetId === 'WETH' && outputAssetId === 'USDC'
      && uint(objective.exactInputUnits, 'v2_advanced_m4_input_invalid') === expectedInput,
    'v2_advanced_m4_profile_objective_mismatch');
    const quote = validatePlanningQuote(ctx, quoteSummary,
      { inputAssetId, outputAssetId, amountIn: expectedInput.toString(), feeTier: 3000, slippageBps: 1000 });
    quoteMinimum = quote.minimumOutput;
    v2Require(quote.minimumOutput === uint(objective.minimumOutputUnits, 'v2_advanced_m4_minimum_output_invalid'),
      'v2_advanced_m4_release_minimum_mismatch');
    const swap = nativeByIndex[2]!;
    routeId = routeBySelection(ctx, objective, inputAssetId, outputAssetId, 3000, quote.poolAddress);
    validateWrap(ctx, nativeByIndex[0]!, expectedInput);
    const routerAddress = String(ctx.manifest.contracts?.[objective.permittedRoutes.find((item: V2Document) => item.routeId === routeId)?.routerContractId]?.address);
    allowanceToken = inputAssetId; allowanceSpender = routerAddress;
    initialAllowance = allowanceScopeForTrade(ctx, inputAssetId, routerAddress);
    validateApproval(ctx, nativeByIndex[1]!, inputAssetId, routerAddress, expectedInput);
    trade = validateTrade(ctx, swap, objective, { inputAssetId, outputAssetId, amountIn: expectedInput,
      minimumOutput: uint(objective.minimumOutputUnits, 'v2_advanced_m4_minimum_output_invalid'), expectedRouteId: routeId });
    v2Require(uint(trade.selected.amountOutMinimumUnits, 'v2_advanced_m4_tx_minimum_invalid') === quote.minimumOutput,
      'v2_advanced_m4_tx_not_bound_to_quote');
    reserveWei = String(objective.nativeReserveWei);
  } else if (taskId === 'H3') {
    const taskProfile = profileTask(ctx);
    const expectedInput = uint(taskProfile.exactInputUnits, 'v2_advanced_h3_profile_input_invalid');
    v2Require(objective.inputAssetId === 'WETH' && (objective.outputAssetId === undefined || objective.outputAssetId === 'USDC')
      && uint(objective.exactInputUnits, 'v2_advanced_h3_input_invalid') === expectedInput,
    'v2_advanced_h3_profile_objective_mismatch');
    const quotePlanning = obj(capture.quotePlanning, 'v2_advanced_h3_quote_planning_missing');
    const quotes = new Map<number, ReturnType<typeof validatePlanningQuote>>();
    for (const fee of [500, 3000]) {
      const quote = validatePlanningQuote(ctx, quotePlanning[`fee${fee}`],
        { inputAssetId: 'WETH', outputAssetId: 'USDC', amountIn: expectedInput.toString(), feeTier: fee, slippageBps: 1000 });
      quotes.set(fee, quote);
    }
    const delivered = actionBody(ctx, ctx.actions[2]!);
    const deliveredParsed = responseHashFromBytes(String(delivered.contentBytes), String(delivered.contentHash),
      'v2_advanced_h3_delivered_bytes_invalid').parsed;
    routeId = expectedH3Route(ctx, deliveredParsed);
    const selectedRoute = arr(objective.permittedRoutes, 'v2_advanced_h3_routes_missing')
      .find((item) => item.routeId === routeId);
    v2Require(selectedRoute, 'v2_advanced_h3_selected_route_missing');
    const quote = quotes.get(Number(selectedRoute.feeTier));
    v2Require(quote && quote.minimumOutput === uint(objective.minimumOutputUnits, 'v2_advanced_h3_minimum_output_invalid'),
      'v2_advanced_h3_release_minimum_mismatch');
    quoteMinimum = quote.minimumOutput;
    validateWrap(ctx, nativeByIndex[0]!, expectedInput);
    const routerAddress = String(ctx.manifest.contracts?.[selectedRoute.routerContractId]?.address);
    allowanceToken = 'WETH'; allowanceSpender = routerAddress;
    validateApproval(ctx, nativeByIndex[1]!, 'WETH', routerAddress, expectedInput);
    trade = validateTrade(ctx, nativeByIndex[2]!, objective, { inputAssetId: 'WETH', outputAssetId: 'USDC',
      amountIn: expectedInput, minimumOutput: uint(objective.minimumOutputUnits, 'v2_advanced_h3_minimum_output_invalid'), expectedRouteId: routeId });
    v2Require(trade.feeTier === Number(selectedRoute.feeTier)
      && uint(trade.selected.amountOutMinimumUnits, 'v2_advanced_h3_tx_minimum_invalid') === quote.minimumOutput,
    'v2_advanced_h3_trade_not_bound_to_reference_quote');
    const paymentBlock = payments[0]!.block, wrapBlock = nativeByIndex[0]!.block;
    v2Require(BigInt(paymentBlock.number) < BigInt(wrapBlock.number), 'v2_advanced_h3_trade_not_after_paid_reference');
    reserveWei = String(objective.nativeReserveWei);
  } else if (taskId === 'U1') {
    const plan = validateU1Planning(ctx, capture, objective);
    const payouts = arr(objective.payoutObligations, 'v2_advanced_u1_payouts_missing').map((item) => obj(item, 'v2_advanced_u1_payout_invalid'));
    fulfilledObligationIds = validateTransferActions(ctx, nativeByIndex.slice(0, 2), payouts);
    const inputAssetId = 'USDC', outputAssetId = 'WETH';
    const routeIdFromInput = routeBySelection(ctx, objective, inputAssetId, outputAssetId, 3000,
      String(nativeByIndex[3]!.selected.poolAddress));
    v2Require(routeIdFromInput === plan.routeId, 'v2_advanced_u1_actual_route_differs_from_plan');
    const route = arr(objective.permittedRoutes, 'v2_advanced_u1_routes_missing').find((item) => item.routeId === plan.routeId);
    v2Require(route, 'v2_advanced_u1_route_missing');
    allowanceToken = inputAssetId; allowanceSpender = String(ctx.manifest.contracts?.[route.routerContractId]?.address);
    initialAllowance = allowanceScopeForTrade(ctx, inputAssetId, allowanceSpender);
    validateApproval(ctx, nativeByIndex[2]!, inputAssetId, allowanceSpender, plan.amountIn);
    trade = validateTrade(ctx, nativeByIndex[3]!, objective, { inputAssetId, outputAssetId, amountIn: plan.amountIn,
      minimumOutput: plan.minimumOutput, expectedRouteId: plan.routeId });
    v2Require(trade.outputAmount >= plan.minimumOutput
      && uint(trade.selected.amountOutMinimumUnits, 'v2_advanced_u1_tx_minimum_invalid') === plan.minimumOutput,
    'v2_advanced_u1_trade_not_bound_to_plan');
    validateUnwrap(ctx, nativeByIndex[4]!, trade.outputAmount);
    reserveWei = String(objective.nativeReserveWei);
    v2Require(String(objective.nativeReserveWei) === String(sourceProfileU1Reserve(ctx)), 'v2_advanced_u1_reserve_profile_mismatch');
  }

  const initialBlock = initialLocator(ctx, capture), finalBlock = finalLocator(ctx, capture);
  const initialRpcBlock = ctx.block(initialBlock), finalRpcBlock = ctx.block(finalBlock);
  v2Require(BigInt(initialBlock.number) < BigInt(finalBlock.number)
    && lower(initialRpcBlock.hash) === initialBlock.hash && lower(finalRpcBlock.hash) === finalBlock.hash,
  'v2_advanced_cutoff_block_order_invalid');
  const actionBlocks: V2Block[] = [];
  for (const action of ctx.actions) {
    const payment = payments.find((item) => item.transactionHash === lower(actionBody(ctx, action).payment?.transactionHash));
    if (action.kind === 'pay' && payment) actionBlocks.push(payment.block);
    else if (!['inspect_offer', 'inspect_catalog', 'retrieve', 'pay'].includes(action.kind)) {
      const nativeAction = nativeById.get(action.operationId);
      if (nativeAction) actionBlocks.push(nativeAction.block);
    }
  }
  v2Require(actionBlocks.length > 0 && BigInt(actionBlocks[0]!.number) > BigInt(initialBlock.number)
    && actionBlocks.every((item, index) => index === 0 || BigInt(item.number) >= BigInt(actionBlocks[index - 1]!.number))
    && BigInt(finalBlock.number) >= BigInt(actionBlocks.at(-1)!.number), 'v2_advanced_action_cutoff_order_invalid');

  // The exact final identifier sets are derived only from successfully joined raw deliveries/transfers.
  verifyFinalIdentifiers(ctx, deliveredComponentIds, fulfilledObligationIds);
  const { stateSha256: _ignoredInitialHash, ...initialShape } = ctx.taskCase.initialState;
  const finalShape = obj(ctx.envelope.finalState, 'v2_advanced_final_state_shape_missing') as V2State;
  const initial = ctx.stateAt(initialShape, initialBlock, initialShape.deliveredComponentIds, initialShape.fulfilledObligationIds);
  const final = ctx.stateAt(finalShape, finalBlock, [...initial.deliveredComponentIds, ...deliveredComponentIds],
    [...initial.fulfilledObligationIds, ...fulfilledObligationIds]);
  const initiallySolved = solvencyForInitial(ctx, initial, deliveredComponentIds, fulfilledObligationIds,
    taskId === 'U1' ? { assets: arr(objective.allocationAssets, 'v2_advanced_u1_assets_missing'), payer: ctx.generation.payerAddress } : undefined,
    reserveWei);
  if (initiallySolved) throw new V2ReferenceError('v2_advanced_initial_objective_satisfied', 'initially_solved');

  if (taskId === 'H2' || taskId === 'U1') {
    const requiredPayouts = taskId === 'H2' ? obligations : arr(objective.payoutObligations, 'v2_advanced_u1_payouts_missing');
    const ids = verifyPayoutBalances(initial, final, requiredPayouts, ctx.generation.payerAddress);
    v2Require(sameSet(ids, fulfilledObligationIds), 'v2_advanced_payout_delta_set_mismatch');
  }
  if (taskId === 'M1' || taskId === 'M2' || taskId === 'H1') {
    const spend = payments.reduce((sum, item) => sum + item.amount, 0n);
    const before = stateBalance(initial, 'participant', 'USDC', 'v2_advanced_initial_usdc_missing', ctx.generation.payerAddress);
    const after = stateBalance(final, 'participant', 'USDC', 'v2_advanced_final_usdc_missing', ctx.generation.payerAddress);
    v2Require(before >= spend && after === before - spend && unchangedNonUsdcParticipantBalances(initial, final, ctx.generation.payerAddress)
      && unchangedAllowances(initial, final), 'v2_advanced_paid_data_state_effect_invalid');
  }
  if (taskId === 'H2') {
    const spend = obligations.reduce((sum, item) => sum + uint(item.exactAmountUnits, 'v2_advanced_h2_obligation_amount_invalid'), 0n);
    const before = stateBalance(initial, 'participant', 'USDC', 'v2_advanced_h2_initial_usdc_missing', ctx.generation.payerAddress);
    const after = stateBalance(final, 'participant', 'USDC', 'v2_advanced_h2_final_usdc_missing', ctx.generation.payerAddress);
    v2Require(before >= spend && after === before - spend, 'v2_advanced_h2_payer_delta_invalid');
    reserveWei = String(objective.nativeReserveWei);
  }
  if (taskId === 'M4' || taskId === 'H3' || taskId === 'U1') {
    const inputAssetId = taskId === 'U1' ? 'USDC' : String(objective.inputAssetId);
    const initialInput = stateBalance(initial, 'participant', inputAssetId, 'v2_advanced_initial_swap_input_missing', ctx.generation.payerAddress);
    if (taskId === 'M4' || taskId === 'H3') v2Require(initialInput === 0n, 'v2_advanced_reverse_swap_initial_weth_not_zero');
    if (taskId === 'U1') v2Require(initialInput >= (trade?.inputAmount ?? 0n), 'v2_advanced_u1_initial_usdc_below_swap_input');
    const outputAssetId = taskId === 'H3' ? 'USDC' : taskId === 'U1' ? 'USDC' : String(objective.outputAssetId);
    const initialOutput = stateBalance(initial, 'participant', outputAssetId, 'v2_advanced_initial_swap_output_missing', ctx.generation.payerAddress);
    const finalOutput = stateBalance(final, 'participant', outputAssetId, 'v2_advanced_final_swap_output_missing', ctx.generation.payerAddress);
    if (taskId === 'M4' || taskId === 'H3') {
      const service = payments.reduce((sum, item) => sum + item.amount, 0n);
      v2Require(finalOutput === initialOutput - service + (trade?.outputAmount ?? 0n), 'v2_advanced_reverse_swap_output_delta_invalid');
    }
    if (taskId === 'U1') {
      const service = payments.reduce((sum, item) => sum + item.amount, 0n);
      const payout = arr(objective.payoutObligations, 'v2_advanced_u1_payouts_missing')
        .reduce((sum, item) => sum + uint(item.exactAmountUnits, 'v2_advanced_u1_payout_amount_invalid'), 0n);
      v2Require(finalOutput === initialOutput - service - payout - (trade?.inputAmount ?? 0n),
        'v2_advanced_u1_usdc_principal_delta_invalid');
    }
    const outputWeth = stateBalance(final, 'participant', 'WETH', 'v2_advanced_final_weth_missing', ctx.generation.payerAddress);
    if (taskId === 'M4' || taskId === 'H3' || taskId === 'U1') v2Require(outputWeth === 0n, 'v2_advanced_final_weth_not_zero');
    if (allowanceToken && allowanceSpender) verifyAllowanceCleanup(ctx, initial, final, allowanceToken, allowanceSpender, initialAllowance);
  }
  if (taskId === 'U1') {
    const assets = arr(objective.allocationAssets, 'v2_advanced_u1_assets_missing');
    const rate = obj(ctx.manifest.feePolicy, 'v2_advanced_u1_rate_missing');
    for (const asset of assets) {
      const ratio = obj(asset.usdcBaseUnitsPerAssetBaseUnit, 'v2_advanced_u1_asset_ratio_missing');
      const expected = asset.assetId === 'USDC' ? { numerator: '1', denominator: '1' }
        : { numerator: String(rate.ethUsdcRateNumerator), denominator: String(rate.ethUsdcRateDenominator) };
      requireEqual(ratio, expected, 'v2_advanced_u1_allocation_conversion_mismatch');
    }
  }

  const cost = verifiedCost(ctx, payments, native, trade);
  const budgetValue = taskId === 'H3' ? objective.combinedExpenseBudgetUsdcUnits : objective.expenseBudgetUsdcUnits;
  const budget = uint(budgetValue, 'v2_advanced_expense_budget_missing');
  const solvable = cost.total <= budget && (reserveWei === undefined || requireReserve(final, ctx.generation.payerAddress, reserveWei, 'v2_advanced_final_reserve'))
    && (taskId !== 'U1' || allocationWithin(final, ctx.generation.payerAddress,
      arr(objective.allocationAssets, 'v2_advanced_u1_assets_missing'), 'v2_advanced_u1_final_allocation_invalid'));
  if (taskId === 'U1' && trade) v2Require(cost.gasWei <= uint(profileTask(ctx).planning.maximumParticipantGasWei,
    'v2_advanced_u1_gas_cap_invalid'), 'v2_advanced_u1_actual_gas_exceeds_plan');
  return { initialBlock, finalBlock, deliveredComponentIds: [...deliveredComponentIds],
    fulfilledObligationIds: [...fulfilledObligationIds], initiallySolved: false, solvable };
}

function sourceProfileU1Reserve(ctx: V2ReferenceContext): string {
  const objective = obj(ctx.taskCase.objective, 'v2_advanced_u1_objective_missing');
  return str(ctx.policy.nativeReserveWei?.U1 ?? objective.nativeReserveWei,
    'v2_advanced_u1_profile_reserve_missing');
}

function planningRpc(ctx: V2ReferenceContext, envId: string, method: string,
  matches: (document: V2Document) => boolean, code: string): V2Document {
  const documents = allDocuments(ctx, (item) => item.schemaVersion === 'bef-rpc-observation/v1'
    && item.method === method && item.boundary === 'local-chain-readonly-proxy'
    && item.endpointBoundary === 'local-chain-readonly-proxy' && lower(item.environmentId) === lower(envId) && matches(item));
  v2Require(documents.length > 0, code, 'unavailable');
  const first = documents[0]!.value;
  v2Require(documents.every((doc) => same(doc.value.result, first.result)), 'v2_advanced_planning_rpc_contradiction');
  return first;
}
function rpcAtPlanningBlock(ctx: V2ReferenceContext, envId: string, method: string, params: unknown[], block: V2Block,
  code: string): bigint {
  const tag = `0x${BigInt(block.number).toString(16)}`;
  const rpc = planningRpc(ctx, envId, method, (doc) => Array.isArray(doc.params)
    && params.every((expected, index) => ADDRESS.test(String(expected))
      ? lower(doc.params[index]) === lower(expected) : same(doc.params[index], expected))
    && lower(doc.params?.[params.length]) === tag, code);
  const raw = str(rpc.result, code);
  v2Require(/^0x(?:0|[1-9a-f][0-9a-f]*)$/i.test(raw), code);
  return BigInt(raw);
}
function planningAssetCall(ctx: V2ReferenceContext, envId: string, token: string, data: string, block: V2Block, code: string): bigint {
  const tag = `0x${BigInt(block.number).toString(16)}`;
  const rpc = planningRpc(ctx, envId, 'eth_call', (doc) => lower(doc.params?.[0]?.to) === lower(token)
    && lower(doc.params?.[0]?.data) === lower(data) && lower(doc.params?.[1]) === tag, code);
  const raw = str(rpc.result, code);
  v2Require(/^0x[0-9a-f]{64}$/i.test(raw), code);
  return BigInt(raw);
}
function addressWord(address: string, code: string): string {
  v2Require(ADDRESS.test(address), code); return address.slice(2).toLowerCase().padStart(64, '0');
}
function validateU1Planning(ctx: V2ReferenceContext, capture: V2Document, objective: V2Document):
  { amountIn: bigint; minimumOutput: bigint; maximumGasWei: bigint; amountOut: bigint; block: V2Block; routeId: string } {
  const source = profile(ctx);
  const sourceTask = obj(source.tasks?.U1, 'v2_advanced_u1_profile_missing');
  const profileRef = obj(ctx.probe.difficultyProfile, 'v2_advanced_u1_profile_ref_missing');
  const plan = checkedArtifact(ctx, { path: capture.planning?.planPath, sha256: capture.planning?.planSha256 }, 'v2_advanced_u1_plan');
  const quoteSummary = obj(plan.quote, 'v2_advanced_u1_plan_quote_missing');
  const quoteResponse = obj(quoteSummary.response, 'v2_advanced_u1_public_quote_missing');
  const rawQuote = checkedArtifact(ctx, { path: quoteSummary.rawResponsePath, sha256: quoteSummary.rawResponseSha256 },
    'v2_advanced_u1_raw_public_quote');
  const taskPlanning = obj(sourceTask.planning, 'v2_advanced_u1_planning_profile_missing');
  const amountIn = uint(taskPlanning.exactInputUsdcUnits, 'v2_advanced_u1_profile_input_invalid');
  const feeTier = Number(taskPlanning.feeTier), slippageBps = Number(taskPlanning.slippageBps);
  const maximumGasWei = uint(taskPlanning.maximumParticipantGasWei, 'v2_advanced_u1_gas_cap_invalid');
  const amountOut = uint(quoteResponse.quote?.amountOutUnits, 'v2_advanced_u1_quote_output_invalid');
  const minimumOutput = amountOut * BigInt(10000 - slippageBps) / 10000n;
  const planningGeneration = obj(plan.planningGeneration, 'v2_advanced_u1_planning_generation_missing');
  const generationId = str(planningGeneration.generationId, 'v2_advanced_u1_planning_generation_missing');
  const envId = str(planningGeneration.envId, 'v2_advanced_u1_planning_env_missing');
  const initial = obj(plan.initialState, 'v2_advanced_u1_plan_initial_state_missing');
  const initialBlock = blockLocator(initial, 'v2_advanced_u1_plan_initial_block_missing');
  const initialPayer = str(initial.payerAddress, 'v2_advanced_u1_plan_payer_missing');
  const usdc = assetAddress(ctx, 'USDC', 'v2_advanced_u1_usdc_asset_missing');
  const weth = assetAddress(ctx, 'WETH', 'v2_advanced_u1_weth_asset_missing');
  const router = obj(ctx.manifest.contracts?.swapRouter02, 'v2_advanced_u1_router_missing');
  const usdcAmount = planningAssetCall(ctx, envId, usdc, `0x70a08231${addressWord(initialPayer, 'v2_advanced_u1_payer_invalid')}`,
    initialBlock, 'v2_advanced_u1_initial_usdc_rpc_missing');
  const wethAmount = planningAssetCall(ctx, envId, weth, `0x70a08231${addressWord(initialPayer, 'v2_advanced_u1_payer_invalid')}`,
    initialBlock, 'v2_advanced_u1_initial_weth_rpc_missing');
  const nativeWei = rpcAtPlanningBlock(ctx, envId, 'eth_getBalance', [initialPayer], initialBlock, 'v2_advanced_u1_initial_native_rpc_missing');
  const usdcAllowance = planningAssetCall(ctx, envId, usdc,
    `0xdd62ed3e${addressWord(initialPayer, 'v2_advanced_u1_payer_invalid')}${addressWord(String(router.address), 'v2_advanced_u1_router_invalid')}`,
    initialBlock, 'v2_advanced_u1_initial_usdc_allowance_rpc_missing');
  const wethAllowance = planningAssetCall(ctx, envId, weth,
    `0xdd62ed3e${addressWord(initialPayer, 'v2_advanced_u1_payer_invalid')}${addressWord(String(router.address), 'v2_advanced_u1_router_invalid')}`,
    initialBlock, 'v2_advanced_u1_initial_weth_allowance_rpc_missing');
  v2Require(generationId !== ctx.generation.generationId && plan.schemaVersion === 'bts-u1-difficulty-v2-pre-action-plan/v1'
    && plan.classification === 'fresh_local_pre_execution_plan_not_release_or_execution_proof'
    && plan.profileSha256 === profileRef.sourceSha256 && plan.manifestSha256 === ctx.identity.environmentManifestSha256
    && profileRef.sourcePath === plan.profilePath && quoteResponse.generationId === generationId
    && quoteResponse.envId === envId && quoteResponse.boundary === 'local-chain-readonly-proxy'
    && quoteResponse.quoteStatus === 'observed' && quoteResponse.inputAssetId === 'USDC' && quoteResponse.outputAssetId === 'WETH'
    && String(quoteResponse.requestedAmountInUnits) === amountIn.toString() && Number(quoteResponse.fee) === feeTier
    && uint(rawQuote.quote?.amountOutUnits, 'v2_advanced_u1_raw_quote_output_invalid') === amountOut
    && same(rawQuote, quoteResponse) && uint(initial.payerUsdcUnits, 'v2_advanced_u1_summary_initial_usdc_invalid') === usdcAmount
    && uint(initial.payerWethUnits, 'v2_advanced_u1_summary_initial_weth_invalid') === wethAmount
    && uint(initial.payerNativeWei, 'v2_advanced_u1_summary_initial_native_invalid') === nativeWei
    && uint(initial.usdcAllowanceUnits, 'v2_advanced_u1_summary_initial_usdc_allowance_invalid') === usdcAllowance
    && uint(initial.wethAllowanceUnits, 'v2_advanced_u1_summary_initial_weth_allowance_invalid') === wethAllowance
    && usdcAmount === 100000000n && wethAmount === 0n && usdcAllowance === 0n && wethAllowance === 0n
    && feeTier === 3000 && slippageBps === 1000 && maximumGasWei === 6000000000000n
    && uint(plan.plan?.plannedInput?.swapInputUsdcUnits, 'v2_advanced_u1_plan_input_invalid') === amountIn
    && uint(plan.plan?.plannedInput?.maximumParticipantGasWei, 'v2_advanced_u1_plan_gas_invalid') === maximumGasWei
    && uint(plan.plan?.plannedInput?.minimumNativeOutputWei, 'v2_advanced_u1_plan_minimum_invalid') === minimumOutput
    && uint(plan.plan?.plannedInput?.quotedNativeOutputWei, 'v2_advanced_u1_plan_quote_output_invalid') === amountOut,
  'v2_advanced_u1_plan_inputs_not_derived');
  const publicHttp = allDocuments(ctx, (item) => item.schemaVersion === 'bef-http-observation/v1'
    && item.request?.method === 'GET' && String(item.request?.path).includes('/quote?')
    && lower(header(item.request?.headers, 'X-BEF-Generation')) === lower(generationId)
    && item.response?.status === 200 && same(item.response?.body, quoteResponse));
  v2Require(publicHttp.length === 1 && rawQuote.generationId === generationId,
    'v2_advanced_u1_public_quote_http_missing', 'unavailable');
  const qData = str(quoteSummary.quoteData, 'v2_advanced_u1_quoter_calldata_missing');
  const quoter = obj(ctx.manifest.contracts?.quoterV2, 'v2_advanced_u1_quoter_missing');
  const call = planningRpc(ctx, envId, 'eth_call', (doc) => lower(doc.params?.[0]?.to) === lower(quoter.address)
    && lower(doc.params?.[0]?.data) === lower(qData) && lower(doc.params?.[1]) === `0x${BigInt(initialBlock.number).toString(16)}`
    && doc.result === quoteSummary.independentResult, 'v2_advanced_u1_independent_quote_rpc_missing');
  const decodedInput = wordUint(qData, 2, 'v2_advanced_u1_quoter_input_invalid');
  const decodedFee = Number(wordUint(qData, 3, 'v2_advanced_u1_quoter_fee_invalid'));
  const decodedTokenIn = wordAddress(qData, 0, 'v2_advanced_u1_quoter_token_in_invalid');
  const decodedTokenOut = wordAddress(qData, 1, 'v2_advanced_u1_quoter_token_out_invalid');
  const responseOut = quoteOutputFromHex(call.result);
  v2Require(qData.slice(0, 10).toLowerCase() === '0xc6a5026a' && decodedTokenIn.toLowerCase() === usdc.toLowerCase()
    && decodedTokenOut.toLowerCase() === weth.toLowerCase() && decodedInput === amountIn && decodedFee === feeTier
    && responseOut === amountOut && uint(quoteSummary.quotedOutputWei, 'v2_advanced_u1_quote_summary_output_invalid') === amountOut
    && uint(quoteSummary.minimumOutputWei, 'v2_advanced_u1_quote_summary_minimum_invalid') === minimumOutput
    && uint(quoteSummary.quoteBlockNumber, 'v2_advanced_u1_quote_block_invalid') === BigInt(initialBlock.number)
    && lower(quoteSummary.quoteBlockHash) === initialBlock.hash, 'v2_advanced_u1_quote_independent_check_failed');
  const blockRpc = planningRpc(ctx, envId, 'eth_getBlockByNumber', (doc) =>
    uint(doc.result?.number, 'v2_advanced_u1_quote_block_invalid') === BigInt(initialBlock.number)
    && lower(doc.result?.hash) === initialBlock.hash, 'v2_advanced_u1_quote_block_rpc_missing');
  void blockRpc;
  validatePlanningFence(ctx, planningGeneration, publicHttp[0]!.order);
  const planAssets = arr(plan.plan?.allocationAssets, 'v2_advanced_u1_plan_assets_missing');
  const objectiveAssets = arr(objective.allocationAssets, 'v2_advanced_u1_objective_assets_missing');
  const profileAssets = arr(sourceTask.allocationAssets, 'v2_advanced_u1_profile_assets_missing');
  v2Require(planAssets.length === 3 && objectiveAssets.length === 3 && profileAssets.length === 3,
    'v2_advanced_u1_asset_count_invalid');
  for (const assetId of ['USDC', 'ETH', 'WETH']) {
    const objectiveAsset = objectiveAssets.find((item) => item.assetId === assetId);
    const planAsset = planAssets.find((item) => item.assetId === assetId);
    const profileTarget = sourceTask.targetSharesBps?.[assetId];
    const profileTolerance = sourceTask.assetToleranceBps?.[assetId];
    v2Require(objectiveAsset && planAsset && Number(objectiveAsset.targetShareBps) === Number(profileTarget)
      && Number(objectiveAsset.toleranceBps) === Number(profileTolerance)
      && Number(planAsset.targetShareBps) === Number(profileTarget) && Number(planAsset.toleranceBps) === Number(profileTolerance),
    'v2_advanced_u1_allocation_contract_mismatch');
  }
  const obligations = arr(objective.payoutObligations, 'v2_advanced_u1_obligations_missing');
  const profileObligations = arr(sourceTask.obligations, 'v2_advanced_u1_profile_obligations_missing');
  v2Require(obligations.length === 2 && profileObligations.length === 2 && obligations.every((item, index) => {
    const expected = profileObligations[index];
    return item.obligationId === expected.obligationId && lower(item.recipient) === lower(expected.recipient)
      && item.assetId === 'USDC' && String(item.exactAmountUnits) === String(expected.amountUsdcUnits);
  }), 'v2_advanced_u1_profile_obligations_mismatch');
  const components = arr(objective.requiredComponents, 'v2_advanced_u1_components_missing');
  const profileComponents = arr(sourceTask.components, 'v2_advanced_u1_profile_components_missing');
  verifyProfileComponents(ctx, profileComponents, components, 'v2_advanced_u1_profile_components_mismatch');
  const serviceCharge = profileComponents.reduce((sum, component) => sum + uint(component.amountUsdcUnits, 'v2_advanced_u1_service_charge_invalid'), 0n);
  const payoutUnits = obligations.reduce((sum, obligation) => sum + uint(obligation.exactAmountUnits, 'v2_advanced_u1_payout_amount_invalid'), 0n);
  const initialUsdc = usdcAmount, initialEth = nativeWei;
  const finalUsdc = initialUsdc - serviceCharge - payoutUnits - amountIn;
  const minimumEth = initialEth - maximumGasWei + minimumOutput;
  const maximumEth = initialEth + amountOut;
  v2Require(finalUsdc > 0n && uint(plan.plan?.projectedBounds?.finalUsdcUnits, 'v2_advanced_u1_projected_usdc_invalid') === finalUsdc
    && uint(plan.plan?.projectedBounds?.minimumNativeWei, 'v2_advanced_u1_projected_min_native_invalid') === minimumEth
    && uint(plan.plan?.projectedBounds?.maximumNativeWei, 'v2_advanced_u1_projected_max_native_invalid') === maximumEth,
  'v2_advanced_u1_projection_bounds_invalid');
  const rational = ctx.manifest.feePolicy;
  const rate = { numerator: String(rational.ethUsdcRateNumerator), denominator: String(rational.ethUsdcRateDenominator) };
  const projectedState = (native: bigint): V2State => ({ balances: [
    { account: 'participant', assetId: 'USDC', amountUnits: finalUsdc.toString() },
    { account: 'participant', assetId: 'ETH', amountUnits: native.toString() },
    { account: 'participant', assetId: 'WETH', amountUnits: '0' },
  ], allowances: [], deliveredComponentIds: [], fulfilledObligationIds: [] });
  const projectedAssets = objectiveAssets.map((asset) => ({ ...asset, usdcBaseUnitsPerAssetBaseUnit: asset.assetId === 'USDC'
    ? { numerator: '1', denominator: '1' } : rate }));
  v2Require(allocationWithin(projectedState(minimumEth), ctx.generation.payerAddress, projectedAssets, 'v2_advanced_u1_min_bound_allocation_invalid')
    && allocationWithin(projectedState(maximumEth), ctx.generation.payerAddress, projectedAssets, 'v2_advanced_u1_max_bound_allocation_invalid'),
  'v2_advanced_u1_plan_does_not_prove_fixed_target');
  const selectedRoute = routeBySelection(ctx, objective, 'USDC', 'WETH', feeTier, String(quoteResponse.poolAddress));
  return { amountIn, minimumOutput, maximumGasWei, amountOut, block: initialBlock, routeId: selectedRoute };
}
