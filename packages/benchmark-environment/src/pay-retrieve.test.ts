import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import test from 'node:test';
import Fastify from 'fastify';
import { ensureSchema, insertOperation, poolFor, runTokenHash, sha256, verifySchema } from './db.js';
import type { ApplicationRuntime, RuntimeEnvironment } from './runtime.js';
import type { RuntimeManifest } from './manifest.js';
import type { ResourceBytes } from './resource.js';
import type { PaymentProtocol } from './protocol.js';
import { registerToolRoutes } from './tools.js';
import {
  AcceptedPaymentTermsSchema,
  PayRequestSchema,
  paidReceipt,
  responseSha256,
  sameAcceptedPaymentTerms,
  verifyInspectionRead,
} from './pay-retrieve.js';

const validPayRequest = {
  resourceId: 'bef-resource-v1',
  offerId: 'canonical',
  readHandle: { kind: 'catalog' as const, operationId: 'c5b9e650-2193-43c2-87bd-2d99fe83a6d8' },
  acceptedTerms: {
    scheme: 'exact',
    network: 'eip155:8453',
    asset: '0x1111111111111111111111111111111111111111',
    amount: '100000',
    payTo: '0x2222222222222222222222222222222222222222',
    transferMethod: 'eip3009',
  },
};

test('pay request rejects caller-supplied delivery bytes and incomplete or changed payment terms', () => {
  assert.equal(PayRequestSchema.safeParse(validPayRequest).success, true);
  assert.equal(PayRequestSchema.safeParse({ ...validPayRequest, contentBytes: 'ZXZpbA==' }).success, false);
  assert.equal(PayRequestSchema.safeParse({ ...validPayRequest, resourceSha256: 'a'.repeat(64) }).success, false);
  assert.equal(AcceptedPaymentTermsSchema.safeParse({ ...validPayRequest.acceptedTerms, amount: '0' }).success, false);
  assert.equal(sameAcceptedPaymentTerms(validPayRequest.acceptedTerms, {
    ...validPayRequest.acceptedTerms,
    asset: validPayRequest.acceptedTerms.asset.toUpperCase().replace('0X', '0x'),
    payTo: validPayRequest.acceptedTerms.payTo.toUpperCase().replace('0X', '0x'),
  }), true);
  assert.equal(sameAcceptedPaymentTerms(validPayRequest.acceptedTerms, {
    ...validPayRequest.acceptedTerms,
    amount: '100001',
  }), false);
});

test('paid receipt contains settlement facts and no delivery payload or hash metadata', () => {
  const receipt = paidReceipt({
    operationId: validPayRequest.readHandle.operationId,
    transactionHash: `0x${'A'.repeat(64)}`,
    amount: '100000',
    asset: validPayRequest.acceptedTerms.asset,
    network: validPayRequest.acceptedTerms.network,
    payTo: validPayRequest.acceptedTerms.payTo,
  });
  assert.deepEqual(Object.keys(receipt).sort(), ['deliveryHandle', 'operationId', 'payment', 'status']);
  assert.equal(receipt.status, 'payment_confirmed');
  assert.equal('content' in receipt, false);
  assert.equal('contentHash' in receipt, false);
  assert.equal('contentBytes' in receipt, false);
  assert.equal('resourceId' in receipt, false);
  assert.equal((receipt.payment as Record<string, unknown>).transactionHash, `0x${'a'.repeat(64)}`);
});

const migrationTestUrl = process.env.BEF_MIGRATION_TEST_DATABASE_URL;

test('PostgreSQL inspection handles bind scope and response hash; pay retries retain one deferred operation without economic rows', {
  skip: !migrationTestUrl ? 'Set BEF_MIGRATION_TEST_DATABASE_URL to a dedicated local PostgreSQL test database.' : false,
}, async () => {
  assert.ok(migrationTestUrl);
  const url = new URL(migrationTestUrl);
  assert.ok(['postgres:', 'postgresql:'].includes(url.protocol));
  assert.ok(['localhost', '127.0.0.1', '::1'].includes(url.hostname.toLowerCase()), 'the test database must be loopback-only');
  const databaseName = decodeURIComponent(url.pathname.replace(/^\/+/, ''));
  assert.match(databaseName, /^bef_migration_test_[a-z0-9_]+$/i, 'the test URL must target a dedicated migration-test database');

  const pool = poolFor(migrationTestUrl);
  const nonce = randomUUID().replaceAll('-', '');
  const envId = `bef-pay-retrieve-${nonce.slice(0, 16)}`;
  const generationId = randomUUID();
  const participantId = `participant-${nonce.slice(0, 16)}`;
  const manifestSha256 = 'a'.repeat(64);
  const payerAddress = '0x1111111111111111111111111111111111111111';
  let inspectionOperationId: string | undefined;
  let paymentOperationId: string | undefined;
  try {
    await ensureSchema(pool);
    await verifySchema(pool);
    await pool.query(
      `INSERT INTO bef_environment(env_id,chain_id,node_identity,manifest_sha256)
       VALUES($1,8453,'private-anvil-fork',$2)`,
      [envId, manifestSha256],
    );
    await pool.query(
      `INSERT INTO bef_generation(generation_id,env_id,participant_id,run_token_sha256,payer_address,resource_variant,
         manifest_sha256,status,expires_at)
       VALUES($1,$2,$3,$4,$5,'canonical',$6,'active',clock_timestamp()+interval '1 hour')`,
      [generationId, envId, participantId, 'b'.repeat(64), payerAddress, manifestSha256],
    );

    const catalogRequest = { method: 'GET', path: '/catalog' };
    const inspection = await insertOperation(pool, {
      envId,
      generationId,
      participantId,
      idempotencyKey: `catalog-${nonce}`,
      requestHash: responseSha256(catalogRequest),
      kind: 'catalog',
    });
    inspectionOperationId = inspection.operationId;
    const catalogResponse = {
      operationId: inspection.operationId,
      readHandle: { kind: 'catalog', operationId: inspection.operationId },
      catalog: [{ resourceId: validPayRequest.resourceId, offers: [{ id: validPayRequest.offerId, payment: validPayRequest.acceptedTerms }] }],
      freeInspection: true,
      deliveryState: 'not_delivered',
    };
    await pool.query(
      `UPDATE bef_operation SET status='accepted',response_sha256=$2 WHERE operation_id=$1`,
      [inspection.operationId, responseSha256(catalogResponse)],
    );

    const validHandle = {
      operationId: inspection.operationId,
      envId,
      generationId,
      participantId,
      manifestSha256,
      kind: 'catalog' as const,
      expectedRequestSha256: responseSha256(catalogRequest),
      expectedResponseSha256: responseSha256(catalogResponse),
    };
    assert.equal(await verifyInspectionRead(pool, validHandle), true);
    assert.equal(await verifyInspectionRead(pool, { ...validHandle, participantId: `foreign-${nonce.slice(0, 8)}` }), false);
    assert.equal(await verifyInspectionRead(pool, { ...validHandle, generationId: randomUUID() }), false);
    assert.equal(await verifyInspectionRead(pool, { ...validHandle, expectedResponseSha256: sha256('altered response') }), false);
    assert.equal(await verifyInspectionRead(pool, { ...validHandle, expectedRequestSha256: sha256('different request') }), false);

    const paymentRequest = { path: '/pay', body: validPayRequest };
    const payRequestHash = responseSha256(paymentRequest);
    const firstPay = await insertOperation(pool, {
      envId,
      generationId,
      participantId,
      idempotencyKey: `pay-${nonce}`,
      requestHash: payRequestHash,
      kind: 'purchase',
      paymentResponseMode: 'deferred_delivery',
    });
    paymentOperationId = firstPay.operationId;
    const retryPay = await insertOperation(pool, {
      envId,
      generationId,
      participantId,
      idempotencyKey: `pay-${nonce}`,
      requestHash: payRequestHash,
      kind: 'purchase',
      paymentResponseMode: 'deferred_delivery',
    });
    assert.equal(firstPay.isNew, true);
    assert.equal(retryPay.isNew, false);
    assert.equal(retryPay.operationId, firstPay.operationId);
    assert.equal(retryPay.paymentResponseMode, 'deferred_delivery');
    const purchaseRequestHash = responseSha256({ path: '/purchase', body: validPayRequest });
    const changedRouteRetry = await insertOperation(pool, {
      envId,
      generationId,
      participantId,
      idempotencyKey: `pay-${nonce}`,
      requestHash: purchaseRequestHash,
      kind: 'purchase',
      paymentResponseMode: 'combined',
    });
    assert.equal(changedRouteRetry.operationId, firstPay.operationId);
    assert.notEqual(purchaseRequestHash, payRequestHash);
    assert.equal(changedRouteRetry.requestHash, payRequestHash);
    assert.equal(changedRouteRetry.paymentResponseMode, 'deferred_delivery');
    await assert.rejects(() => pool.query(
      `UPDATE bef_operation SET payment_response_mode='combined' WHERE operation_id=$1`, [firstPay.operationId],
    ), /payment_response_mode is immutable/);

    const effects = await pool.query<{ operations: string; payments: string; deliveries: string }>(
      `SELECT
         (SELECT count(*)::text FROM bef_operation WHERE env_id=$1 AND generation_id=$2) AS operations,
         (SELECT count(*)::text FROM bef_payment WHERE env_id=$1 AND generation_id=$2) AS payments,
         (SELECT count(*)::text FROM bef_delivery WHERE operation_id=$3) AS deliveries`,
      [envId, generationId, firstPay.operationId],
    );
    assert.deepEqual(effects.rows[0], { operations: '2', payments: '0', deliveries: '0' });
  } finally {
    const operationIds = [inspectionOperationId, paymentOperationId].filter((value): value is string => value !== undefined);
    if (operationIds.length) await pool.query('DELETE FROM bef_operation WHERE operation_id=ANY($1::uuid[])', [operationIds]).catch(() => undefined);
    await pool.query('DELETE FROM bef_generation WHERE env_id=$1', [envId]).catch(() => undefined);
    await pool.query('DELETE FROM bef_environment WHERE env_id=$1', [envId]).catch(() => undefined);
    await pool.end();
  }
});

test('HTTP inspection, /pay idempotency, cross-route conflict, and deferred delivery use durable PostgreSQL state', {
  skip: !migrationTestUrl ? 'Set BEF_MIGRATION_TEST_DATABASE_URL to a dedicated local PostgreSQL test database.' : false,
}, async () => {
  assert.ok(migrationTestUrl);
  const url = new URL(migrationTestUrl);
  assert.ok(['postgres:', 'postgresql:'].includes(url.protocol));
  assert.ok(['localhost', '127.0.0.1', '::1'].includes(url.hostname.toLowerCase()), 'the test database must be loopback-only');
  const databaseName = decodeURIComponent(url.pathname.replace(/^\/+/, ''));
  assert.match(databaseName, /^bef_migration_test_[a-z0-9_]+$/i, 'the test URL must target a dedicated migration-test database');

  const pool = poolFor(migrationTestUrl);
  const nonce = randomUUID().replaceAll('-', '');
  const envId = `bef-pay-retrieve-http-${nonce.slice(0, 12)}`;
  const generationId = randomUUID();
  const participantId = `participant-${nonce.slice(0, 12)}`;
  const token = nonce;
  const manifestSha256 = 'a'.repeat(64);
  const payerAddress = '0x1111111111111111111111111111111111111111';
  const facilitatorAddress = '0x2222222222222222222222222222222222222222';
  const asset = '0x3333333333333333333333333333333333333333';
  const resourceId = 'bef-resource-test';
  const offerId = 'canonical';
  const amount = '100000';
  const network = 'eip155:8453';
  const transferMethod = 'eip3009';
  const resourceBytes = Buffer.from(JSON.stringify({ resourceId, schema: 'pay-retrieve-test/v1', value: 'durable fixture' }));
  const resourceHash = sha256(resourceBytes);
  const resource: ResourceBytes = {
    resourceId,
    contentType: 'application/json',
    schema: 'pay-retrieve-test/v1',
    provenance: { source: 'synthetic test fixture' },
    bytes: resourceBytes,
    hash: resourceHash,
    parsed: JSON.parse(resourceBytes.toString('utf8')) as Record<string, unknown>,
  };
  const offer = { id: offerId, amount };
  const manifest = {
    x402: {
      resourceId,
      resourcePath: 'resources/pay-retrieve-test.json',
      resourceSha256: resourceHash,
      offers: [offer],
      catalog: [{
        resourceId,
        resourcePath: 'resources/pay-retrieve-test.json',
        resourceSha256: resourceHash,
        contentType: resource.contentType,
        dataType: 'test-data',
        schema: resource.schema,
        provenance: resource.provenance,
        offers: [offer],
      }],
      scheme: 'exact',
      network,
      asset,
      assetTransferMethod: transferMethod,
      amount,
    },
  } as unknown as RuntimeManifest;
  const runtimeEnvironment = { id: envId, facilitatorAddress } as unknown as RuntimeEnvironment;
  const runtime = {
    loadedManifest: { sha256: manifestSha256 },
    manifest,
    pool,
    resources: new Map([[resourceId, resource]]),
    resource,
    envs: new Map([[envId, runtimeEnvironment]]),
  } as unknown as ApplicationRuntime;
  const challengePath = `http://localhost/tools/${envId}/pay`;
  let protocolRequestPath = '';
  const protocol = {
    http: {
      processHTTPRequest: async (context: { path?: unknown }) => {
        protocolRequestPath = typeof context.path === 'string' ? context.path : '';
        return {
          type: 'payment-error',
          response: {
            status: 402,
            headers: { 'content-type': 'application/json' },
            body: {
              x402Version: 2,
              resource: { url: challengePath },
              accepts: [{ scheme: 'exact', network, asset, amount, payTo: facilitatorAddress }],
            },
          },
        };
      },
    },
  } as unknown as PaymentProtocol;
  const app = Fastify({ logger: false });
  const operationIds: string[] = [];
  let seededPayment = false;
  let seededObservation = false;
  let seededDelivery = false;
  try {
    await ensureSchema(pool);
    await verifySchema(pool);
    await pool.query(
      `INSERT INTO bef_environment(env_id,chain_id,node_identity,manifest_sha256)
       VALUES($1,8453,'private-anvil-fork',$2)`,
      [envId, manifestSha256],
    );
    await pool.query(
      `INSERT INTO bef_generation(generation_id,env_id,participant_id,run_token_sha256,payer_address,resource_variant,
         manifest_sha256,status,expires_at)
       VALUES($1,$2,$3,$4,$5,'canonical',$6,'active',clock_timestamp()+interval '1 hour')`,
      [generationId, envId, participantId, runTokenHash(token), payerAddress, manifestSha256],
    );
    await registerToolRoutes(app, runtime, new Map([[envId, protocol]]));

    const catalogKey = `catalog-${nonce}`;
    const catalogHeaders = {
      authorization: `Bearer ${token}`,
      'x-bef-generation': generationId,
      'idempotency-key': catalogKey,
    };
    const firstCatalog = await app.inject({ method: 'GET', url: `/tools/${envId}/catalog`, headers: catalogHeaders });
    assert.equal(firstCatalog.statusCode, 200);
    const catalogBody = firstCatalog.json() as { operationId: string; readHandle: { kind: string; operationId: string } };
    operationIds.push(catalogBody.operationId);
    assert.deepEqual(catalogBody.readHandle, { kind: 'catalog', operationId: catalogBody.operationId });
    const catalogReplay = await app.inject({ method: 'GET', url: `/tools/${envId}/catalog`, headers: catalogHeaders });
    assert.equal(catalogReplay.statusCode, 200);
    assert.equal(catalogReplay.json().operationId, catalogBody.operationId);
    const catalogRow = await pool.query<{ operation_kind: string; status: string; response_sha256: string }>(
      `SELECT operation_kind,status,response_sha256 FROM bef_operation WHERE operation_id=$1`, [catalogBody.operationId],
    );
    assert.deepEqual(catalogRow.rows[0], {
      operation_kind: 'catalog', status: 'accepted', response_sha256: responseSha256(catalogBody),
    });

    const offerKey = `offer-${nonce}`;
    const offerResponse = await app.inject({
      method: 'GET',
      url: `/tools/${envId}/offer?resourceId=${resourceId}`,
      headers: { ...catalogHeaders, 'idempotency-key': offerKey },
    });
    assert.equal(offerResponse.statusCode, 200);
    const offerBody = offerResponse.json() as { operationId: string; readHandle: { kind: string; operationId: string } };
    operationIds.push(offerBody.operationId);
    assert.deepEqual(offerBody.readHandle, { kind: 'offer', operationId: offerBody.operationId });
    const offerRow = await pool.query<{ operation_kind: string; status: string; response_sha256: string }>(
      `SELECT operation_kind,status,response_sha256 FROM bef_operation WHERE operation_id=$1`, [offerBody.operationId],
    );
    assert.deepEqual(offerRow.rows[0], {
      operation_kind: 'offer', status: 'accepted', response_sha256: responseSha256(offerBody),
    });

    const payKey = `pay-${nonce}`;
    const payBody = {
      resourceId,
      offerId,
      readHandle: catalogBody.readHandle,
      acceptedTerms: { scheme: 'exact', network, asset, amount, payTo: facilitatorAddress, transferMethod },
    };
    const payHeaders = { ...catalogHeaders, 'idempotency-key': payKey };
    const payChallenge = await app.inject({ method: 'POST', url: `/tools/${envId}/pay`, headers: payHeaders, payload: payBody });
    assert.equal(payChallenge.statusCode, 402);
    const challenge = payChallenge.json() as { resource: { url: string } };
    const paymentOperationId = payChallenge.headers['x-bef-operation-id'];
    assert.equal(typeof paymentOperationId, 'string');
    operationIds.push(paymentOperationId as string);
    assert.equal(challenge.resource.url, challengePath);
    assert.equal(protocolRequestPath, `/tools/${envId}/pay`);
    const payRetry = await app.inject({ method: 'POST', url: `/tools/${envId}/pay`, headers: payHeaders, payload: payBody });
    assert.equal(payRetry.statusCode, 402);
    assert.equal(payRetry.headers['x-bef-operation-id'], paymentOperationId);

    const crossRouteRetry = await app.inject({
      method: 'POST',
      url: `/tools/${envId}/purchase`,
      headers: payHeaders,
      payload: { resourceId, offerId },
    });
    assert.equal(crossRouteRetry.statusCode, 409);
    assert.deepEqual(crossRouteRetry.json(), { error: 'idempotency_key_conflict' });

    const pendingRetrieve = await app.inject({
      method: 'GET',
      url: `/tools/${envId}/retrieve?operationId=${paymentOperationId}`,
      headers: { ...catalogHeaders, 'idempotency-key': `retrieve-${nonce}` },
    });
    assert.equal(pendingRetrieve.statusCode, 409);
    const noEconomicRows = await pool.query<{ payments: string; deliveries: string; status: string; mode: string }>(
      `SELECT (SELECT count(*)::text FROM bef_payment WHERE operation_id=$1) AS payments,
              (SELECT count(*)::text FROM bef_delivery WHERE operation_id=$1) AS deliveries,
              status,payment_response_mode AS mode
         FROM bef_operation WHERE operation_id=$1`, [paymentOperationId],
    );
    assert.deepEqual(noEconomicRows.rows[0], { payments: '0', deliveries: '0', status: 'awaiting_payment', mode: 'deferred_delivery' });

    // This fixture seeds persisted observations to test the HTTP delivery boundary only.
    // It is synthetic PostgreSQL state and is not evidence of a live chain settlement.
    const transactionHash = `0x${'b'.repeat(64)}`;
    const authorizationSha256 = 'c'.repeat(64);
    const receipt = paidReceipt({ operationId: paymentOperationId as string, transactionHash, amount, asset, network, payTo: facilitatorAddress });
    await pool.query(
      `INSERT INTO bef_x402_observation(observation_id,env_id,generation_id,operation_id,variant_id,phase,request_sha256,
         safe_request,outcome,transaction_hash)
       VALUES($1,$2,$3,$4,'baseline','settle',$5,$6::jsonb,'success',$7)`,
      [randomUUID(), envId, generationId, paymentOperationId, 'd'.repeat(64), JSON.stringify({ paymentRequirements: { payTo: facilitatorAddress } }), transactionHash],
    );
    seededObservation = true;
    await pool.query(
      `INSERT INTO bef_payment(payment_id,operation_id,env_id,generation_id,authorization_sha256,payer_address,network,
         asset_address,amount_units,facilitator_address,transaction_hash,receipt_status,token_delta_units,payer_balance_before,
         payer_balance_after,facilitator_balance_before,facilitator_balance_after)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'success',$9,1000000,900000,0,100000)`,
      [randomUUID(), paymentOperationId, envId, generationId, authorizationSha256, payerAddress, network, asset, amount, facilitatorAddress, transactionHash],
    );
    seededPayment = true;
    await pool.query(
      `UPDATE bef_operation SET status='settled',receipt_status='success',authorization_sha256=$2,
             transaction_hash=$3,response_sha256=$4,completed_at=clock_timestamp()
        WHERE operation_id=$1 AND status='awaiting_payment'`,
      [paymentOperationId, authorizationSha256, transactionHash, responseSha256(receipt)],
    );

    const getDelivery = () => app.inject({
      method: 'GET',
      url: `/tools/${envId}/retrieve?operationId=${paymentOperationId}`,
      headers: { ...catalogHeaders, 'idempotency-key': `retrieve-${nonce}` },
    });
    await pool.query('UPDATE bef_operation SET response_sha256=$2 WHERE operation_id=$1', [paymentOperationId, 'f'.repeat(64)]);
    const unboundReceiptRetrieve = await getDelivery();
    assert.equal(unboundReceiptRetrieve.statusCode, 409);
    const noUnboundDelivery = await pool.query<{ count: string; status: string }>(
      `SELECT (SELECT count(*)::text FROM bef_delivery WHERE operation_id=$1) AS count,status
         FROM bef_operation WHERE operation_id=$1`, [paymentOperationId],
    );
    assert.deepEqual(noUnboundDelivery.rows[0], { count: '0', status: 'settled' });
    await pool.query('UPDATE bef_operation SET response_sha256=$2 WHERE operation_id=$1', [paymentOperationId, responseSha256(receipt)]);
    const [firstDelivery, concurrentDelivery] = await Promise.all([getDelivery(), getDelivery()]);
    assert.equal(firstDelivery.statusCode, 200);
    assert.equal(concurrentDelivery.statusCode, 200);
    assert.deepEqual(firstDelivery.json(), concurrentDelivery.json());
    assert.equal(firstDelivery.json().contentBytes, resourceBytes.toString('base64'));
    assert.equal(firstDelivery.json().contentHash, resourceHash);
    const deliveries = await pool.query<{ count: string; status: string; response_sha256: string }>(
      `SELECT (SELECT count(*)::text FROM bef_delivery WHERE operation_id=$1) AS count,
              status,response_sha256 FROM bef_operation WHERE operation_id=$1`, [paymentOperationId],
    );
    assert.deepEqual(deliveries.rows[0], {
      count: '1', status: 'delivered', response_sha256: responseSha256(receipt),
    });
    seededDelivery = true;

    // A retried /pay returns only the persisted settlement receipt after delivery.
    const payReceiptRetry = await app.inject({ method: 'POST', url: `/tools/${envId}/pay`, headers: payHeaders, payload: payBody });
    assert.equal(payReceiptRetry.statusCode, 200);
    assert.deepEqual(payReceiptRetry.json(), receipt);
    assert.equal('contentBytes' in payReceiptRetry.json(), false);
    const finalEconomicRows = await pool.query<{ operations: string; payments: string; deliveries: string }>(
      `SELECT (SELECT count(*)::text FROM bef_operation WHERE env_id=$1 AND generation_id=$2) AS operations,
              (SELECT count(*)::text FROM bef_payment WHERE operation_id=$3) AS payments,
              (SELECT count(*)::text FROM bef_delivery WHERE operation_id=$3) AS deliveries`,
      [envId, generationId, paymentOperationId],
    );
    assert.deepEqual(finalEconomicRows.rows[0], { operations: '3', payments: '1', deliveries: '1' });
  } finally {
    await app.close().catch(() => undefined);
    if (operationIds.length) {
      await pool.query('DELETE FROM bef_delivery WHERE operation_id=ANY($1::uuid[])', [operationIds]).catch(() => undefined);
      if (seededDelivery || seededPayment) await pool.query('DELETE FROM bef_payment WHERE operation_id=ANY($1::uuid[])', [operationIds]).catch(() => undefined);
      if (seededObservation) await pool.query('DELETE FROM bef_x402_observation WHERE operation_id=ANY($1::uuid[])', [operationIds]).catch(() => undefined);
      await pool.query('DELETE FROM bef_operation WHERE operation_id=ANY($1::uuid[])', [operationIds]).catch(() => undefined);
    }
    await pool.query('DELETE FROM bef_generation WHERE env_id=$1', [envId]).catch(() => undefined);
    await pool.query('DELETE FROM bef_environment WHERE env_id=$1', [envId]).catch(() => undefined);
    await pool.end();
  }
});
