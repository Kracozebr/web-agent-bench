import { createHash } from 'node:crypto';
import type { Pool, PoolClient } from 'pg';

export type PreparationStatus = 'preparing' | 'ready' | 'unknown' | 'fenced';
export type PreparationFixtureState = 'not_started' | 'hash_bound' | 'observed' | 'unknown' | 'reconciled';

export type PreparationRequestPins = {
  preparationId: string;
  envId: string;
  publicPinsSha256: string;
  participantId: string;
  payerAddress: string;
  resourceVariant: 'canonical' | 'mismatched_data' | 'verification_without_receipt';
  manifestSha256: string;
};

export type PreparationRecord = {
  preparation_id: string;
  env_id: string;
  public_pins_sha256: string | null;
  request_sha256: string | null;
  participant_id: string | null;
  payer_address: string | null;
  resource_variant: string | null;
  manifest_sha256: string | null;
  generation_id: string | null;
  status: PreparationStatus;
  fixture_state: PreparationFixtureState;
  fixture_transaction_hash: string | null;
  fixture_block_hash: string | null;
  fixture_hash: string | null;
  fixture_facts: Record<string, unknown> | null;
  reset_identity: Record<string, unknown> | null;
  reset_completed_at: Date | string | null;
  created_at: Date | string;
  updated_at: Date | string;
  fence_confirmed_at: Date | string | null;
};

export type PreparationResponse = {
  envId: string;
  preparationId: string;
  generationId: string;
  participantId: string;
  payerAddress: string;
  runToken: string;
  expiresAt: string;
  fixture: {
    transactionHash: string;
    blockHash: string;
    amountUnits: string;
    payerTokenBefore: string;
    payerTokenAfter: string;
    donorTokenBefore: string;
    donorTokenAfter: string;
    payerNativeBalance: string;
    receiptObservation: object;
  };
};

function canonicalRequest(pins: PreparationRequestPins): string {
  return JSON.stringify([
    pins.preparationId,
    pins.envId,
    pins.manifestSha256,
    pins.publicPinsSha256.toLowerCase(),
    pins.participantId,
    pins.payerAddress.toLowerCase(),
    pins.resourceVariant,
  ]);
}

export function preparationRequestHash(pins: PreparationRequestPins): string {
  return createHash('sha256').update(canonicalRequest(pins)).digest('hex');
}

export class PreparationResponseStore {
  // AICODE-NOTE: The raw run token is cached only for same-process response replay.
  // Never hydrate this store from PostgreSQL; a new process must fence and cannot recover it.
  private readonly responses = new Map<string, {
    requestSha256: string;
    generationId: string;
    expiresAtMs: number;
    response: PreparationResponse;
  }>();

  put(requestSha256: string, response: PreparationResponse, expiresAtMs: number): void {
    const now = Date.now();
    for (const [key, entry] of this.responses) if (entry.expiresAtMs <= now) this.responses.delete(key);
    this.responses.set(this.key(response.envId, response.preparationId), {
      requestSha256,
      generationId: response.generationId,
      expiresAtMs,
      response,
    });
  }

  get(envId: string, preparationId: string, requestSha256: string): PreparationResponse | null {
    const key = this.key(envId, preparationId);
    const entry = this.responses.get(key);
    if (!entry) return null;
    if (entry.expiresAtMs <= Date.now()) {
      this.responses.delete(key);
      return null;
    }
    if (entry.requestSha256 !== requestSha256) return null;
    return entry.response;
  }

  erasePreparation(envId: string, preparationId: string): void {
    this.responses.delete(this.key(envId, preparationId));
  }

  eraseGeneration(envId: string, generationId: string): void {
    for (const [key, entry] of this.responses) {
      if (key.startsWith(`${envId.length}:${envId}`) && entry.generationId === generationId) this.responses.delete(key);
    }
  }

  eraseEnvironment(envId: string): void {
    for (const key of this.responses.keys()) {
      if (key.startsWith(`${envId.length}:${envId}`)) this.responses.delete(key);
    }
  }

  eraseAll(): void {
    this.responses.clear();
  }

  private key(envId: string, preparationId: string): string {
    return `${envId.length}:${envId}${preparationId}`;
  }
}

export async function selectPreparation(
  client: PoolClient,
  preparationId: string,
  envId?: string,
  forUpdate = false,
): Promise<PreparationRecord | null> {
  const result = await client.query<PreparationRecord>(
    `SELECT preparation_id,env_id,public_pins_sha256,request_sha256,participant_id,payer_address,resource_variant,
            manifest_sha256,generation_id,status,fixture_state,fixture_transaction_hash,
            fixture_block_hash,fixture_hash,fixture_facts,reset_identity,reset_completed_at,
            created_at,updated_at,fence_confirmed_at
       FROM bef_preparation
      WHERE preparation_id=$1 AND ($2::text IS NULL OR env_id=$2)
      ${forUpdate ? 'FOR UPDATE' : ''}`,
    [preparationId, envId ?? null],
  );
  return result.rows[0] ?? null;
}

export async function reservePreparation(
  client: PoolClient,
  pins: PreparationRequestPins,
): Promise<'created' | 'preparation_id_used'> {
  const requestSha256 = preparationRequestHash(pins);
  const inserted = await client.query(
    `INSERT INTO bef_preparation
       (preparation_id,env_id,public_pins_sha256,request_sha256,participant_id,payer_address,resource_variant,manifest_sha256,
        status,fixture_state)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'preparing','not_started')
     ON CONFLICT (preparation_id) DO NOTHING
     RETURNING preparation_id`,
    [pins.preparationId, pins.envId, pins.publicPinsSha256.toLowerCase(), requestSha256, pins.participantId,
      pins.payerAddress.toLowerCase(), pins.resourceVariant, pins.manifestSha256],
  );
  return inserted.rowCount ? 'created' : 'preparation_id_used';
}

export async function recordPreparationResetProof(
  pool: Pool,
  args: { preparationId: string; envId: string; resetIdentity: Record<string, unknown> },
): Promise<void> {
  await withPgTransaction(pool, async (client) => {
    const updated = await client.query(
      `UPDATE bef_preparation
          SET reset_identity=$3::jsonb,reset_completed_at=clock_timestamp()
        WHERE preparation_id=$1 AND env_id=$2 AND status='preparing'
          AND generation_id IS NULL AND reset_identity IS NULL
        RETURNING preparation_id`,
      [args.preparationId, args.envId, JSON.stringify(args.resetIdentity)],
    );
    if (!updated.rowCount) throw new Error('preparation_reset_proof_not_recorded');
  });
}

export async function bindPreparationGeneration(
  pool: Pool,
  args: {
    pins: PreparationRequestPins;
    generationId: string;
    runTokenSha256: string;
    expiresAt: Date;
  },
): Promise<void> {
  await withPgTransaction(pool, async (client) => {
    const reservation = await selectPreparation(client, args.pins.preparationId, args.pins.envId, true);
    if (!reservation || reservation.status !== 'preparing' || reservation.generation_id !== null || reservation.reset_identity === null ||
        reservation.request_sha256?.trim() !== preparationRequestHash(args.pins)) {
      throw new Error('preparation_generation_reservation_not_available');
    }
    await client.query(
      `INSERT INTO bef_generation
         (generation_id,env_id,participant_id,run_token_sha256,payer_address,resource_variant,manifest_sha256,status,expires_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,'active',$8)`,
      [args.generationId, args.pins.envId, args.pins.participantId, args.runTokenSha256,
        args.pins.payerAddress.toLowerCase(), args.pins.resourceVariant, args.pins.manifestSha256, args.expiresAt],
    );
    const bound = await client.query(
      `UPDATE bef_preparation SET generation_id=$3
        WHERE preparation_id=$1 AND env_id=$2 AND generation_id IS NULL AND status='preparing'
        RETURNING preparation_id`,
      [args.pins.preparationId, args.pins.envId, args.generationId],
    );
    if (!bound.rowCount) throw new Error('preparation_generation_binding_failed');
  });
}

export async function bindFixtureTransactionHash(
  pool: Pool,
  args: { preparationId: string; envId: string; generationId: string; transactionHash: string },
): Promise<void> {
  await withPgTransaction(pool, async (client) => {
    const result = await client.query(
      `UPDATE bef_preparation
          SET fixture_state='hash_bound',fixture_transaction_hash=$4
        WHERE preparation_id=$1 AND env_id=$2 AND generation_id=$3 AND status='preparing'
          AND fixture_state IN ('not_started','hash_bound')
          AND (fixture_transaction_hash IS NULL OR fixture_transaction_hash=$4)
        RETURNING preparation_id`,
      [args.preparationId, args.envId, args.generationId, args.transactionHash],
    );
    if (!result.rowCount) throw new Error('preparation_fixture_hash_not_bound');
    const generation = await client.query(
      `UPDATE bef_generation SET fixture_transaction_hash=$3
        WHERE env_id=$1 AND generation_id=$2 AND status='active'
          AND (fixture_transaction_hash IS NULL OR fixture_transaction_hash=$3)
        RETURNING generation_id`,
      [args.envId, args.generationId, args.transactionHash],
    );
    if (!generation.rowCount) throw new Error('generation_fixture_hash_not_bound');
  });
}

export async function markPreparationUnknown(
  pool: Pool,
  args: { preparationId: string; envId: string },
): Promise<void> {
  await withPgTransaction(pool, async (client) => {
    const current = await selectPreparation(client, args.preparationId, args.envId, true);
    if (!current || current.status !== 'preparing') return;
    if (current.generation_id) {
      await client.query(
        `UPDATE bef_generation SET status='fenced',fenced_at=COALESCE(fenced_at,clock_timestamp())
          WHERE env_id=$1 AND generation_id=$2 AND status='active'`,
        [args.envId, current.generation_id],
      );
    }
    await client.query(
      `UPDATE bef_preparation SET status='unknown',fixture_state='unknown'
        WHERE preparation_id=$1 AND env_id=$2 AND status='preparing'`,
      [args.preparationId, args.envId],
    );
  });
}

export async function recordPreparationFixture(
  pool: Pool,
  args: {
    preparationId: string;
    envId: string;
    generationId: string;
    participantId: string;
    fixture: {
      transactionHash: string;
      blockHash: string;
      amountUnits: string;
      payerTokenBefore: string;
      payerTokenAfter: string;
      donorTokenBefore: string;
      donorTokenAfter: string;
      payerNativeBalance: string;
      receiptObservation: object;
      fixtureHash: string;
    };
    expiresAtSeconds: number;
  },
): Promise<string> {
  const facts = {
    amountUnits: args.fixture.amountUnits,
    payerTokenBefore: args.fixture.payerTokenBefore,
    payerTokenAfter: args.fixture.payerTokenAfter,
    donorTokenBefore: args.fixture.donorTokenBefore,
    donorTokenAfter: args.fixture.donorTokenAfter,
    payerNativeBalance: args.fixture.payerNativeBalance,
    receiptObservation: args.fixture.receiptObservation,
  };
  return withPgTransaction(pool, async (client) => {
    const generation = await client.query<{ expires_at: Date | string }>(
      `UPDATE bef_generation
          SET fixture_hash=$4,fixture_transaction_hash=$5,fixture_block_hash=$6,
              fixture_token_delta_units=$7,fixture_native_balance_wei=$8,
              expires_at=clock_timestamp() + ($9::int * interval '1 second')
        WHERE env_id=$1 AND generation_id=$2 AND status='active' AND participant_id=$3
        RETURNING expires_at`,
      [args.envId, args.generationId, args.participantId,
        args.fixture.fixtureHash, args.fixture.transactionHash, args.fixture.blockHash,
        args.fixture.amountUnits, args.fixture.payerNativeBalance, args.expiresAtSeconds],
    );
    if (!generation.rowCount) throw new Error('generation_fixture_persistence_failed');
    const updated = await client.query(
      `UPDATE bef_preparation
          SET status='ready',fixture_state='observed',fixture_transaction_hash=$4,
              fixture_block_hash=$5,fixture_hash=$6,fixture_facts=$7::jsonb
        WHERE preparation_id=$1 AND env_id=$2 AND generation_id=$3 AND status='preparing'
          AND fixture_state IN ('hash_bound','not_started')
          AND (fixture_transaction_hash IS NULL OR fixture_transaction_hash=$4)
        RETURNING preparation_id`,
      [args.preparationId, args.envId, args.generationId, args.fixture.transactionHash,
        args.fixture.blockHash, args.fixture.fixtureHash, JSON.stringify(facts)],
    );
    if (!updated.rowCount) throw new Error('preparation_fixture_persistence_failed');
    const expiresAt = generation.rows[0]!.expires_at;
    return expiresAt instanceof Date ? expiresAt.toISOString() : new Date(expiresAt).toISOString();
  });
}

export async function confirmPreparationFence(
  client: PoolClient,
  args: { preparationId: string; envId: string },
): Promise<{ kind: 'fenced'; record: PreparationRecord } | { kind: 'foreign' }> {
  const existing = await selectPreparation(client, args.preparationId, undefined, true);
  if (existing && existing.env_id !== args.envId) return { kind: 'foreign' };
  if (!existing) {
    const inserted = await client.query(
      `INSERT INTO bef_preparation(preparation_id,env_id,status,fixture_state,fence_confirmed_at)
       VALUES($1,$2,'fenced','not_started',clock_timestamp())
       ON CONFLICT (preparation_id) DO NOTHING
       RETURNING preparation_id`,
      [args.preparationId, args.envId],
    );
    if (!inserted.rowCount) return { kind: 'foreign' };
    const tombstone = await selectPreparation(client, args.preparationId, args.envId);
    if (!tombstone) throw new Error('preparation_fence_tombstone_missing');
    return { kind: 'fenced', record: tombstone };
  }

  if (existing.generation_id) {
    await client.query(
      `UPDATE bef_generation SET status='fenced',fenced_at=COALESCE(fenced_at,clock_timestamp())
        WHERE env_id=$1 AND generation_id=$2 AND status='active'`,
      [args.envId, existing.generation_id],
    );
  }
  await client.query(
    `UPDATE bef_preparation SET status='fenced',fence_confirmed_at=COALESCE(fence_confirmed_at,clock_timestamp())
      WHERE preparation_id=$1 AND env_id=$2`,
    [args.preparationId, args.envId],
  );
  const record = await selectPreparation(client, args.preparationId, args.envId);
  if (!record) throw new Error('preparation_fence_record_missing');
  return { kind: 'fenced', record };
}

export function publicPreparationStatus(record: PreparationRecord): Record<string, unknown> {
  const asIso = (value: Date | string | null) => value === null ? null
    : value instanceof Date ? value.toISOString() : new Date(value).toISOString();
  return {
    schemaVersion: 'bef-preparation-status/v1',
    envId: record.env_id,
    preparationId: record.preparation_id,
    status: record.status,
    generationId: record.generation_id,
    request: record.request_sha256 === null ? null : {
      requestSha256: record.request_sha256.trim(),
      publicPinsSha256: record.public_pins_sha256?.trim() ?? null,
      participantId: record.participant_id,
      payerAddress: record.payer_address,
      resourceVariant: record.resource_variant,
      manifestSha256: record.manifest_sha256?.trim() ?? null,
    },
    fixture: {
      state: record.fixture_state,
      transactionHash: record.fixture_transaction_hash,
      blockHash: record.fixture_block_hash,
      fixtureHash: record.fixture_hash?.trim() ?? null,
      facts: record.fixture_facts,
    },
    baselineReset: record.reset_identity === null ? null : {
      identity: record.reset_identity,
      completedAt: asIso(record.reset_completed_at),
    },
    createdAt: asIso(record.created_at),
    updatedAt: asIso(record.updated_at),
    fenceConfirmedAt: asIso(record.fence_confirmed_at),
  };
}

export async function recordRecoveredFixtureReceipt(
  client: PoolClient,
  args: {
    preparationId: string;
    envId: string;
    transactionHash: string;
    blockHash: string;
    fixtureFacts: Record<string, unknown>;
  },
): Promise<PreparationRecord | null> {
  const updated = await client.query(
    `UPDATE bef_preparation
        SET fixture_state='reconciled',fixture_block_hash=COALESCE(fixture_block_hash,$4),fixture_facts=COALESCE(fixture_facts,$5::jsonb)
      WHERE preparation_id=$1 AND env_id=$2 AND fixture_transaction_hash=$3
        AND fixture_state IN ('hash_bound','unknown','reconciled')
        AND (fixture_block_hash IS NULL OR fixture_block_hash=$4)
        AND (fixture_facts IS NULL OR fixture_facts=$5::jsonb)
      RETURNING preparation_id`,
    [args.preparationId, args.envId, args.transactionHash, args.blockHash, JSON.stringify(args.fixtureFacts)],
  );
  if (!updated.rowCount) return null;
  return selectPreparation(client, args.preparationId, args.envId);
}

export async function withPgTransaction<T>(pool: Pool, callback: (client: PoolClient) => Promise<T>): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await callback(client);
    await client.query('COMMIT');
    return result;
  } catch (error) {
    await client.query('ROLLBACK').catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
}
