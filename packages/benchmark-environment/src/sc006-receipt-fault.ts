export type Sc006ReceiptReadScope = {
  envId: string;
  generationId: string;
  operationId: string;
};

export type Sc006ReceiptFaultStatus = Sc006ReceiptReadScope & {
  armed: boolean;
  applied: boolean;
  transactionHash: string | null;
  faultedReads: number;
  broadcastHashes: string[];
  lastFaultAt: string | null;
  restored: boolean;
};

type FaultState = Sc006ReceiptFaultStatus & { expiresAt: number };

export class Sc006ReceiptReadFaults {
  private readonly records = new Map<string, FaultState>();

  arm(scope: Sc006ReceiptReadScope, ttlMs: number): Sc006ReceiptFaultStatus {
    if (!Number.isInteger(ttlMs) || ttlMs < 500 || ttlMs > 15_000) throw new Error('receipt_fault_ttl_out_of_range');
    const previous = this.records.get(scope.operationId);
    if (previous?.armed && performance.now() < previous.expiresAt) throw new Error('receipt_fault_already_armed');
    const state: FaultState = {
      ...scope, armed: true, applied: false, transactionHash: null, faultedReads: 0,
      broadcastHashes: [], lastFaultAt: null, restored: false, expiresAt: performance.now() + ttlMs,
    };
    this.records.set(scope.operationId, state);
    return this.publicStatus(state);
  }

  status(operationId: string): Sc006ReceiptFaultStatus | null {
    const state = this.records.get(operationId);
    return state ? this.publicStatus(state) : null;
  }

  restore(operationId: string, generationId: string): Sc006ReceiptFaultStatus | null {
    const state = this.records.get(operationId);
    if (!state || state.generationId !== generationId) return null;
    state.armed = false;
    state.restored = true;
    return this.publicStatus(state);
  }

  recordBroadcast(scope: Sc006ReceiptReadScope, transactionHash: string): void {
    const state = this.records.get(scope.operationId);
    if (state && state.envId === scope.envId && state.generationId === scope.generationId
      && /^0x[0-9a-f]{64}$/i.test(transactionHash)) state.broadcastHashes.push(transactionHash.toLowerCase());
  }

  intercept(scope: Sc006ReceiptReadScope | undefined, body: unknown): Response | null {
    if (!scope) return null;
    const state = this.records.get(scope.operationId);
    if (!state || !state.armed || performance.now() >= state.expiresAt
      || state.envId !== scope.envId || state.generationId !== scope.generationId
      || state.faultedReads !== 0) return null;
    let parsed: unknown;
    try { parsed = JSON.parse(typeof body === 'string' ? body : 'null') as unknown; } catch { return null; }
    const requests = Array.isArray(parsed) ? parsed : [parsed];
    if (requests.length !== 1) return null;
    const request = requests[0];
    if (!request || typeof request !== 'object' || Array.isArray(request)) return null;
    const record = request as Record<string, unknown>;
    const params = record.params;
    const transactionHash = Array.isArray(params) ? params[0] : null;
    if (record.method !== 'eth_getTransactionReceipt'
      || typeof transactionHash !== 'string' || !/^0x[0-9a-f]{64}$/i.test(transactionHash)
      || (state.transactionHash !== null && state.transactionHash.toLowerCase() !== transactionHash.toLowerCase())) return null;
    state.transactionHash ??= transactionHash;
    state.faultedReads = 1;
    state.applied = true;
    state.lastFaultAt = new Date().toISOString();
    return new Response(JSON.stringify({
      jsonrpc: '2.0', id: record.id ?? 1,
      error: { code: -32000, message: 'BEF-SC-006 one-shot receipt observer unavailable' },
    }), { status: 503, headers: { 'content-type': 'application/json' } });
  }

  private publicStatus(state: FaultState): Sc006ReceiptFaultStatus {
    return {
      envId: state.envId,
      generationId: state.generationId,
      operationId: state.operationId,
      armed: state.armed && performance.now() < state.expiresAt,
      applied: state.applied,
      transactionHash: state.transactionHash,
      faultedReads: state.faultedReads,
      broadcastHashes: [...state.broadcastHashes],
      lastFaultAt: state.lastFaultAt,
      restored: state.restored,
    };
  }
}
