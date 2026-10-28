import type { TaskCase, TaskReleaseManifest } from './task-release.js';

export type V2Document = Record<string, any>;
export type V2State = Omit<TaskCase['initialState'], 'stateSha256'>;
export type V2Block = { number: string; hash: string };
export type V2Action = { kind: string; operationId: string; rawResponsePath: string; rawResponseSha256: string };
export type V2RawDocument = { path: string; sha256: string; boundary: string; order: number; value: V2Document };
export class V2ReferenceError extends Error {
  constructor(readonly code: string,
    readonly disposition: 'unavailable' | 'mismatch' | 'unsolvable' | 'initially_solved' = 'mismatch') { super(code); }
}
export function v2Require(condition: unknown, code: string,
  disposition: V2ReferenceError['disposition'] = 'mismatch'): asserts condition {
  if (!condition) throw new V2ReferenceError(code, disposition);
}
export interface V2ReferenceContext {
  taskCase: TaskCase;
  identity: TaskReleaseManifest['executionIdentity'];
  manifest: V2Document;
  policy: V2Document;
  probe: V2Document;
  envelope: V2Document;
  generation: { envId: string; generationId: string; participantId: string; payerAddress: string };
  actions: readonly V2Action[];
  /** All hash-checked documents; order is probe observation order, or -1 for standalone bodies. */
  documents: readonly V2RawDocument[];
  /** Observation documents strictly after actual generation creation and before its fence. */
  actualDocuments: readonly V2RawDocument[];
  raw(path: string): V2Document;
  action(action: V2Action): V2Document;
  /** Matching actual HTTP observations, including payment challenge and signed response. */
  http(action: V2Action): readonly V2Document[];
  rpc(method: string): readonly V2Document[];
  receipt(transactionHash: string): V2Document;
  transaction(transactionHash: string): V2Document;
  block(block: V2Block): V2Document;
  /** Reconstruct amounts from independently retained block-tagged RPC reads; never copies amounts from shape. */
  stateAt(shape: V2State, block: V2Block, deliveredIds?: readonly string[], fulfilledIds?: readonly string[]): V2State;
  /** Returns only independent bef_observer/read-only observations in the actual generation phase. */
  database(): readonly V2Document[];
}
export type V2GoalProof = {
  initialBlock: V2Block;
  finalBlock: V2Block;
  deliveredComponentIds: string[];
  fulfilledObligationIds: string[];
  initiallySolved: boolean;
  solvable: boolean;
};
