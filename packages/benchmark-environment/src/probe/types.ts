export type ProbeScenarioId =
  | 'BEF-SC-001'
  | 'BEF-SC-002'
  | 'BEF-SC-003'
  | 'BEF-SC-004'
  | 'BEF-SC-005'
  | 'BEF-SC-006'
  | 'BEF-SC-007'
  | 'BEF-SC-008'
  | 'BEF-SC-009'
  | 'BEF-SC-010'
  | 'BEF-SC-011'
  | 'BEF-SC-012';
export type ProbeStatus = 'captured' | 'blocked' | 'error';

export type ProbeArtifact = {
  path: string;
  sha256: string;
  contentType: 'application/json';
  boundary: string;
};

export type ProbeOperation = {
  operationId: string;
  kind: string;
  idempotencyKeyHash: string;
  observedStatus: string;
  transactionHash: string | null;
  receiptStatus: 'unknown' | 'not_submitted' | 'success' | 'reverted';
};

/** A content-addressed operation inventory from a capture replayed offline by SC-012. */
export type ReplayedOriginalCaptureReference = {
  provenance: 'replayed-original';
  scenarioId: 'BEF-SC-004' | 'BEF-SC-005';
  evidenceRoot: { kind: 'repository_relative'; path: string };
  probeIndexPath: 'probe.json';
  probeIndexSha256: string;
  environmentId: string;
  generationId: string;
  operationIds: string[];
};

export type ProbeObservation = {
  id: string;
  sourceArtifact: string;
};

export type BlockedProbe = {
  schemaVersion: 'bef-runtime-probe/v1';
  scenarioId: ProbeScenarioId;
  status: 'blocked';
  reasonCode: string;
  missingPrerequisites: string[];
  manifest: null;
  environment: null;
  operations: [];
  observations: [];
  artifacts: [];
};

export type CapturedProbe = {
  schemaVersion: 'bef-runtime-probe/v1';
  scenarioId: ProbeScenarioId;
  status: 'captured' | 'error';
  manifest: { path: 'manifest.json'; sha256: string };
  environment: {
    envId: string;
    generation: {
      generationId: string;
      participantId: string;
      payerAddress: string;
    };
  };
  operations: ProbeOperation[];
  replayedOriginalCaptures?: ReplayedOriginalCaptureReference[];
  observations: ProbeObservation[];
  artifacts: ProbeArtifact[];
  applicationSourceSha256: string;
  probeSourceSha256: string;
  runtimeVersions: Record<string, string>;
  sourceBlock: { number: string; hash: string };
  errorCode?: string;
};

export type ErrorProbe = {
  schemaVersion: 'bef-runtime-probe/v1';
  scenarioId: ProbeScenarioId;
  status: 'error';
  errorCode: string;
  manifest: { path: 'manifest.json'; sha256: string } | null;
  environment: {
    envId: string;
    generation: {
      generationId: string;
      participantId: string;
      payerAddress: string;
    };
  } | null;
  operations: ProbeOperation[];
  replayedOriginalCaptures?: ReplayedOriginalCaptureReference[];
  observations: ProbeObservation[];
  artifacts: ProbeArtifact[];
  applicationSourceSha256?: string;
  probeSourceSha256?: string;
  runtimeVersions?: Record<string, string>;
  sourceBlock?: { number: string; hash: string };
};

export type ProbePayload = BlockedProbe | CapturedProbe | ErrorProbe;

export type RawObservation = {
  schemaVersion: 'bef-http-observation/v1' | 'bef-db-observation/v1' | 'bef-rpc-observation/v1' | 'bef-resource-observation/v1';
  boundary: string;
  operationId: string | null;
  variantId: string | null;
  [key: string]: unknown;
};
