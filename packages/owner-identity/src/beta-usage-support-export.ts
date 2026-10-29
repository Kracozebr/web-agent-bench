import { createHash } from "node:crypto";
import { sql } from "drizzle-orm";
import type { OwnerDatabase } from "./db.js";
import type { BetaDeploymentManifest } from "./beta-profile.js";
import { TASK_IDS } from "./task-catalog.js";

export const BETA_USAGE_CLIENT_FAMILIES = ["codex", "claude-code", "claude-desktop", "hermes"] as const;
export type BetaUsageClientFamily = (typeof BETA_USAGE_CLIENT_FAMILIES)[number] | "unknown";

export type PinnedBetaClientRegistry = {
  version: string;
  sha256: string;
  clients: readonly { oauthClientId: string | null; family: string }[];
  provenance: {
    source: "validated_config.betaManifest" | "explicit_test_fixture";
    hashBasis: string;
  };
};

/**
 * The deployment schema has no separately signed client-registry digest. Derive an exact,
 * explicitly labelled fingerprint from the startup-validated family/enabled/OAuth-ID projection.
 */
export function pinnedBetaClientRegistryFromManifest(manifest: BetaDeploymentManifest): PinnedBetaClientRegistry {
  // AICODE-NOTE: This digest fingerprints validated config.betaManifest registry fields; it is a derived identity, not an external signature or release.manifestHash.
  const projection = {
    schemaVersion: manifest.schemaVersion,
    clients: manifest.clients.map(({ family, enabled, oauthClientId }) => ({ family, enabled, oauthClientId }))
      .sort((left, right) => left.family < right.family ? -1 : left.family > right.family ? 1 : 0)
  };
  const canonical = JSON.stringify(projection);
  return {
    version: "beta-client-registry/v1",
    sha256: createHash("sha256").update(canonical).digest("hex"),
    clients: projection.clients.map(({ family, oauthClientId }) => ({ family, oauthClientId })),
    provenance: {
      source: "validated_config.betaManifest",
      hashBasis: "SHA-256(JSON.stringify({schemaVersion,clients sorted by family with family/enabled/oauthClientId}))"
    }
  };
}

type RunRow = {
  run_id: string;
  owner_id: string;
  agent_id: string;
  access_generation: number;
  mode: string;
  task_ids: string[];
  status: string;
};

type ActionRow = {
  action_id: string;
  run_id: string;
  owner_id: string;
  agent_id: string;
  access_generation: number;
  grant_id: string | null;
  grant_owner_id: string | null;
  grant_agent_id: string | null;
  grant_access_generation: number | null;
  grant_source: string | null;
  oauth_client_id: string | null;
};

type GrantRow = {
  grant_id: string;
  source: string;
  oauth_client_id: string | null;
};

type ReportRow = {
  report_id: string;
  owner_id: string;
  reporter_kind: string;
  reporter_id: string;
  operation_id: string;
  run_id: string | null;
};

type BonusLedgerRow = {
  entry_id: string;
  owner_id: string;
  operation_id: string;
  entry_type: string;
  source_kind: string;
  amount_units: string | bigint;
  run_id: string | null;
};

export type BetaUsageSupportSnapshot = {
  registeredOwners: number;
  registeredAgents: number;
  purgedReportReceipts: number;
  runs: readonly RunRow[];
  actions: readonly ActionRow[];
  grants: readonly GrantRow[];
  reports: readonly ReportRow[];
  bonusLedger: readonly BonusLedgerRow[];
};

type FamilyUsage = {
  issuedOAuthGrants: number;
  connectedObservedOwners: number;
  connectedObservedAgents: number;
  trainingRuns: number;
  trainingOwners: number;
  trainingAgents: number;
  fullRuns: number;
  fullOwners: number;
  fullAgents: number;
  repeatOwners: number;
  repeatAgents: number;
  failedRuns: number;
  unknownOutcomeRuns: number;
  otherTerminalRuns: number;
  nonterminalRuns: number;
  unknownFamilyRuns: number;
  reporterFamilyReports: number;
  reportsAssociatedWithRunFamily: number;
};

export type BetaUsageSupportExport = {
  metadata: {
    schemaVersion: "beta-usage-support-export/v1";
    scope: "all_retained_records";
    asOfUtc: string;
    clientRegistry: { version: string; sha256: string; provenance: PinnedBetaClientRegistry["provenance"] };
    connectionEvidence: {
      connectedObservedBasis: "authenticated_task_action";
      actualPreflightConnections: null;
    };
  };
  owners: {
    distinct: number;
    withRunUse: number;
    connectedObserved: number;
    actualPreflightConnections: null;
    trainingUsers: number;
    fullUsers: number;
    repeatUsers: number;
  };
  agents: {
    distinct: number;
    withRunUse: number;
    connectedObserved: number;
    actualPreflightConnections: null;
    trainingUsers: number;
    fullUsers: number;
    repeatUsers: number;
  };
  accessGrantsIssued: number;
  oauthGrantsIssued: number;
  runs: {
    trainingAttempts: number;
    fullAttempts: number;
    completed: number;
    failed: number;
    unknownOutcome: number;
    otherTerminal: number;
    nonterminal: number;
    nonCanonicalRanked: number;
  };
  clients: Record<BetaUsageClientFamily, FamilyUsage>;
  support: {
    reports: number;
    reporterFamilyUnknown: number;
    reportsAssociatedWithRunFamily: number;
    retentionHistory: {
      status: "incomplete";
      completeLifetimeReportCount: null;
      purgedReportReceipts: number;
      purgedOwnerOrClientAttribution: "unknown";
    };
    manualSupportMinutes: null;
    manualSupportMinutesStatus: "not_recorded";
  };
  funding: {
    bonusUsage: {
      owners: number;
      runs: number;
      debitEntries: number;
      refundEntries: number;
      grossDebitedUnits: string;
      refundedUnits: string;
      netUnits: string;
      unit: "USDC_base_units_6_decimals";
    };
    paidConversion: { status: "not_measured"; owners: null };
  };
  dataQuality: {
    duplicateRunRecords: number;
    duplicateActionRecords: number;
    duplicateReportOperations: number;
    conflictingReportOperations: number;
    conflictingClientBindings: number;
    unboundHistoricalActivity: number;
    reportsWithoutTrustedReporterBinding: number;
    unlinkedBonusDebitEntries: number;
  };
};

type QueryDatabase = Pick<OwnerDatabase, "execute">;

function resultRows<T>(value: unknown): T[] {
  return value as T[];
}

function firstRow<T>(value: unknown, code: string): T {
  const rows = resultRows<T>(value);
  if (!rows.length) throw new Error(code);
  return rows[0]!;
}

function validateRegistry(registry: PinnedBetaClientRegistry): void {
  if (!registry || typeof registry.version !== "string" || registry.version.length < 1 || registry.version.length > 128 ||
    typeof registry.sha256 !== "string" || !/^[0-9a-f]{64}$/.test(registry.sha256) || !Array.isArray(registry.clients) ||
    !registry.provenance || !["validated_config.betaManifest", "explicit_test_fixture"].includes(registry.provenance.source) ||
    typeof registry.provenance.hashBasis !== "string" || registry.provenance.hashBasis.length < 1 || registry.provenance.hashBasis.length > 300) {
    throw new Error("beta_usage_export_pinned_registry_invalid");
  }
}

function clientFamilyIndex(registry: PinnedBetaClientRegistry): Map<string, Set<BetaUsageClientFamily>> {
  const byClient = new Map<string, Set<BetaUsageClientFamily>>();
  for (const client of registry.clients) {
    if (!client || typeof client.oauthClientId !== "string" || client.oauthClientId.length === 0) continue;
    const family = BETA_USAGE_CLIENT_FAMILIES.includes(client.family as (typeof BETA_USAGE_CLIENT_FAMILIES)[number])
      ? client.family as (typeof BETA_USAGE_CLIENT_FAMILIES)[number]
      : null;
    if (!family) continue;
    const families = byClient.get(client.oauthClientId) ?? new Set<BetaUsageClientFamily>();
    families.add(family);
    byClient.set(client.oauthClientId, families);
  }
  return byClient;
}

function isCanonicalFullRun(run: RunRow): boolean {
  return run.mode === "ranked" && Array.isArray(run.task_ids) && run.task_ids.length === TASK_IDS.length &&
    run.task_ids.every((taskId, index) => taskId === TASK_IDS[index]);
}

function stableKey(...parts: string[]): string {
  return JSON.stringify(parts);
}

function numberOf(values: Set<string>): number {
  return values.size;
}

function emptyFamilyUsage(): FamilyUsage {
  return {
    issuedOAuthGrants: 0,
    connectedObservedOwners: 0,
    connectedObservedAgents: 0,
    trainingRuns: 0,
    trainingOwners: 0,
    trainingAgents: 0,
    fullRuns: 0,
    fullOwners: 0,
    fullAgents: 0,
    repeatOwners: 0,
    repeatAgents: 0,
    failedRuns: 0,
    unknownOutcomeRuns: 0,
    otherTerminalRuns: 0,
    nonterminalRuns: 0,
    unknownFamilyRuns: 0,
    reporterFamilyReports: 0,
    reportsAssociatedWithRunFamily: 0
  };
}

/**
 * Aggregates only stable persisted identities. No owner/client detail is returned.
 * Client family attribution requires a persisted action grant whose OAuth client ID
 * resolves uniquely through the supplied pinned registry.
 */
export function aggregateBetaUsageSupportExport(
  snapshot: BetaUsageSupportSnapshot,
  registry: PinnedBetaClientRegistry,
  asOf: Date
): BetaUsageSupportExport {
  validateRegistry(registry);
  if (!Number.isFinite(asOf.getTime())) throw new Error("beta_usage_export_timestamp_invalid");
  const clientFamilies = clientFamilyIndex(registry);
  const familyKeys: BetaUsageClientFamily[] = [...BETA_USAGE_CLIENT_FAMILIES, "unknown"];
  const clients = Object.fromEntries(familyKeys.map((family) => [family, emptyFamilyUsage()])) as Record<BetaUsageClientFamily, FamilyUsage>;
  const runById = new Map<string, RunRow>();
  let duplicateRunRecords = 0;
  for (const run of snapshot.runs) {
    if (runById.has(run.run_id)) {
      duplicateRunRecords += 1;
      continue;
    }
    runById.set(run.run_id, run);
  }

  const actionsByRun = new Map<string, ActionRow[]>();
  const actionIds = new Set<string>();
  let duplicateActionRecords = 0;
  for (const action of snapshot.actions) {
    if (actionIds.has(action.action_id)) {
      duplicateActionRecords += 1;
      continue;
    }
    actionIds.add(action.action_id);
    const rows = actionsByRun.get(action.run_id) ?? [];
    rows.push(action);
    actionsByRun.set(action.run_id, rows);
  }

  const runFamily = new Map<string, BetaUsageClientFamily>();
  let conflictingClientBindings = 0;
  let unboundHistoricalActivity = 0;
  for (const [runId] of runById) {
    const run = runById.get(runId)!;
    const actions = actionsByRun.get(runId) ?? [];
    const oauthClientIds = new Set<string>();
    const resolvedFamilies = new Set<BetaUsageClientFamily>();
    let everyActionTrusted = actions.length > 0;
    let ambiguousRegistryBinding = false;
    let inconsistentActionGrant = false;
    for (const action of actions) {
      const hasPersistedOAuthClient = action.grant_id !== null && action.grant_source === "oauth" &&
        action.oauth_client_id !== null && action.oauth_client_id.length > 0;
      if (hasPersistedOAuthClient) oauthClientIds.add(action.oauth_client_id!);
      const identityMatches = action.owner_id === run.owner_id && action.agent_id === run.agent_id &&
        action.owner_id === action.grant_owner_id && action.agent_id === action.grant_agent_id &&
        action.access_generation === action.grant_access_generation && action.access_generation === run.access_generation;
      if (hasPersistedOAuthClient && !identityMatches) inconsistentActionGrant = true;
      const hasBoundGrant = hasPersistedOAuthClient && identityMatches;
      if (!hasBoundGrant) {
        everyActionTrusted = false;
        continue;
      }
      const matches = clientFamilies.get(action.oauth_client_id!);
      if (!matches || matches.size !== 1) {
        everyActionTrusted = false;
        if (matches && matches.size > 1) ambiguousRegistryBinding = true;
        continue;
      }
      resolvedFamilies.add([...matches][0]!);
    }
    const hasConflict = oauthClientIds.size > 1 || resolvedFamilies.size > 1 || ambiguousRegistryBinding || inconsistentActionGrant;
    if (hasConflict) conflictingClientBindings += 1;
    const family = everyActionTrusted && !hasConflict && resolvedFamilies.size === 1
      ? [...resolvedFamilies][0]!
      : "unknown";
    runFamily.set(runId, family);
    if (family === "unknown") unboundHistoricalActivity += 1;
  }

  const issuedGrantIds = new Set<string>();
  const issuedOAuthGrantIds = new Set<string>();
  for (const grant of snapshot.grants) {
    if (issuedGrantIds.has(grant.grant_id)) continue;
    issuedGrantIds.add(grant.grant_id);
    if (grant.source !== "oauth") continue;
    issuedOAuthGrantIds.add(grant.grant_id);
    const matches = grant.oauth_client_id ? clientFamilies.get(grant.oauth_client_id) : undefined;
    const family = matches?.size === 1 ? [...matches][0]! : "unknown";
    clients[family].issuedOAuthGrants += 1;
  }

  const observedOwners = new Set<string>();
  const observedAgents = new Set<string>();
  const observedOwnersByFamily = new Map<BetaUsageClientFamily, Set<string>>();
  const observedAgentsByFamily = new Map<BetaUsageClientFamily, Set<string>>();
  const runOwners = new Set<string>();
  const runAgents = new Set<string>();
  const trainingOwners = new Set<string>();
  const trainingAgents = new Set<string>();
  const fullOwners = new Set<string>();
  const fullAgents = new Set<string>();
  const runIdsByOwner = new Map<string, Set<string>>();
  const runIdsByAgent = new Map<string, Set<string>>();
  const ownerRunsByFamily = new Map<BetaUsageClientFamily, Map<string, Set<string>>>();
  const agentRunsByFamily = new Map<BetaUsageClientFamily, Map<string, Set<string>>>();
  let trainingAttempts = 0;
  let fullAttempts = 0;
  let completedRuns = 0;
  let failedRuns = 0;
  let unknownOutcomeRuns = 0;
  let otherTerminalRuns = 0;
  let nonterminalRuns = 0;
  let nonCanonicalRanked = 0;

  for (const [runId, run] of runById) {
    const family = runFamily.get(runId) ?? "unknown";
    const familyUsage = clients[family];
    runOwners.add(run.owner_id);
    runAgents.add(run.agent_id);
    const ownerIds = runIdsByOwner.get(run.owner_id) ?? new Set<string>();
    ownerIds.add(runId);
    runIdsByOwner.set(run.owner_id, ownerIds);
    const agentIds = runIdsByAgent.get(run.agent_id) ?? new Set<string>();
    agentIds.add(runId);
    runIdsByAgent.set(run.agent_id, agentIds);

    const familyOwnerRuns = ownerRunsByFamily.get(family) ?? new Map<string, Set<string>>();
    const ownerFamilyRunIds = familyOwnerRuns.get(run.owner_id) ?? new Set<string>();
    ownerFamilyRunIds.add(runId);
    familyOwnerRuns.set(run.owner_id, ownerFamilyRunIds);
    ownerRunsByFamily.set(family, familyOwnerRuns);
    const familyAgentRuns = agentRunsByFamily.get(family) ?? new Map<string, Set<string>>();
    const agentFamilyRunIds = familyAgentRuns.get(run.agent_id) ?? new Set<string>();
    agentFamilyRunIds.add(runId);
    familyAgentRuns.set(run.agent_id, agentFamilyRunIds);
    agentRunsByFamily.set(family, familyAgentRuns);

    if (actionsByRun.has(runId)) {
      const familyOwners = observedOwnersByFamily.get(family) ?? new Set<string>();
      const familyAgents = observedAgentsByFamily.get(family) ?? new Set<string>();
      for (const action of actionsByRun.get(runId)!) {
        observedOwners.add(action.owner_id);
        observedAgents.add(action.agent_id);
        familyOwners.add(action.owner_id);
        familyAgents.add(action.agent_id);
      }
      observedOwnersByFamily.set(family, familyOwners);
      observedAgentsByFamily.set(family, familyAgents);
    }

    if (run.mode === "training") {
      trainingAttempts += 1;
      trainingOwners.add(run.owner_id);
      trainingAgents.add(run.agent_id);
      familyUsage.trainingRuns += 1;
    } else if (run.mode === "ranked" && isCanonicalFullRun(run)) {
      fullAttempts += 1;
      fullOwners.add(run.owner_id);
      fullAgents.add(run.agent_id);
      familyUsage.fullRuns += 1;
    } else if (run.mode === "ranked") {
      nonCanonicalRanked += 1;
    }

    if (run.status === "completed") {
      completedRuns += 1;
    } else if (run.status === "failed") {
      failedRuns += 1;
      familyUsage.failedRuns += 1;
    } else if (run.status === "cancelled" || run.status === "expired" || run.status === "disqualified") {
      otherTerminalRuns += 1;
      familyUsage.otherTerminalRuns += 1;
    } else if (run.status === "queued" || run.status === "preparing" || run.status === "running" ||
      run.status === "cancellation_requested") {
      nonterminalRuns += 1;
      familyUsage.nonterminalRuns += 1;
    } else {
      unknownOutcomeRuns += 1;
      familyUsage.unknownOutcomeRuns += 1;
    }
    if (family === "unknown") familyUsage.unknownFamilyRuns += 1;
  }

  const countRepeats = (source: Map<string, Set<string>>): number =>
    [...source.values()].filter((runIds) => runIds.size > 1).length;
  for (const family of familyKeys) {
    const familyUsage = clients[family];
    const ownerRunMap = ownerRunsByFamily.get(family) ?? new Map<string, Set<string>>();
    const agentRunMap = agentRunsByFamily.get(family) ?? new Map<string, Set<string>>();
    familyUsage.repeatOwners = countRepeats(ownerRunMap);
    familyUsage.repeatAgents = countRepeats(agentRunMap);
    familyUsage.connectedObservedOwners = observedOwnersByFamily.get(family)?.size ?? 0;
    familyUsage.connectedObservedAgents = observedAgentsByFamily.get(family)?.size ?? 0;
    familyUsage.trainingOwners = new Set([...runById.values()].filter((run) =>
      run.mode === "training" && runFamily.get(run.run_id) === family).map((run) => run.owner_id)).size;
    familyUsage.trainingAgents = new Set([...runById.values()].filter((run) =>
      run.mode === "training" && runFamily.get(run.run_id) === family).map((run) => run.agent_id)).size;
    familyUsage.fullOwners = new Set([...runById.values()].filter((run) =>
      isCanonicalFullRun(run) && runFamily.get(run.run_id) === family).map((run) => run.owner_id)).size;
    familyUsage.fullAgents = new Set([...runById.values()].filter((run) =>
      isCanonicalFullRun(run) && runFamily.get(run.run_id) === family).map((run) => run.agent_id)).size;
  }

  const runFamilyById = runFamily;
  const dedupedReports = new Map<string, ReportRow>();
  const conflictingReportLinks = new Set<string>();
  const conflictingReportOperations = new Set<string>();
  let duplicateReportOperations = 0;
  for (const report of snapshot.reports) {
    const key = stableKey(report.owner_id, report.operation_id);
    const existing = dedupedReports.get(key);
    if (!existing) {
      dedupedReports.set(key, report);
      continue;
    }
    duplicateReportOperations += 1;
    if (existing.run_id !== report.run_id) conflictingReportLinks.add(key);
    if (existing.run_id !== report.run_id || existing.reporter_kind !== report.reporter_kind ||
      existing.reporter_id !== report.reporter_id) conflictingReportOperations.add(key);
  }
  let reportsAssociatedWithRunFamily = 0;
  for (const [key, report] of dedupedReports) {
    // A linked run does not bind the client that submitted the report.
    clients.unknown.reporterFamilyReports += 1;
    if (report.run_id && !conflictingReportLinks.has(key)) {
      const associatedFamily = runFamilyById.get(report.run_id);
      if (associatedFamily && associatedFamily !== "unknown") {
        clients[associatedFamily].reportsAssociatedWithRunFamily += 1;
        reportsAssociatedWithRunFamily += 1;
      }
    }
  }

  const bonusEntryIds = new Set<string>();
  const bonusOwners = new Set<string>();
  const bonusRuns = new Set<string>();
  let grossDebited = 0n;
  let refunded = 0n;
  let debitEntries = 0;
  let refundEntries = 0;
  let unlinkedBonusDebitEntries = 0;
  for (const entry of snapshot.bonusLedger) {
    if (entry.source_kind !== "tester_bonus") continue;
    if (bonusEntryIds.has(entry.entry_id)) continue;
    bonusEntryIds.add(entry.entry_id);
    if (entry.entry_type === "debit") {
      debitEntries += 1;
      grossDebited += BigInt(entry.amount_units);
      bonusOwners.add(entry.owner_id);
      if (entry.run_id) bonusRuns.add(entry.run_id);
      else unlinkedBonusDebitEntries += 1;
    } else if (entry.entry_type === "refund") {
      refundEntries += 1;
      refunded += BigInt(entry.amount_units);
    }
  }

  const totalReports = dedupedReports.size;
  return {
    metadata: {
      schemaVersion: "beta-usage-support-export/v1",
      scope: "all_retained_records",
      asOfUtc: asOf.toISOString(),
      clientRegistry: { version: registry.version, sha256: registry.sha256, provenance: registry.provenance },
      connectionEvidence: { connectedObservedBasis: "authenticated_task_action", actualPreflightConnections: null }
    },
    owners: {
      distinct: snapshot.registeredOwners,
      withRunUse: numberOf(runOwners),
      connectedObserved: numberOf(observedOwners),
      actualPreflightConnections: null,
      trainingUsers: numberOf(trainingOwners),
      fullUsers: numberOf(fullOwners),
      repeatUsers: countRepeats(runIdsByOwner)
    },
    agents: {
      distinct: snapshot.registeredAgents,
      withRunUse: numberOf(runAgents),
      connectedObserved: numberOf(observedAgents),
      actualPreflightConnections: null,
      trainingUsers: numberOf(trainingAgents),
      fullUsers: numberOf(fullAgents),
      repeatUsers: countRepeats(runIdsByAgent)
    },
    accessGrantsIssued: issuedGrantIds.size,
    oauthGrantsIssued: issuedOAuthGrantIds.size,
    runs: {
      trainingAttempts,
      fullAttempts,
      completed: completedRuns,
      failed: failedRuns,
      unknownOutcome: unknownOutcomeRuns,
      otherTerminal: otherTerminalRuns,
      nonterminal: nonterminalRuns,
      nonCanonicalRanked
    },
    clients,
    support: {
      reports: totalReports,
      reporterFamilyUnknown: totalReports,
      reportsAssociatedWithRunFamily,
      retentionHistory: {
        status: "incomplete",
        completeLifetimeReportCount: null,
        purgedReportReceipts: snapshot.purgedReportReceipts,
        purgedOwnerOrClientAttribution: "unknown"
      },
      manualSupportMinutes: null,
      manualSupportMinutesStatus: "not_recorded"
    },
    funding: {
      bonusUsage: {
        owners: bonusOwners.size,
        runs: bonusRuns.size,
        debitEntries,
        refundEntries,
        grossDebitedUnits: grossDebited.toString(),
        refundedUnits: refunded.toString(),
        netUnits: (grossDebited - refunded).toString(),
        unit: "USDC_base_units_6_decimals"
      },
      paidConversion: { status: "not_measured", owners: null }
    },
    dataQuality: {
      duplicateRunRecords,
      duplicateActionRecords,
      duplicateReportOperations,
      conflictingReportOperations: conflictingReportOperations.size,
      conflictingClientBindings,
      unboundHistoricalActivity,
      reportsWithoutTrustedReporterBinding: totalReports,
      unlinkedBonusDebitEntries
    }
  };
}

async function readSnapshot(database: QueryDatabase): Promise<{ snapshot: BetaUsageSupportSnapshot; asOf: Date }> {
  const identity = firstRow<{ transaction_read_only: string; snapshot_at: Date | string }>(await database.execute(sql`
    SELECT current_setting('transaction_read_only') AS transaction_read_only, transaction_timestamp() AS snapshot_at
  `), "beta_usage_export_snapshot_identity_missing");
  if (identity.transaction_read_only !== "on") throw new Error("beta_usage_export_requires_read_only_transaction");

  const counts = firstRow<{ registered_owners: number | string; registered_agents: number | string; purged_report_receipts: number | string }>(await database.execute(sql`
    SELECT (SELECT count(*) FROM oid_owner)::text AS registered_owners,
      (SELECT count(*) FROM oid_agent)::text AS registered_agents,
      (SELECT count(DISTINCT report_id) FROM oid_support_report_deletion_receipt)::text AS purged_report_receipts
  `), "beta_usage_export_account_counts_missing");
  const runs = resultRows<RunRow>(await database.execute(sql`
    SELECT id::text AS run_id,owner_id::text AS owner_id,agent_id::text AS agent_id,
      access_generation,mode,task_ids,status FROM oid_benchmark_run
  `));
  // AICODE-NOTE: Never infer historical client family from profile metadata or report version text;
  // attribution is grant_id -> stored OAuth client ID -> the caller's pinned registry only.
  const actions = resultRows<ActionRow>(await database.execute(sql`
    SELECT action.id::text AS action_id,action.run_id::text AS run_id,
      action.owner_id::text AS owner_id,action.agent_id::text AS agent_id,
      action.access_generation,action.grant_id::text AS grant_id,
      grant_row.owner_id::text AS grant_owner_id,grant_row.agent_id::text AS grant_agent_id,
      grant_row.access_generation AS grant_access_generation,grant_row.source AS grant_source,
      grant_row.oauth_client_id
    FROM oid_run_task_action AS action
    LEFT JOIN oid_agent_access_grant AS grant_row ON grant_row.id=action.grant_id
  `));
  const grants = resultRows<GrantRow>(await database.execute(sql`
    SELECT id::text AS grant_id,source,oauth_client_id FROM oid_agent_access_grant
  `));
  // `client_version`, free-form body/context, and current profile metadata are intentionally not selected.
  const reports = resultRows<ReportRow>(await database.execute(sql`
    SELECT id::text AS report_id,owner_id::text AS owner_id,reporter_kind,
      reporter_id::text AS reporter_id,operation_id,run_id::text AS run_id
    FROM oid_support_report
  `));
  const bonusLedger = resultRows<BonusLedgerRow>(await database.execute(sql`
    SELECT entry.id::text AS entry_id,entry.owner_id::text AS owner_id,entry.operation_id,
      entry.entry_type,entry.source_kind,entry.amount_units::text AS amount_units,run.id::text AS run_id
    FROM oid_ledger_entry AS entry
    LEFT JOIN oid_benchmark_run AS run
      ON entry.entry_type='debit' AND entry.operation_id='rundeb_'||replace(run.id::text,'-','')
    WHERE entry.source_kind='tester_bonus' AND entry.entry_type IN ('debit','refund')
  `));
  const owners = Number(counts.registered_owners);
  const agents = Number(counts.registered_agents);
  const purgedReportReceipts = Number(counts.purged_report_receipts);
  if (!Number.isSafeInteger(owners) || !Number.isSafeInteger(agents) || !Number.isSafeInteger(purgedReportReceipts)) {
    throw new Error("beta_usage_export_count_out_of_range");
  }
  const snapshotAt = identity.snapshot_at instanceof Date ? identity.snapshot_at : new Date(identity.snapshot_at);
  if (!Number.isFinite(snapshotAt.getTime())) throw new Error("beta_usage_export_snapshot_timestamp_invalid");
  return {
    snapshot: { registeredOwners: owners, registeredAgents: agents, purgedReportReceipts, runs, actions, grants, reports, bonusLedger },
    asOf: snapshotAt
  };
}

/**
 * Read-only export entry point. The entire export is derived inside one repeatable,
 * read-only PostgreSQL transaction so its counts share a single snapshot.
 */
export async function buildBetaUsageSupportExport(
  db: OwnerDatabase,
  registry: PinnedBetaClientRegistry
): Promise<BetaUsageSupportExport> {
  validateRegistry(registry);
  return db.transaction(async (tx) => {
    const { snapshot, asOf } = await readSnapshot(tx);
    return aggregateBetaUsageSupportExport(snapshot, registry, asOf);
  }, { isolationLevel: "repeatable read", accessMode: "read only" });
}
