import assert from "node:assert/strict";
import { test } from "node:test";
import { sql } from "drizzle-orm";
import type { OwnerIdentityConfig } from "./config.js";
import { createDatabase, type OwnerDatabase } from "./db.js";
import {
  aggregateBetaUsageSupportExport,
  buildBetaUsageSupportExport,
  type BetaUsageSupportSnapshot,
  type PinnedBetaClientRegistry
} from "./beta-usage-support-export.js";
import { TASK_IDS } from "./task-catalog.js";

const optIn = process.env.OID_BETA_USAGE_SUPPORT_PG_REGRESSION === "true";
const EXPECTED_DB = /^oid_acceptance_[a-f0-9]{32}$/;
const REGISTRY: PinnedBetaClientRegistry = {
  version: "sc023-test-pinned-client-registry/v1",
  sha256: "a".repeat(64),
  clients: [
    { oauthClientId: "sc023-codex-client", family: "codex" },
    { oauthClientId: "sc023-hermes-client", family: "hermes" }
  ],
  provenance: { source: "explicit_test_fixture", hashBasis: "fixed test-only client map" }
};

function rows<T>(result: unknown): T[] {
  return result as T[];
}

function first<T>(result: unknown): T {
  const found = rows<T>(result);
  if (!found.length) throw new Error("beta_usage_pg_probe_expected_row_missing");
  return found[0]!;
}

function acceptanceUrl(raw: string | undefined, expectedDatabase: string, role: "oid_owner" | "oid_observer"): string {
  if (!raw) throw new Error("beta_usage_pg_probe_database_url_missing");
  const url = new URL(raw);
  if (url.hostname !== "postgres" || url.username !== role) throw new Error("beta_usage_pg_probe_database_endpoint_rejected");
  url.pathname = `/${expectedDatabase}`;
  return url.href;
}

async function readOnlyFacts(database: OwnerDatabase) {
  return database.transaction(async (tx) => {
    const current = first<{ database: string; role: string; read_only: string }>(await tx.execute(sql`
      SELECT current_database() AS database,current_user AS role,current_setting('transaction_read_only') AS read_only
    `));
    assert.equal(current.role, "oid_observer");
    assert.equal(current.read_only, "on");
    return first<{
      owners: string;
      agents: string;
      runs: string;
      actions: string;
      grants: string;
      reports: string;
      deduped_reports: string;
      purged_report_receipts: string;
      training_runs: string;
      canonical_full_runs: string;
      completed_runs: string;
      failed_runs: string;
      unknown_outcome_runs: string;
      other_terminal_runs: string;
      nonterminal_runs: string;
      connected_owners: string;
      connected_agents: string;
      bonus_debit_entries: string;
      bonus_refund_entries: string;
      bonus_gross_units: string;
      bonus_refunded_units: string;
      bonus_runs: string;
    }>(await tx.execute(sql`
      SELECT
        (SELECT count(*) FROM oid_owner)::text AS owners,
        (SELECT count(*) FROM oid_agent)::text AS agents,
        (SELECT count(*) FROM oid_benchmark_run)::text AS runs,
        (SELECT count(*) FROM oid_run_task_action)::text AS actions,
        (SELECT count(*) FROM oid_agent_access_grant)::text AS grants,
        (SELECT count(*) FROM oid_support_report)::text AS reports,
        (SELECT count(DISTINCT (owner_id,operation_id)) FROM oid_support_report)::text AS deduped_reports,
        (SELECT count(DISTINCT report_id) FROM oid_support_report_deletion_receipt)::text AS purged_report_receipts,
        (SELECT count(*) FROM oid_benchmark_run WHERE mode='training')::text AS training_runs,
        (SELECT count(*) FROM oid_benchmark_run WHERE mode='ranked' AND task_ids=ARRAY[
          'S1','S2','S3','S4','M1','M2','M3','M4','H1','H2','H3','U1']::text[])::text AS canonical_full_runs,
        (SELECT count(*) FROM oid_benchmark_run WHERE status='completed')::text AS completed_runs,
        (SELECT count(*) FROM oid_benchmark_run WHERE status='failed')::text AS failed_runs,
        (SELECT count(*) FROM oid_benchmark_run WHERE status='unknown')::text AS unknown_outcome_runs,
        (SELECT count(*) FROM oid_benchmark_run WHERE status IN ('cancelled','expired','disqualified'))::text AS other_terminal_runs,
        (SELECT count(*) FROM oid_benchmark_run WHERE status IN ('queued','preparing','running','cancellation_requested'))::text AS nonterminal_runs,
        (SELECT count(DISTINCT owner_id) FROM oid_run_task_action)::text AS connected_owners,
        (SELECT count(DISTINCT agent_id) FROM oid_run_task_action)::text AS connected_agents,
        (SELECT count(*) FROM oid_ledger_entry WHERE source_kind='tester_bonus' AND entry_type='debit')::text AS bonus_debit_entries,
        (SELECT count(*) FROM oid_ledger_entry WHERE source_kind='tester_bonus' AND entry_type='refund')::text AS bonus_refund_entries,
        (SELECT coalesce(sum(amount_units),0) FROM oid_ledger_entry WHERE source_kind='tester_bonus' AND entry_type='debit')::text AS bonus_gross_units,
        (SELECT coalesce(sum(amount_units),0) FROM oid_ledger_entry WHERE source_kind='tester_bonus' AND entry_type='refund')::text AS bonus_refunded_units,
        (SELECT count(DISTINCT run.id) FROM oid_ledger_entry AS entry JOIN oid_benchmark_run AS run
          ON entry.operation_id='rundeb_'||replace(run.id::text,'-','')
          WHERE entry.source_kind='tester_bonus' AND entry.entry_type='debit')::text AS bonus_runs
    `));
  }, { isolationLevel: "repeatable read", accessMode: "read only" });
}

function fixtureSnapshot(): BetaUsageSupportSnapshot {
  const owner1 = "owner-1";
  const owner2 = "owner-2";
  const owner3 = "owner-3";
  const agent1 = "agent-1";
  const agent2 = "agent-2";
  const agent3 = "agent-3";
  const runTrainingFailed = { run_id: "training-failed", owner_id: owner1, agent_id: agent1, access_generation: 4, mode: "training", task_ids: ["S1"], status: "failed" };
  const runTrainingComplete = { run_id: "training-complete", owner_id: owner1, agent_id: agent1, access_generation: 4, mode: "training", task_ids: ["S2"], status: "completed" };
  const runTrainingCancelled = { run_id: "training-cancelled", owner_id: owner1, agent_id: agent1, access_generation: 4, mode: "training", task_ids: ["S1"], status: "cancelled" };
  const runFull = { run_id: "full-canonical", owner_id: owner1, agent_id: agent1, access_generation: 4, mode: "ranked", task_ids: [...TASK_IDS], status: "completed" };
  const runUnbound = { run_id: "historical-unbound", owner_id: owner2, agent_id: agent2, access_generation: 1, mode: "training", task_ids: ["S1"], status: "unknown" };
  const runConflicting = { run_id: "conflicting-family", owner_id: owner3, agent_id: agent3, access_generation: 7, mode: "training", task_ids: ["S1", "S2"], status: "completed" };
  const codexGrant = {
    grant_id: "grant-codex", owner_id: owner1, agent_id: agent1, access_generation: 4,
    source: "oauth", oauth_client_id: "sc023-codex-client"
  };
  const hermesGrant = {
    grant_id: "grant-hermes", owner_id: owner3, agent_id: agent3, access_generation: 7,
    source: "oauth", oauth_client_id: "sc023-hermes-client"
  };
  const codexGrantForAgent3 = {
    grant_id: "grant-codex-agent3", owner_id: owner3, agent_id: agent3, access_generation: 7,
    source: "oauth", oauth_client_id: "sc023-codex-client"
  };
  const action = (id: string, runId: string, ownerId: string, agentId: string, generation: number,
    grant: typeof codexGrant | typeof hermesGrant | typeof codexGrantForAgent3) => ({
    action_id: id,
    run_id: runId,
    owner_id: ownerId,
    agent_id: agentId,
    access_generation: generation,
    grant_id: grant.grant_id,
    grant_owner_id: grant.owner_id,
    grant_agent_id: grant.agent_id,
    grant_access_generation: grant.access_generation,
    grant_source: grant.source,
    oauth_client_id: grant.oauth_client_id
  });
  return {
    registeredOwners: 3,
    registeredAgents: 3,
    purgedReportReceipts: 0,
    runs: [runTrainingFailed, runTrainingComplete, runTrainingCancelled, runFull, runUnbound, runConflicting, runTrainingComplete],
    actions: [
      action("action-1", runTrainingFailed.run_id, owner1, agent1, 4, codexGrant),
      action("action-2", runTrainingComplete.run_id, owner1, agent1, 4, codexGrant),
      action("action-2", runTrainingComplete.run_id, owner1, agent1, 4, codexGrant),
      action("action-6", runTrainingCancelled.run_id, owner1, agent1, 4, codexGrant),
      action("action-3", runFull.run_id, owner1, agent1, 4, codexGrant),
      action("action-4", runConflicting.run_id, owner3, agent3, 7, hermesGrant),
      action("action-5", runConflicting.run_id, owner3, agent3, 7, codexGrantForAgent3)
    ],
    grants: [
      { grant_id: codexGrant.grant_id, source: "oauth", oauth_client_id: codexGrant.oauth_client_id },
      { grant_id: hermesGrant.grant_id, source: "oauth", oauth_client_id: hermesGrant.oauth_client_id },
      { grant_id: codexGrantForAgent3.grant_id, source: "oauth", oauth_client_id: codexGrantForAgent3.oauth_client_id },
      { grant_id: "manual-credential", source: "manual", oauth_client_id: null }
    ],
    reports: [
      { report_id: "report-1", owner_id: owner1, reporter_kind: "owner", reporter_id: owner1, operation_id: "report-op-1", run_id: runFull.run_id },
      { report_id: "report-1-retry", owner_id: owner1, reporter_kind: "owner", reporter_id: owner1, operation_id: "report-op-1", run_id: runFull.run_id },
      { report_id: "report-old", owner_id: owner2, reporter_kind: "owner", reporter_id: owner2, operation_id: "report-op-2", run_id: null }
    ],
    bonusLedger: [
      { entry_id: "bonus-debit", owner_id: owner1, operation_id: "rundeb_full", entry_type: "debit", source_kind: "tester_bonus", amount_units: "1000000", run_id: runFull.run_id },
      { entry_id: "bonus-refund", owner_id: owner1, operation_id: "runref_full", entry_type: "refund", source_kind: "tester_bonus", amount_units: "250000", run_id: null },
      { entry_id: "bonus-reserve", owner_id: owner1, operation_id: "full", entry_type: "reserve", source_kind: "tester_bonus", amount_units: "1000000", run_id: null },
      { entry_id: "cash-debit", owner_id: owner1, operation_id: "cash", entry_type: "debit", source_kind: "cash_usdc", amount_units: "9000000", run_id: runFull.run_id }
    ]
  };
}

test("usage export deduplicates stable identities and fails closed on missing or conflicting client bindings", () => {
  const exported = aggregateBetaUsageSupportExport(fixtureSnapshot(), REGISTRY, new Date("2026-10-29T12:00:00.000Z"));
  assert.equal(exported.metadata.scope, "all_retained_records");
  assert.equal(exported.metadata.asOfUtc, "2026-10-29T12:00:00.000Z");
  assert.equal(exported.metadata.clientRegistry.sha256, REGISTRY.sha256);
  assert.deepEqual(exported.metadata.clientRegistry.provenance, REGISTRY.provenance);
  assert.deepEqual(exported.metadata.connectionEvidence, {
    connectedObservedBasis: "authenticated_task_action", actualPreflightConnections: null
  });
  assert.equal(exported.owners.distinct, 3);
  assert.equal(exported.owners.withRunUse, 3);
  assert.equal(exported.owners.connectedObserved, 2);
  assert.equal(exported.owners.actualPreflightConnections, null);
  assert.equal(exported.owners.trainingUsers, 3);
  assert.equal(exported.owners.fullUsers, 1);
  assert.equal(exported.owners.repeatUsers, 1);
  assert.equal(exported.agents.distinct, 3);
  assert.equal(exported.runs.trainingAttempts, 5);
  assert.equal(exported.runs.fullAttempts, 1);
  assert.equal(exported.runs.completed, 3);
  assert.equal(exported.runs.failed, 1);
  assert.equal(exported.runs.unknownOutcome, 1);
  assert.equal(exported.runs.otherTerminal, 1);
  assert.equal(exported.runs.nonterminal, 0);
  assert.equal(exported.clients.codex.trainingRuns, 3);
  assert.equal(exported.clients.codex.fullRuns, 1);
  assert.equal(exported.clients.codex.failedRuns, 1);
  assert.equal(exported.clients.codex.otherTerminalRuns, 1);
  assert.equal(exported.clients.codex.repeatOwners, 1);
  assert.equal(exported.clients.codex.connectedObservedOwners, 1);
  assert.equal(exported.clients.unknown.trainingRuns, 2);
  assert.equal(exported.clients.unknown.unknownFamilyRuns, 2);
  assert.equal(exported.clients.unknown.reporterFamilyReports, 2);
  assert.equal(exported.clients.codex.reporterFamilyReports, 0);
  assert.equal(exported.clients.codex.reportsAssociatedWithRunFamily, 1);
  assert.equal(exported.support.reports, 2);
  assert.equal(exported.support.reporterFamilyUnknown, 2);
  assert.equal(exported.support.reportsAssociatedWithRunFamily, 1);
  assert.deepEqual(exported.support.retentionHistory, {
    status: "incomplete",
    completeLifetimeReportCount: null,
    purgedReportReceipts: 0,
    purgedOwnerOrClientAttribution: "unknown"
  });
  assert.equal(exported.support.manualSupportMinutes, null);
  assert.equal(exported.funding.bonusUsage.owners, 1);
  assert.equal(exported.funding.bonusUsage.runs, 1);
  assert.equal(exported.funding.bonusUsage.grossDebitedUnits, "1000000");
  assert.equal(exported.funding.bonusUsage.refundedUnits, "250000");
  assert.equal(exported.funding.bonusUsage.netUnits, "750000");
  assert.equal(exported.funding.paidConversion.status, "not_measured");
  assert.equal(exported.funding.paidConversion.owners, null);
  assert.equal(exported.accessGrantsIssued, 4);
  assert.equal(exported.oauthGrantsIssued, 3);
  assert.equal(exported.clients.codex.issuedOAuthGrants, 2);
  assert.equal(exported.clients.hermes.issuedOAuthGrants, 1);
  assert.deepEqual(exported.dataQuality, {
    duplicateRunRecords: 1,
    duplicateActionRecords: 1,
    duplicateReportOperations: 1,
    conflictingReportOperations: 0,
    conflictingClientBindings: 1,
    unboundHistoricalActivity: 2,
    reportsWithoutTrustedReporterBinding: 2,
    unlinkedBonusDebitEntries: 0
  });
});

test("usage export matches a repeatable read-only PostgreSQL snapshot without writes", { skip: !optIn }, async () => {
  const expectedDatabase = process.env.OID_BETA_USAGE_SUPPORT_PG_TEST_DATABASE ?? "";
  assert.match(expectedDatabase, EXPECTED_DB, "the opt-in regression requires a unique oid_acceptance database identity");
  const owner = createDatabase({ databaseUrl: acceptanceUrl(process.env.OID_DATABASE_URL, expectedDatabase, "oid_owner") } as OwnerIdentityConfig);
  const observer = createDatabase({ databaseUrl: acceptanceUrl(process.env.OID_OBSERVER_DATABASE_URL, expectedDatabase, "oid_observer") } as OwnerIdentityConfig);
  try {
    const ownerIdentity = first<{ database: string; role: string }>(await owner.db.execute(sql`
      SELECT current_database() AS database,current_user AS role
    `));
    const observerIdentity = first<{ database: string; role: string; read_only: string }>(await observer.db.execute(sql`
      SELECT current_database() AS database,current_user AS role,current_setting('transaction_read_only') AS read_only
    `));
    assert.equal(ownerIdentity.database, expectedDatabase);
    assert.equal(ownerIdentity.role, "oid_owner");
    assert.equal(observerIdentity.database, expectedDatabase);
    assert.equal(observerIdentity.role, "oid_observer");
    assert.equal(observerIdentity.read_only, "on");

    const before = await readOnlyFacts(observer.db);
    const exported = await buildBetaUsageSupportExport(owner.db, REGISTRY);
    assert.equal(exported.metadata.clientRegistry.version, REGISTRY.version);
    assert.equal(exported.metadata.clientRegistry.sha256, REGISTRY.sha256);
    assert.deepEqual(exported.metadata.clientRegistry.provenance, REGISTRY.provenance);
    assert.equal(exported.owners.distinct, Number(before.owners));
    assert.equal(exported.agents.distinct, Number(before.agents));
    assert.equal(exported.runs.trainingAttempts, Number(before.training_runs));
    assert.equal(exported.runs.fullAttempts, Number(before.canonical_full_runs));
    assert.equal(exported.runs.completed, Number(before.completed_runs));
    assert.equal(exported.runs.failed, Number(before.failed_runs));
    assert.equal(exported.runs.unknownOutcome, Number(before.unknown_outcome_runs));
    assert.equal(exported.runs.otherTerminal, Number(before.other_terminal_runs));
    assert.equal(exported.runs.nonterminal, Number(before.nonterminal_runs));
    assert.equal(exported.owners.connectedObserved, Number(before.connected_owners));
    assert.equal(exported.agents.connectedObserved, Number(before.connected_agents));
    assert.equal(exported.support.reports, Number(before.deduped_reports));
    assert.equal(exported.support.retentionHistory.purgedReportReceipts, Number(before.purged_report_receipts));
    assert.equal(exported.support.retentionHistory.completeLifetimeReportCount, null);
    assert.equal(exported.funding.bonusUsage.debitEntries, Number(before.bonus_debit_entries));
    assert.equal(exported.funding.bonusUsage.refundEntries, Number(before.bonus_refund_entries));
    assert.equal(exported.funding.bonusUsage.grossDebitedUnits, before.bonus_gross_units);
    assert.equal(exported.funding.bonusUsage.refundedUnits, before.bonus_refunded_units);
    assert.equal(exported.funding.bonusUsage.runs, Number(before.bonus_runs));
    assert.equal(exported.funding.paidConversion.status, "not_measured");
    assert.equal(exported.owners.actualPreflightConnections, null);
    assert.equal(exported.support.manualSupportMinutes, null);
    assert.equal(typeof exported.funding.bonusUsage.netUnits, "string");
    const after = await readOnlyFacts(observer.db);
    assert.deepEqual(after, before, "usage export must leave owner, run, report and ledger facts unchanged");
  } finally {
    await Promise.all([owner.client.end({ timeout: 5 }), observer.client.end({ timeout: 5 })]);
  }
});
