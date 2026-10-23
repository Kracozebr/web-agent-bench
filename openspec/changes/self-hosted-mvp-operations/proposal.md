## Why

The selected single-server MVP needs reproducible deployment, bounded storage and
observed local recovery. The user selected 30 days for detailed internal run logs
and deferred external backup storage, so operational claims must reflect that scope.

Status: proposed; scenario and implementation approval are pending.

## What Changes

- Define pinned Docker Compose development/server profiles for the accepted stack,
  with persistent volumes, narrow service networks and separate test/payment roles.
- Verify configuration/readiness, bounded worker/storage admission and restart
  behavior through actual services, durable state and fenced old workers.
- Implement the selected 30-day detailed-run-log window with protected result,
  financial and compact evidence records and holds for unresolved investigations.
- Specify proposed terminal-time aging, safe cleanup paths, concurrency handling,
  evidence-availability markers and no early deletion to hide disk pressure.
- Add bounded consistent local database/file backup sets and isolated local restore
  checks, preserving the explicit absence of total-server-loss recovery coverage.
- Fence monetary writes, broadcast and stale job authority after restore until
  required reconciliation; provide safe operator health/backup/retention visibility.
- Require a separately observed deployment check on the actual selected Linux host;
  local container evidence alone cannot establish that host's capacity or readiness.

Non-goals: off-host storage/integration, five-minute recovery guarantees, high
availability, a full Base node, automated mainnet disaster reactivation, new domain
billing/auth rules, full task grading, PvP or paid monitoring services.

Retention duration/exemptions and deferred external storage are user-selected.
Cleanup mechanics, local backup cadence/quota/tooling, restore fencing and operator
reactivation are proposed engineering scope; exact configuration needs review.

## Capabilities

### New Capabilities

- `self-hosted-mvp-operations`: actual deployment/readiness and resource boundaries,
  safe run-log retention, bounded local copies/restore and honest operator evidence.

### Modified Capabilities

None. Preserve synchronized `benchmarking-core` and `realtime-pvp` and consume the
other proposed lifecycle, environment, payments, access and result contracts.
Do not replace their execution, ledger, authorization or scoring authorities.

## Impact

Future Compose profiles, pinned configuration/runbooks, backup/restore and cleanup
jobs, PostgreSQL retention/backup manifests, bounded persistent file storage,
private operator status and Python real-environment acceptance adapters.

This affects benchmark evidence availability and the deployment/recovery boundary
of money operations, without claiming chain settlement safety or changing normal
owner-confirmed withdrawal policy. No container, backup, cleanup, restore, user
server connection or executable test is run by this proposal.
