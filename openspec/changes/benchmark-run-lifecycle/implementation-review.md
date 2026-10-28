# Incremental implementation review — 2026-10-26

Approved scope is unchanged; see [approval.md](approval.md). Implementation and
capture details are in [the run-admission checkpoint](../../../docs/run-admission-acceptance.md).

Launch-intent HTTP/MCP/UI, PostgreSQL source reservations, queue claims, atomic
start/debit and durable cancellation primitives are implemented. The retained
72-observation PostgreSQL capture described in the checkpoint passed with explicitly synthetic
release/readiness/fence ports, and the actual owner browser displays unavailable
release without creating a financial effect. This does not establish a positive
browser/selected-client launch or any complete BRL environment scenario.

The real task-release registry remains empty; execution readiness and numeric
product policy are unconfigured. No scheduler claims or starts product work.
The registry now has a serialized immutable activation-order journal and
idempotent same-pointer replay. Current-task issuance is wired into HTTP/MCP
with exact-grant, current-mode, deadline and pinned-snapshot checks. Task-action
admission/status and explicit finish now use HTTP/MCP, a durable command outbox,
one authoritative cutoff and append-only receipt reconciliation. Unknown effects
block new commands; a known original transaction cannot be replaced or erased.
The immutable evaluation store, read-only reconstruction and private feedback
projection are implemented and tested using synthetic observation ports.
Actual observer integration, execution recovery, task advancement, eligibility
and the remaining integration variants are incomplete. The selected BEF bridge
is being verified separately; it is not enabled as a product worker.
The mandatory BRL BDD adapter/gates remain unaccepted.

Task checkboxes requiring those complete gates remain unchecked. No spec sync
or archive is permitted by this checkpoint.
