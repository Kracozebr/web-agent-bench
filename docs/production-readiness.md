# Production and public-leaderboard readiness

The local harness is not a production benchmark service. Before publishing results or running
financially meaningful PvP, close the relevant gates:

- isolated agent execution with enforced CPU, memory, time, network, filesystem, and key policy;
- deterministic run bundles and replay divergence reporting;
- independent validation of score calculation and evidence provenance;
- named chain environment, receipt/finality policy, reorg handling, and reconciliation;
- authoritative match clock, monotonic event log, disconnect/late-action policy, and result signing;
- idempotent settlement with durable deduplication and an operator-visible reconciliation queue;
- redacted logs, retention, access control, and incident/audit procedures; and
- adversarial testing for prompt injection, tool abuse, sybil agents, collusion, denial of service,
  and invalid or delayed chain observations.

Until those gates pass, label outputs as local/reference, testnet, or experimental and keep them out
of a production leaderboard or payout decision.

