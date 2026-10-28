# Incremental implementation review — 2026-10-26

Approved scope is unchanged; see [approval.md](approval.md). Boundary-specific
evidence and reproduction commands are in [the run-admission checkpoint](../../../docs/run-admission-acceptance.md).

Implemented the complete typed twelve-task manifest contract, public metadata,
open-training selection/pricing, fixed-set and hash validation, private
mode projections, and an immutable PostgreSQL registry. Eleven synthetic release
contract checks passed; they do not supply actual feasibility/reference evidence.
Registry integration uses a separate retained synthetic database without an API.

Added the actual participant-selected USDC transfer primitive. Its local-fork
capture independently binds HTTP, transaction input, receipt/log, balances, gas
and PostgreSQL rows; all 41 raw artifact hashes verified. Seventeen focused
executor persistence/cost/RPC checks passed. The primitive capture is explicitly
not BTS acceptance and contains no task grade.

Pure internal evaluators now cover the twelve rubrics; current-task issuance
provides the active agent's necessary conditions through HTTP/MCP. The release
schema also pins U1 routes and explicit recipient balance baselines. The current
Docker contract suite passed 37 checks across release, issuance, all twelve
rubrics, feedback and the retained transfer-artifact reader. These include
synthetic evaluator observations and do not constitute twelve runtime task
acceptances. Reverse-swap and multi-resource delivery primitive captures are
retained separately in the checkpoint. Run-bound commands, cutoff and immutable
evaluation storage are implemented; the actual observation adapter and complete
run execution remain unfinished.
There is no activated release, complete set of real case bundles, same-tool
reference paths for all tasks, actual observation-to-evaluator adapter or product
execution handoff.
No BTS mandatory scenario is promoted to passed. Gated task checkboxes remain
unchecked; no sync or archive is permitted.
