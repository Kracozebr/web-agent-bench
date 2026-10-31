# Paid-delivery cutoff verification

## Diagnosed user run

Run `31ff0148-7376-4a22-b255-a42b9b5bfe9a` has durable S1/M1 grades 1/1.
H1 started 2026-10-31 16:31:17.620 UTC and closed at its original deadline
16:32:17.620 UTC. Treasury payment was admitted at 16:32:06.458 and observed at
16:32:09.906; no treasury retrieval was admitted. A different resource was genuinely
retrieved. The worker's retained reason is `paid_resource_delivery_unobserved`;
after the unchanged 180-second observation window the run cancelled with
`coordinator_evaluation_unknown`. No RPC outage is established by these observations.

The source packet has observed coverage, six closed H1 actions, two confirmed
payments and one delivery. It distinguishes a task deadline failure from the
platform's inability to classify a provable non-request. The correction keeps
ordinary rubric failed/partial credit separate from genuine unknown evidence.

## Catalog audit

| Mode/task | Collector | Scope of this correction |
|---|---|---|
| Training M1 | dedicated M1 | Per-payment proof, including unrelated retrieval edge |
| Training H1 | paid data | Previously omitted; shared proof required |
| Ranked M1/M2/H1 | paid data | Previously omitted; shared proof required |
| Ranked H3/U1 | composite paid + chain | Shared proof plus independently verified child authority |
| S1/S2/S3/S4/M3/M4/H2 | transfer, inspection, allowance or chain | Existing rubric and unknown safety retained |

Current open Training is S1/M1/H1. Full Ranked remains all twelve tasks.
The baseline audit of all twelve uses synthetic existing evaluator fixtures;
removing only a delivery observation correctly produces unknown without proof.
It does not prove a real runtime no-request census. That proof is verified separately.

## Canonical checks

Final compiled backend and enabled PostgreSQL suites: 158 executed testcases,
zero failures, errors or skips. Includes all twelve evaluator contracts, five
paid-family absence/ambiguity matrices, composite identity, legacy hashes, both
M1 per-payment cases and sealed replay. Exact command, source hashes and actual
JUnit are recorded under `artifacts/runs/paid-delivery-cutoff-validation/`.

Mandatory live Training and full Ranked captures passed independent replay and
all four BDD gates (zero failed or blocked). Independent-reader tests: 7 passed.
Capture `fbadf265-3c64-4840-bb96-59113039455f` retained stable producer sources.

| Actual run | Result |
|---|---|
| Training `d8ffc615-ea0e-4b28-91b9-9b0ed6e974d9` | completed; S1/M1 1/1, H1 2/3 after original deadline |
| Ranked `1228f4e0-141d-49af-94ec-00c64577b049` | completed; all twelve known results |

Ranked: S1/S3/S4/M3/M4/H2 passed 1/1; S2 partial 7/10; M1/M2/H3/U1
failed 0/1; H1 partial 2/3. The five paid goals were deliberately left without
one retrieval, so these failed/partial grades are expected test outcomes, not
successful solving claims. H3/U1 child source hashes and exact authority were
independently checked. One quoted debit per run, no refunds/cash, empty slots,
released claims and all exact owner/BEF generation fences were confirmed.
All nine historical fingerprint sets for the user's run matched before/after.

The Ranked S2 probe found a separate defect: required `version`, `paymentFlow`
and `name` are absent from public inspect_offer. The actor submitted only public
data, receiving the correct existing 7/10 rubric fraction. This is explicitly
recorded as an open disclosure defect (`betaReady: false`), not accepted as S2
full-credit or beta-readiness evidence. Its dedicated correction is tracked in
the subsequent S2 change. The original stand remains stopped while that and
agent reporting integration are qualified; restoration is still a delivery task.

Actual hash references, JUnit command/source identities and preserved-history
report are in `tests/bdd/changes/paid-delivery-cutoff-consistency/runtime-inputs.json`.
Reference MCP execution is identified separately from native model execution.
This change does not claim external-beta, mainnet or all prior BER gates.

## Reporting integration finding

The backend implements `support.report`, `support.report_receipt` and screenshot
tools. The current participant's `w3bench_user.enabled_tools` exposes only six
identity/run tools and filters out every `support.*` tool. The handoff asks for
errors in the final answer but does not instruct an MCP report submission.
Consequently capability implementation did not make automatic reporting active
for this connection. No report linked to the diagnosed run exists in PostgreSQL.
Enabling/report-trigger policy is recorded as a separate integration gap; this
grading correction does not silently expand client capabilities.

The owner's subsequent explicit instruction to address agent reporting and S2
has assigned separate subagents/changes; this report records the completed PDC
boundary before those source changes.
