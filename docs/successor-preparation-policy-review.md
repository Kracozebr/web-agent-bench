# Owner-confirmed local successor-preparation policy

Date: 2026-10-28. This records a configuration decision for the approved BRL packet,
not a new scenario, an execution authorization, or a passing acceptance gate.

BRL-REQ-006 excludes queue/preparation time from execution clocks. The active
[design](../openspec/changes/benchmark-run-lifecycle/design.md) leaves numeric
timeouts unselected and requires versioned configuration before execution. The
900-second queue bound applies before the first start; it does not bound
preparation between selected tasks. Individual HTTP timeouts do not supply an
end-to-end wall-clock bound.

Owner-confirmed private local profile: **180 seconds per successor preparation**,
under `local-bef-successor-preparation/v1`. On 2026-10-28 the owner answered
«180 секунд — локальный профиль (рекомендуется)» to the 180/300 configuration
question, confirming the already selected engineering default. This numerical
choice does not by itself enable sequential execution. A
300-second alternative provides more tolerance for slow local startup. Neither
value is a production capacity or latency guarantee. The selected value must
be versioned and retained in the admitted run policy before charging; a later
configuration change cannot retarget an existing run.

The implementation retains version and seconds separately from the task-release
policy hash and quote. New local launch intents snapshot them before holds or
charges; acceptance copies that exact pair to the run. Existing rows are nullable
and receive no backfill. Multi-task admission/start requires a supported saved
pair; a legacy single-task run does not need a successor policy. The same saved
value, rather than a later server default, bounds successor preparation. These
implementation has focused PostgreSQL coverage and a private two-task runtime
capture, with the limits described below.

The interval starts at the preceding known task's persisted terminalization
timestamp and ends at the next task's atomic activation timestamp. Use database
time. The activation transaction adds that measured interval once to the old
overall deadline, retains the original run/charge/claim/slot identities, and
sets the next task deadline from its pinned task duration and adjusted overall
deadline. Replay verifies the original interval/event/binding instead of adding
time again. If the previous task had already exhausted execution time, no
successor starts.

The bound does not authorize action retries, credential restoration, unproven
grades, automatic refunds on generic errors, or revival of terminal runs.
Unknown preparation/effect evidence blocks advancement. Exact-generation fencing,
platform attribution and the existing bounded recovery/refund contract remain
required; this numeric choice alone does not close those dependencies. Cancellation
retains the existing pre-start/post-start rules and does not earn a new execution
clock adjustment.

Before broader sequential acceptance, verify the selected bound and immutable
policy snapshot, exact-once clock adjustment, cancellation/restart races, expiry
with no fabricated results, and all recovery/refund prerequisites. The current
S1/S2 positive runtime path does not prove those adversarial/recovery gates.

The fresh local capture `200e82e5-0616-48dd-813c-5f7271aa42d5` preserved the
intent/run v1/180 snapshot and observed actual server-worker preparation and
activation of S2 after S1. Its 3462-ms preparation interval extended the overall
deadline by exactly 3462 ms once; the original run/charge/claim/slot identities
were retained. Both known 1/1 results were read through the owner results button,
and independent stopped-state owner/BEF checks passed 16/16. That capture used an
internal grading/fencing/completion bridge. A subsequent separate automatic-worker
capture `93a9597a-c8d4-411b-9204-332aaa79912b` also completed S1/S2 and owner UI
readback, with a 3509-ms interval added once under the same saved v1/180 policy.
Neither positive path establishes the remaining expiry/unknown/refund/ranked
gates. Exact artifacts and hashes are in
[run admission acceptance](run-admission-acceptance.md).
