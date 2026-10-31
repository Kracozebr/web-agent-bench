# Benchmark execution reliability

Status: approved for implementation on 2026-10-31. Runtime acceptance is incomplete; see [current evidence](../../implementation-progress.md). [Design](../../design.md), [BDD packet](../../bdd-design.md), [approval](../../approval.md).

## ADDED Requirements

### Requirement: BER-REQ-001 Represent every valid action and finish answer through MCP
The MCP boundary SHALL accept every bounded command and declared finish-answer shape permitted by the task contract, including minimum and fully populated swap and S2 answers. Recursive element, byte and depth limits SHALL be finite, documented and compatible with those shapes; malformed or oversized inputs SHALL fail before admission with no side effect.

Scenario setup: Authenticated participant agent and the real declared tool schema

#### Scenario: BER-SC-001 Represent every valid action and finish answer through MCP
- **WHEN** the native MCP client submits valid nested swap/answers and malformed, excess-byte, excess-depth or forbidden-field variants
- **THEN** schema-valid payloads SHALL reach scoped admission or task validation; invalid payloads SHALL be rejected without action or financial writes, and no valid declared payload SHALL fail solely because nested fields exceed eight

### Requirement: BER-REQ-002 Disclose answer contracts without teaching a solution
Each issued task SHALL disclose its accepted answer schema or explicit no-answer contract and safe validation field paths. Only S2/S3 SHALL accept their structured answers under the current catalog. Descriptors SHALL NOT disclose reference answers or sealed material.

Scenario setup: Current S1/S2/S3 and an unrelated queued Ranked task

#### Scenario: BER-SC-002 Disclose answer contracts without teaching a solution
- **WHEN** the agent reads the issued contract and submits correctly shaped, wrong-shaped, missing or unexpected structured answers
- **THEN** validation SHALL identify correctable shape errors without leaking hidden values; contract-valid finish SHALL record one closure and invalid finish SHALL not consume the operation or close the task

### Requirement: BER-REQ-003 Resolve admitted actions across the task cutoff
Every action admitted before the committed cutoff SHALL reach an evidence-backed observed, rejected-before-execution or unknown receipt. Task deadline SHALL stop new admission without silently dropping existing outbox work. Unknown dispatch effects SHALL NOT be retried as new economic actions.

Scenario setup: Exact H1 third-payment shape admitted immediately before deadline

#### Scenario: BER-SC-003 Resolve admitted actions across the task cutoff
- **WHEN** the worker crosses the task deadline with pending delivery, loses a response, restarts or receives a late duplicate
- **THEN** the same action SHALL be reconciled or explicitly unknown, closure SHALL include its cutoff identity, and a duplicate payment, permanently invisible pending state or fabricated receipt SHALL not result

### Requirement: BER-REQ-004 Preserve unknown grading and terminate safely
A closed reconciled task whose observation or evaluation is unknown SHALL retain explicit unknown evidence and follow existing bounded platform recovery, fencing and source-linked compensation authority. It SHALL NOT hang until an unrelated clock, count unknown as agent zero, or invent eligibility.

Scenario setup: Ranked H1 with confirmed payment and closed cutoff but unknown evaluation

#### Scenario: BER-SC-004 Preserve unknown grading and terminate safely
- **WHEN** grading preflight remains unknown, recovers before the bound or exhausts around restart and owner cancellation
- **THEN** recovery SHALL observe original effects, select one authoritative terminal path, preserve the original reason and fence before resource release; no incomplete Ranked publication SHALL occur

### Requirement: BER-REQ-005 Diagnose and prevent successor preparation regression
The earlier pre-M3 failure SHALL be reproduced or explained with exact source-bound preparation evidence before a claimed fix. Successor preparation SHALL preserve predecessor grading/fence proof and original admission/financial identity; a health-only regression is insufficient.

Scenario setup: Original f54674d5 capture and a fresh serial Training3/Full12 profile

#### Scenario: BER-SC-005 Diagnose and prevent successor preparation regression
- **WHEN** M3 preparation encounters wrong origin, unavailable health, mismatched case pins, interrupted preparation or normal success
- **THEN** the preparation reason SHALL remain distinct from task failure and overall timeout; a repaired path SHALL issue M3 and complete a fresh serial Full12 with twelve terminal evaluations and exact cleanup

### Requirement: BER-REQ-006 Complete catalog rejection evidence
The release producer and independent replay SHALL exercise training_set_mismatch, training_weight_or_sum_mismatch, ranked_or_training_case_count_mismatch and release_identity_reuse under existing BTS-SC-001/002. A producer verified label or inventory listing SHALL NOT count as execution evidence.

Scenario setup: Actual release validation boundary and isolated malformed candidate artifacts

#### Scenario: BER-SC-006 Complete catalog rejection evidence
- **WHEN** each missing negative control and a valid current catalog pass through the producer and independent raw replay
- **THEN** all four invalid candidates SHALL be rejected before activation/reservation with exact reasons and unchanged active identity; valid Training S1/M1/H1 and Ranked twelve SHALL remain admissible

### Requirement: BER-REQ-007 Recover and replay without rewriting business history
Crash recovery SHALL resume only authorized idempotent unfinished durable transitions, including the first owed evaluation, completion or source-linked refund, without duplicating task effects or replacing committed history. Independent artifact replay SHALL be strictly read-only: no command dispatch, business writes, score replacement or refund issuance. Missing proof or divergence SHALL remain non-passing.

Scenario setup: Fresh serial Training3 and complete Full12 with all evidence paths and hashes

#### Scenario: BER-SC-007 Recover and replay without rewriting business history
- **WHEN** response loss and restart interrupt cutoff, grading, successor activation and completion handoff, then raw evidence is replayed twice
- **THEN** crash recovery SHALL complete each authorized pending transition at most once; independent replay SHALL reconstruct one consistent original history or report divergence without writes, while task identities, finance sources, claims, slots, fences and publication eligibility remain authoritative

### Requirement: BER-REQ-008 Attribute failures with bounded diagnostic evidence
Participant feedback SHALL separate agent contract/goal failure, agent deadline, platform preparation/dispatch/observation failure and unknown attribution using durable causal evidence. Client logs alone SHALL NOT authorize compensation or change official grades.

Scenario setup: Original Training 1faa495d and Ranked 6adddaa9 evidence plus a repaired-profile capture

#### Scenario: BER-SC-008 Attribute failures with bounded diagnostic evidence
- **WHEN** an owner opens results and compares native tool failures with persisted admissions, receipts and evaluations
- **THEN** the projection SHALL show eight evaluated Ranked tasks as their original records, mark four other tasks unevaluated, identify the MCP contract defect separately, and avoid attributing unissued or platform-unknown tasks to agent failure

