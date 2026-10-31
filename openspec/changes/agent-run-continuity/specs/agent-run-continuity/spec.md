# Agent run continuity

## ADDED Requirements

### Requirement: ARC-REQ-001 Execute the complete handoff continuously
The system SHALL enforce the scoped continuity boundary described below without changing historical grades, deadlines, prices, refund authority or task goals.

Scenario setup: An owner-created Training intent and native client

#### Scenario: ARC-SC-001 Execute the complete handoff continuously
- **WHEN** the owner copies the complete handoff and the client executes that single request
- **THEN** the request SHALL contain the actual agent and intent IDs, selection and unchanged limits; the native client SHALL continue after acceptance through every task until explicit terminal status, without a second execution prompt, duplicate admission or secret disclosure

### Requirement: ARC-REQ-002 Expose authorized run progression through MCP
The system SHALL enforce the scoped continuity boundary described below without changing historical grades, deadlines, prices, refund authority or task goals.

Scenario setup: An authenticated agent and queued running and terminal runs

#### Scenario: ARC-SC-002 Expose authorized run progression through MCP
- **WHEN** the client reads current_task through preparation grading and termination or after authorization changes
- **THEN** the response SHALL retain task and add scoped run status, terminal flag, waiting state and retry hint; task null SHALL NOT imply completion, denied principals SHALL receive no projection, and reads SHALL cause no business writes

### Requirement: ARC-REQ-003 Grade proven unrequested retrieval without fabricating absence
The system SHALL enforce the scoped continuity boundary described below without changing historical grades, deadlines, prices, refund authority or task goals.

Scenario setup: A closed M1 with confirmed payment and no admitted retrieve at cutoff

#### Scenario: ARC-SC-003 Grade proven unrequested retrieval without fabricating absence
- **WHEN** the worker evaluates the authoritative absence proof and its missing contradictory or admitted-retrieval variants
- **THEN** only complete matching cutoff census and source evidence SHALL permit ordinary known failed M1 credit zero; H1 SHALL still be issued and completed under the existing run policy, while missing ambiguous contradictory or admitted retrieval evidence SHALL remain unknown without invented delivery or refund authority

