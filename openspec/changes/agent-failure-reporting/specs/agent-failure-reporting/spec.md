# Agent failure reporting

## ADDED Requirements

### Requirement: AFR-REQ-001 Report confirmed terminal platform failures privately once
The participant handoff SHALL require exactly one idempotent private `support.report` after an authoritative terminal run response explicitly identifies a platform execution/preparation/observation/evaluation failure, including `coordinator_evaluation_unknown`. It SHALL retain known run/task/action links, submit only safe identifiers/status/error codes, reuse deterministic `afr_<run UUID without hyphens>` operation ID and unchanged content for a bounded retry, and confirm the returned report ID with `support.report_receipt`. An MCP error or unavailable receipt SHALL remain an explicit reporting failure.

Scenario setup: A browser-admitted run has an actual terminal platform failure and the same authenticated agent still has a valid grant

#### Scenario: AFR-SC-001 Confirm one private platform failure report
- **WHEN** the agent observes the confirmed terminal platform failure, submits the report, encounters an uncertain response and retries the unchanged operation
- **THEN** one report and its creation audit SHALL persist for the same owner/agent/run/task/action, the receipt SHALL identify that report, the admin UI SHALL show it, and reporting SHALL not change benchmark, task, action, grade or ledger state

### Requirement: AFR-REQ-002 Keep ordinary benchmark outcomes and reporting failures separate
An ordinary failed or partial task outcome, payment without delivery, transient wait, null task or unconfirmed transport error SHALL NOT by itself trigger an automatic platform-bug report. Reporting SHALL never relaunch/reaccept a run, retry payment, finish a task again, change an evaluation or claim a support report was delivered without a receipt. Report content SHALL exclude credentials, signatures, raw responses, account data and hidden Ranked conditions/answers.

Scenario setup: Ordinary benchmark failure, nonterminal wait and a terminal platform failure whose reporting tool fails are observed

#### Scenario: AFR-SC-002 Preserve benchmark state when reporting is unnecessary or fails
- **WHEN** the agent encounters ordinary failed/partial outcomes or nonterminal null tasks, then separately encounters a denied/unavailable report or receipt operation
- **THEN** ordinary outcomes SHALL create no automatic bug report, and a failed report/receipt SHALL preserve the original run/task/action/financial state while the final summary states reporting is unresolved without exposing protected payloads

### Requirement: AFR-REQ-003 Expose scoped text reporting after terminal run status
The reviewed local participant profile SHALL include exactly the existing six benchmark tools plus `support.report` and `support.report_receipt`, with the reviewed explicit approval policy and no added screenshot/local-file/command capability. Reporting SHALL remain available after run termination while the grant is valid; expired/revoked grants, another owner/agent's links and forged principal fields SHALL remain denied before report writes. A configuration update SHALL preserve unrelated settings and use a private backup and concurrency check.

Scenario setup: Existing six-tool Codex profile, valid terminal-run grant and revoked/expired/foreign-link negative grants

#### Scenario: AFR-SC-003 Preserve report authorization and profile scope
- **WHEN** the scoped configuration is prepared/applied/repeated or conflicts with another edit, and report tools are called after terminal status or using revoked/expired/foreign credentials
- **THEN** the valid agent SHALL retain private text report/receipt access after the run ends, invalid authority SHALL produce no report or benchmark writes, and only the two approved support tools SHALL be added without changing unrelated configuration
