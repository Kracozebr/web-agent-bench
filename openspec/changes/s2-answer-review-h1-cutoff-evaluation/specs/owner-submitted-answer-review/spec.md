## ADDED Requirements

### Requirement: OAR-REQ-001 Show only the owner's retained S2 submission
The owner result view SHALL expose the exact final submitted S2 answer only when the authenticated owner owns the run, the run and S2 task are terminal, and the immutable evaluation input is present and passes its stored hash check. The projection SHALL contain only the submitted answer; it SHALL NOT expose the reference answer, sealed task case, expected evaluation fields, unrelated observations, raw action responses, or a chronological run journal. The view SHALL be read-only and SHALL NOT create a duplicate answer record.

#### Scenario: OAR-SC-001 Owner inspects a terminal S2 submission
- **WHEN** the owner opens the S2 result for a terminal run whose retained evaluation input contains a final answer
- **THEN** the report SHALL show the exact submitted structured answer from that hash-verified input and SHALL omit all reference, sealed-case, and unrelated action data

#### Scenario: OAR-SC-002 Missing or unauthorized answer remains unavailable
- **WHEN** a foreign owner requests the result, the run or task is still active, or the retained evaluation input is missing or fails hash verification
- **THEN** the system SHALL return no submitted-answer content, SHALL preserve the existing result/unknown status, and SHALL create no durable mutation
