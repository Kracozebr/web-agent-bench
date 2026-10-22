# Real-time PvP

## Purpose

Define fair, replayable, real-time matches between web3 agents with an authoritative clock and
idempotent settlement boundary.

## Requirements

### Requirement: PV-REQ-001 Pin match identity and rules before start
The match authority SHALL create a match only after both declared agents are ready and SHALL pin the
participants, rules version, seed, clock/deadline policy, benchmark version, and settlement policy.
The pinned match specification MUST remain immutable after the match starts.

#### Scenario: PV-SC-001 A PvP match starts only after both agents are ready
- **WHEN** two declared agents become ready for a match with a selected ruleset and seed
- **THEN** the authority SHALL start the match with an immutable participant and rules snapshot and SHALL reject a one-sided start

### Requirement: PV-REQ-002 Own event order and deadlines at the authority
The match authority SHALL emit an append-only event stream with monotonic sequence numbers and
authoritative timestamps. Each accepted action MUST be associated with the active match, actor, turn or
phase, and deadline decision; client timestamps MUST NOT determine event order.

#### Scenario: PV-SC-002 Accepted PvP actions have authoritative monotonic order
- **WHEN** ready agents submit actions during an active match, including actions received close to a deadline
- **THEN** the authority SHALL record accepted actions in one monotonic sequence with its own deadline decision

### Requirement: PV-REQ-003 Make terminal outcomes stable across disconnects and late actions
The match authority SHALL record a terminal result once the rules determine an outcome. Disconnect,
reconnect, duplicate, and late actions MUST follow the pinned policy and MUST NOT mutate a terminal
result or its event history.

#### Scenario: PV-SC-003 A late action cannot mutate a terminal match
- **WHEN** an agent reconnects or submits a duplicate action after the authority has recorded a terminal result
- **THEN** the authority SHALL record the rejection or ignore decision and preserve the original result and event sequence

### Requirement: PV-REQ-004 Settle one match outcome idempotently
The settlement boundary SHALL bind one terminal match result to one settlement intent and a durable
deduplication key. Retrying the same settlement request MUST return the original outcome without
duplicating a payout, ledger effect, or on-chain submission; an ambiguous provider result MUST remain
reconciliation-required.

#### Scenario: PV-SC-004 Retrying settlement produces one durable outcome
- **WHEN** the same terminal match settlement is submitted twice with the same deduplication key
- **THEN** the settlement boundary SHALL return one stable outcome and SHALL record no duplicate effect

