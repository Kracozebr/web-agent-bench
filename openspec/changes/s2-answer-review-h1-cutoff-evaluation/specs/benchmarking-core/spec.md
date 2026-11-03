## MODIFIED Requirements

### Requirement: WB-REQ-002 Keep score dimensions and evidence status separate
The benchmark harness SHALL expose task outcome, latency, resource/cost, tool-safety, chain-effect,
and evidence-quality dimensions separately. Missing, delayed, contradictory, or unverifiable chain
evidence MUST be represented as `unknown` or `inconclusive` and MUST NOT be silently converted into
a successful outcome. A complete, authoritative cutoff census that proves a required delivery was
never requested MAY resolve that delivery check to the existing rubric's known partial result, but
payment SHALL NOT imply delivery and all other rubric and evidence checks SHALL still apply.

#### Scenario: WB-SC-002 A scorecard separates outcome cost latency safety and evidence
- **WHEN** a completed run is converted into a scorecard with partial chain evidence
- **THEN** the scorecard SHALL retain separate dimensions and mark the chain evidence status as `unknown` without changing the task outcome

#### Scenario: WB-SC-006 H1 grades a validated paid-child absence proof
- **WHEN** a closed H1 task has a successful required payment, no delivery for that payment, and the trusted admitted-action replay validates a complete paid-child cutoff proof with no same-payment retrieve admitted
- **THEN** the evaluator SHALL apply the existing H1 rubric to the observed facts, record its existing partial result, and complete the ordinary task/run handoff without changing the deadline or payment

#### Scenario: WB-SC-007 Ambiguous H1 retrieval evidence stays unknown
- **WHEN** the cutoff census or paid-child proof is missing, incomplete, contradictory, foreign, hash-mismatched, or a retrieve for the same payment was admitted
- **THEN** the evaluator SHALL retain `unknown` without inventing delivery, a score, or a new terminal cause
