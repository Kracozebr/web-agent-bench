## 1. S2 owner answer review

- [x] 1.1 Add an owner-only read projection for the final S2 answer from the hash-verified retained evaluation input, gated on terminal run and task state.
- [x] 1.2 Add the submitted-answer field to the owner S2 result/report view and render it as escaped structured text; do not return case, reference, or journal data.
- [x] 1.3 Add focused API/UI checks for owner access, terminal and hash gates, exact answer equality, hidden-field omission, and read-only behavior.

## 2. H1 cutoff evaluation

- [x] 2.1 Replay the retained H1 paid-child packet through projection and evaluator; record whether the absence proof is minted and the exact preflight predicate that blocks grading.
- [x] 2.2 Apply the smallest correction to the proven failing projection/authority gate; never accept an unvalidated child reference.
- [x] 2.3 Add positive and adversarial evaluator coverage: proven H1 no-retrieve becomes the existing partial result; incomplete, mismatched, contradictory, or same-payment retrieve evidence remains unknown.

## 3. Acceptance and evidence

- [x] 3.1 Add the approved Gherkin scenarios, named mappers, adapters, and semantic harness contracts for OAR-SC-001/002 and WB-SC-006/007.
- [x] 3.2 Verify S2 through the actual browser → owner API → PostgreSQL path and inspect the exact submitted value against the retained input hash.
- [ ] 3.3 Verify H1 with a fresh bounded browser-started Training run through the worker and local BEF using the native MCP action path; independently confirm cutoff proof, existing partial grade, single handoff, and unchanged payment identity. Blocked for this pass: the user said Training runs are not needed; no fresh H1 run was started.
- [ ] 3.4 Record gate results and raw evidence references; keep unavailable environment gates blocked and preserve all historical run rows unchanged. Partial: local checks and the read-only S2 database verification passed; fresh H1 environment evidence remains unavailable.
