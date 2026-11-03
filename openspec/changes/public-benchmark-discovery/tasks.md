# Implementation and closeout tasks

Implementation is approved on 2026-10-31. Product code is being implemented; all six mandatory environment gates remain `not_run` until real capture and independent replay. See [approval](approval.md), [design](design.md), and [BDD packet](bdd-design.md).

## 1. Reconcile and freeze the boundary

- [x] 1.1 Reconcile PBD against BTS-REQ-001/002/004 and BTS-SC-001/002/007/008; BLP-REQ-001–003/009–011 and BLP-SC-013/015–017; BPC-REQ-014/BPC-SC-025 and BPC-SC-023. No legacy IDs, result history, exposure, grading, publication, or authorization rules change. Implementation/assertion scope remains the six approved PBD scenarios. Evidence: cross-change authority table in [design.md](design.md); approval dated 2026-10-31.
- [ ] 1.2 Freeze a real target/profile and resolve host/domain/HTTPS, validated release, independent observer, and required external client/operations prerequisites. These are not available in the current local source review; target acceptance remains blocked/not_run.
- [x] 1.3 No migration, new business record, or private evidence store is introduced by this change. Public GET projections are read-only; existing unified backup/restore remains a target release prerequisite and is not promoted by this code change.

## 2. Implement the approved public surfaces

- [x] 2.1 Install the approved six-scenario active-delta contract and generated Gherkin/named-mapper mirrors with the reproducible installer. Structural validation is required; no runtime evidence is created by installation.
- [ ] 2.1a Implement and register the approved `public_benchmark_discovery` adapter so each mapper drives its named real boundary and independently replays required observations, negatives, and durable effects. Do not substitute a source-only or self-asserted report adapter; the runtime gates remain `not_run` until this is complete.
- [x] 2.2 Replace the sign-in redirect with an anonymous product homepage, accessible public navigation, sign-in/connect links, the approved infrastructure-gap explanation, public rules, release-aware prices, metadata, and favicon. PBD-SC-001 browser/mobile/auth and durable-effect gate remains `not_run`.
- [x] 2.3 Publish twelve explicitly authored task-family goals, constraints, credit criteria, current Training roster, interpretation limits, and a catalog endpoint that only projects a consistent validated release/version/price. PBD-SC-002 release-bound browser/admission comparison remains `not_run`.
- [x] 2.4 Keep public task serialization allowlisted and omit release hashes/identity/manifest/cases; no private manifest serializer or issuance route is added. PBD-SC-003 canary/build/cache/hidden-path gate remains `not_run`.
- [x] 2.5 Reuse the existing authoritative public Ranked read model and best-result pointer; expose only discovery navigation, preserving its selection and privacy contract. PBD-SC-004 actual coordinator handoff/database/cache gate remains `not_run`.
- [x] 2.6 Distinguish healthy empty results, qualification restrictions, missing results, and unavailable service; provide safe retry on the list and do not weaken guards or error caching. PBD-SC-005 HTTP/manifest/cache transition gate remains `not_run`.
- [x] 2.7 Keep explanatory content separate from release/results activation; catalog release state is informational and does not enable a cohort. PBD-SC-006 target-profile and activation-denial gate remains `not_run`.

## 3. Prove integration before acceptance

- [ ] 3.1 Capture every approved observation and negative variant on frozen source/profile and independently replay raw paths/hashes; rerun applicable BRL/BTS/BPC/AAP/BLP regressions. Missing variants are non-passing.
- [ ] 3.2 Prove the real anonymous browser-to-API and eligible-result journeys against the selected target with independent database/BEF observation. Local UI or API tests alone do not pass the gate.
- [x] 3.3 No new durable records, private files, or mutation flows were added, so no new migration/rollback/restore rehearsal is applicable to this implementation. Existing unified backup/restore target controls remain required by BPC and PBD-SC-006.
- [ ] 3.4 Review mandatory gate results and external prerequisites; deliberate release activation, spec sync, and archive are allowed only after all required gates pass under `docs/task-design.md`.
