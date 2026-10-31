# Local continuity qualification

Boundary: disposable browser owner/admin UI, real backend/coordinator, local BEF/RPC,
read-only owner/BEF PostgreSQL and sealed files; native participant uses the operator's
existing Codex OAuth and the pinned 0.165.0 CLI. Google login in this disposable fixture
uses the local provider fixture. This is not external-beta or mainnet acceptance.

The independent BDD reader, not the producer's `verified` label, decides acceptance.
Final local qualification passed: 3/3 mandatory BDD scenarios, zero failed or blocked.

## Qualified capture

Capture `396226a1-1f9e-47e2-866c-5f49d008b2f3`, frozen before/after source inputs:

| Profile | Run | Confirmed result | Capture SHA-256 |
|---|---|---|---|
| Controlled deadline | `99b43934-85fe-47fe-8acf-14f738d3bcd2` | completed; M1 failed 0/1, H1 passed 1/1 | `4cce5f20355455a4e5800d0b2edccdec349ea234b8ae94831bc4ce8fda50d4f2` |
| Native handoff | `705704cd-efd5-42ad-9639-f612474cccb8` | completed; S1/M1/H1 passed 1/1 | `e6079626cbfe614e87cbd334b404523d71b75dd84bcf0e03d5be8243e6e5713a` |

Native: actual clipboard equals UI handoff; 44 MCP calls, zero local calls, zero tool
errors; explicit native terminal response. Participant credential file was removed.
Each run has one quoted bonus debit, no refund or duplicate payment, released slots
and exact owner/source generation fences. Browser result reads match durable grades.
Eight independent-reader tests passed, including four rehashed mutations of the actual
capture. Original run fingerprints match across all nine source sets.

`tests/bdd/changes/agent-run-continuity/runtime-inputs.json` pins both captures, actual
JUnit negative reports and the historical preservation report. Local artifacts are
ignored; a checkout without those files cannot reproduce environment acceptance.

Reproduce locally with the guarded Docker acceptance runner
`node packages/owner-acceptance/src/runner.mjs --agent-run-continuity-only` and Windows
broker `node tools/run_arc_native.mjs --capture-id <captureId>`, using the documented
runtime overlays and loopback-only `39001:4500` mapping. Independently replay with
`.venv/Scripts/python.exe tools/run_bdd_acceptance.py --change agent-run-continuity`.

The ordinary Google stand was restored with the executor enabled: `/healthz`, public
`/api/identity/config` and `/sign-in` returned HTTP 200; Google mode and admin configured.
An optional second history comparison after readiness was not run: automatic permission
review timed out twice before execution. The completed before/after observer comparison
and mandatory BDD historical gate passed; this optional retry does not replace them.

## Completed regressions

- Backend suites: Node reports 72 passed, zero failures/skips, including the enabled
  PostgreSQL issuance, sealed-source and training-lifecycle suites.
- Handoff: 3 passed; backend/frontend TypeScript checks passed.
- Native bridge: 7 passed, including finite SSE framing, exact forwarding, source pins,
  private job lifecycle and safe response projections.
- Nonblocking HTTP tracing: 2 passed.
- Independent reader: 8 passed, zero skipped, using the qualified controlled capture.
- Strict OpenSpec validation and semantic BDD audit: valid, 3/3 protected scenarios.

JUnit and source-bound negative reports are under
`artifacts/runs/agent-run-continuity-validation/` (ignored local evidence).

## Diagnostic captures retained

- `64557e3e-35b4-4c46-b870-62b78bc40ec5` and
  `0ce115dc-8504-4c69-bae3-73a314abce90`: stopped before run admission. The reference
  SDK rejected a legacy protocol pin before sending a request. The reference client now
  uses its supported modern protocol; native Codex retains its pinned legacy profile.
- `084ae5ba-c8d7-4e4e-b12e-8b821f23b49f`: controlled run
  `574db38e-a622-4428-9c90-bbc727376e71` completed with M1 failed 0/1 and H1 passed 1/1;
  native run `46b405f0-60ce-433a-839c-89edcb51bbfa` completed with S1/M1/H1 passed 1/1.
  Native performed 61 MCP calls, zero local calls, one recovered tool error. These are
  diagnostic runtime results, not final ARC acceptance: clipboard read permission,
  finite-SSE projection and PostgreSQL string-sequence replay needed correction.
- `2bebab9a-f710-4cce-9191-66bfbba660e1`: controlled and native physical replays
  passed, including the real clipboard and explicit native terminal response. Native run
  `df3fe4cc-4249-4bbb-9902-22168449465f` completed all three tasks at 1/1, with 42 MCP
  calls, zero local calls and zero tool errors. An adversarial evidence-copy test then
  exposed a missing duplicate-H1-action check in the independent reader. That check
  was added; the final qualification uses a fresh capture with the revised reader.

The original user run `a6e58ea5-11a2-4476-8619-3bfab98e22d3` is never regraded or
refunded by this change. Independent read-only fingerprints cover its run, tasks,
actions, receipts, evaluations, closures, ledger, reports and screenshots.
