## Context

The backend already exposes `support.report` and `support.report_receipt`, derives the reporter from the current bearer, validates private run/task/action links and deduplicates unchanged submissions by operation ID. The local `w3bench_user` profile exposes only six benchmark tools. The handoff currently asks for a chat summary only.

## Goals / Non-Goals

**Goals:** Send one safe private report after an explicitly confirmed terminal platform failure; confirm its receipt and make it visible in the real admin report queue. Keep this available after the run ends while the same grant remains valid.

**Non-Goals:** Automatic bug reports for ordinary failed/partial task grades; additional task execution, retries of economic effects, grade changes, external messaging, mandatory screenshots, credential refresh or a new installer product.

## Decisions

Use only the existing two text support tools in addition to the six benchmark tools. Their side effects are private support rows, with no benchmark action or billing authority. Screenshots remain optional through existing explicit capabilities; text reporting requires no local file, shell or browser access.

The trigger requires `run.terminal === true` and a server-reported platform failure category, including `coordinator_evaluation_unknown` or another explicit infrastructure/preparation/observation failure. A task's failed/partial outcome, a confirmed payment without delivery, waiting with `task:null`, or an unexplained transport timeout is not enough. Preserve unresolved status in chat when confirmation is unavailable.

Use deterministic operation ID `afr_` followed by the run UUID without hyphens, preserving exactly the same title/body/links for any bounded unchanged retry. Include only known run/task/action IDs, confirmed run status/reason, tool names and safe error codes. Never include Ranked conditions/variants/answers, tool payloads, signatures, bearer values, provider data, raw responses or account details. Confirm the returned report ID through `support.report_receipt`. Reporting failure is a separate unresolved result and never admits another run or changes task/financial results.

The deployment patch performs a dry-run by default, verifies a caller-reviewed full-file SHA before writing, refuses unexpected profile shapes, backs up privately alongside the original config and preserves all unrelated content. Root applies it after independent qualification of existing captures. An already-running Codex session must reconnect/restart its MCP session to obtain newly allowed tools.

## Risks / Trade-offs

[An expired/revoked grant cannot report] → Fail closed and retain a safe chat diagnostic; do not switch identity. [A model may summarize instead of submit] → Explicit handoff protocol plus actual native tool transcript when claiming native acceptance. [A report accidentally copies private cases] → Restrict the report template to identifiers/enums and verify capture/body contents independently. [Configuration concurrency] → Expected-hash compare and private exact backup before atomic replacement.

## Execution and evidence boundary

Product E2E starts with a real UI run admission, retains the actual terminal failure response, sends MCP report and receipt under the same agent, opens the report in the real admin UI, then independently reads PostgreSQL report/audit/link rows. Compare run/task/action/ledger snapshots before and after reporting. Reference SDK evidence is labelled separately from native Codex behavior. Source-hashed JUnit covers revoked/expired/foreign links and retry/report-failure behavior. Runtime remains `not_run` until retained raw captures pass an independent reader; no historical grade is rewritten.
