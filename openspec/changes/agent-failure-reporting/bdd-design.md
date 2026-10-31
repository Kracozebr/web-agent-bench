# Agent failure reporting BDD design

Normative source: [delta spec](specs/agent-failure-reporting/spec.md). Authorization: [approval](approval.md). All runtime gates initially `not_run`.

| Scenario | Boundary and observations | Negative/adversarial variants | Durable effects and evidence |
|---|---|---|---|
| AFR-SC-001 | Actual browser run admission → confirmed platform failure → same-agent MCP report/receipt → admin UI → readonly PostgreSQL | unchanged retry after uncertain response; wrong run/task/action link | one report/audit, same private links, unchanged run/task/action/grade/ledger; source-pinned raw capture and native/reference label |
| AFR-SC-002 | Handoff policy and actual support failure boundary | ordinary failed/partial grade; nonterminal null; no terminal confirmation; report unavailable; receipt denied; hidden payload injection | zero extra reports for ordinary outcomes; no reaccept/pay/finish/grade/refund; safe summary and snapshot hashes |
| AFR-SC-003 | Selected local profile file and actual authenticated MCP/PG boundary | already patched; concurrent config edit; forged principal; foreign link; expired/revoked grant | exact two-tool addition with backup; valid post-terminal report and receipt; zero unauthorized writes; config unit/JUnit and actual MCP auth PG proof |

Named mappers: `test_afr_sc_001`, `test_afr_sc_002`, `test_afr_sc_003`; adapter: `agent_failure_reporting`; gate: `environment`; mandatory: true. PNG attachment is optional and absent from this gate; a text report must work alone. Neither a prompt string test nor a toast proves native agent submission or PostgreSQL persistence. Replay must fail closed if runtime inputs are absent, malformed, secret-bearing, source-drifted or lack the independent admin/PG correlation.
