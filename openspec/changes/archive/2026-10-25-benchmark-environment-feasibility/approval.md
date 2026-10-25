# Implementation authorization

Date: 2026-10-23. Boundary: owner authorization, not execution evidence.

After the explanation of the next BEF slice, its twelve executable scenarios and
the stage-2 browser/MCP/API/database journey, the owner instructed:

> ок, давай продолжай, для реализации используй луна макс сабагентов, энд ту энд действительно должны быть от клика кнопки в браузере до конечного результата (запись в бд, изменения на бэкенде)

This authorizes implementation of the existing BEF-SC-001–012 scope, its
active-delta harness and minimal isolated acceptance deployment. Use Luna/max
subagents for implementation and retain a separate parent review. Project-local
dependency/bootstrap work needed for this scope is included. Existing scenario
assertions, required negative variants and evidence boundaries remain in force.

Source block/contracts, runtime/SDK versions, x402 scheme/asset compatibility,
funding and numerical guardrails must be concretely pinned and verified before
executing environment gates. Unknown observations are not passing results. A
changed asset/scheme boundary or new scenario still requires the scope review
specified by this packet. Source-network writes, customer funds and production
deployment are outside this acceptance deployment.

The E2E requirement applies to actual user-facing journeys as they are implemented:
start the action through a real browser control, exercise the running backend,
and independently inspect the expected persisted database/backend effects.
DOM-only checks, localStorage state, intercepted success responses and direct
API calls that bypass the initiating browser action do not establish that E2E.
Integration probes of the BEF environment remain labelled environment/integration
gates; they do not establish the stage-2 user journey or owner/agent authentication.

All twelve runtime gates remain `not_run` until actual execution. Implementation
authorization does not mark any prerequisite, scenario or later MVP slice passed.
