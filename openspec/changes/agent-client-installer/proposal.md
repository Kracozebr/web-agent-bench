## Why

Participants currently copy credentials, identifiers and client commands across a long setup guide. The approved product direction is automatic client setup, participant-owned model execution, and a renewable connection until explicit revocation.

Status: implementation and listed BDD assertions approved on 2026-10-31 after independent review. Planning validation and approval are separate from runtime acceptance. See [approval](approval.md) and the [cross-change index](../../../docs/beta-usability-spec-plan.md).

## What Changes

- Provide a user-launched installer that detects and configures the selected supported native client, with recoverable configuration edits.
- Use browser authorization, scoped renewable grants and secure local token storage; remove the manual 24-hour key from the ordinary path.
- Negotiate protocol and capabilities rather than matching an exact application version; qualify actual client paths.
- Deliver owner-authorized launch requests to the connected agent without copying Intent IDs and expose real connection status.

Non-goals and evidence boundary: Hosted model execution, model-provider credential custody, bypassing native consent, identity/version spoofing, silently changing unrelated client settings, automatic cap/permission increases, unqualified OS support and real-money authorization. A local reference adapter is not a participant-owned model run or target-host acceptance. No PvP fairness or settlement change is included.

## Capabilities

### New Capabilities

- `agent-client-installer`: Agent client installer and durable connection.

### Modified Capabilities

None of the three synchronized main capabilities is replaced in this planning packet. Integration with active deltas is recorded explicitly below and in design.md; existing active approval scopes are not silently amended.

## Impact

new installer packaging and client adapters; OAuth/grant/refresh storage and routes; existing MCP access policy and launch-intent integration; client status UI. No platform-hosted LLM, provider-key custody, real-money access or bypass of client consent.

Owns installer, refresh lifecycle, native client handoff and connection health. Existing agent-access-and-permissions (AAP), owner-identity-and-pilot-admission (OID), BRL and BPC remain authoritative for owner/agent binding, permission checks and run admission.

Dependencies: Can be designed in parallel with execution repair; its real-client acceptance requires BER correctness. The cabinet consumes connection and launch status; public pages link to the installer.

