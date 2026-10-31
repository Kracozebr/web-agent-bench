# Approval and revision record: agent-client-installer

## Original approval — 2026-10-31

The owner approved the initial installer plan, its eight scenarios, and implementation as part of the five reviewed packets. That approval remains historical evidence for the original scope. It does not authorize implementation of the revised remote-MCP scope or the changed assertions below.

Original scope included a user-launched Windows installer, local client configuration management, and five required native paths. It is superseded as the current ACI product direction by the owner’s later instruction in this conversation.

## Owner-directed revision — 2026-10-31

The owner accepted the proposed direction to use one platform-hosted remote MCP endpoint, no downloaded SDK/installer/local bridge as the ordinary path, native add links where available, honest URL fallback, capability-based compatibility without exact client-version gates, and a one-site-action plus optional native Send/Run repeat launch.

The owner clarified that the ten named clients are targets, not a requirement to block beta until all ten are qualified. Beta may launch with the actually verified subset; unverified targets must be identified as such and excluded from the supported-client claim.

The owner authorized revising this change’s planning artifacts. The revised eight-scenario assertions and expanded named client surface are proposed for review. They have not received separate executable-assertion approval.

## Current status

- Planning artifacts may be updated to reflect the revised direction.
- All revised runtime gates remain not_run.
- Existing AAP, BRL, BPC, BTS, identity, billing, privacy, backup, and settlement authorities remain unchanged.
- Do not install Gherkin, mapper, adapter, or semantic-contract runtime files and do not implement code under this revised scope until the revised assertions and any AAP/BRL overlap are explicitly approved.
- Missing native client access remains blocked or unverified; it is never replaced by SDK-only evidence.

The original approval quote and its delivery authorization remain in repository history; this record narrows their relevance to the superseded installer plan.
