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

## Renewed implementation approval — 2026-10-31

The owner subsequently explicitly instructed implementation with separate UI and remote-MCP agents after the successful Training/Ranked work was committed and pushed, using the revised remote-MCP change. This renews approval for the existing eight ACI scenarios and their revised assertions: canonical remote endpoint with honest URL fallback, owner/selected-agent consent, renewable bounded tokens, scoped versus agent-wide revocation and restore fencing, capability-based protocol/schema checks, authenticated free preflight, selected-connection launch intent, and truthful native-client qualification. The earlier pending-approval statements above describe the superseded planning checkpoint; they do not require another approval for this scope.

No installer, local bridge, hidden client-configuration write, provider-key collection, exact application-version gate, price/rubric/timer/refund change, or claim for an untested client is authorized. Existing AAP and BRL authorities remain in force. Implementation and structural checks do not establish native-client/browser acceptance. All mandatory environment gates remain not_run until real captures and independent replay prove them; missing infrastructure or clients remain blocked/unverified. No live migration, restart, global client configuration, or operator-secret change was performed by the remote-MCP implementation agent.
