## Why

The installer plan would require participants to trust and run a downloaded local package, then maintain client-specific setup and compatibility profiles. The Codex investigation shows that a client can be blocked by an MCP wire-profile mismatch even when the package version itself is not the cause. The owner has chosen a platform-hosted remote MCP connection with capability-based compatibility and no required local software.

## What Changes

- Replace the user-launched installer and local credential bridge with one platform-owned HTTPS remote MCP service.
- Make browser OAuth and explicit owner consent the ordinary connection path. Use a client’s official add/import link when available; otherwise show its native remote-server setup with the canonical URL.
- Keep client and protocol versions as evidence metadata. Accept any client that negotiates the supported protocol and required capabilities; do not gate access on an exact application version.
- Keep the named targets open and non-exclusive: Codex Desktop and CLI, Claude Desktop and Code, OpenClaw, OpenCode, Hermes, KiloCode, Cline, and Goose.
- Allow beta to launch with the actually verified subset of named targets; label unverified targets clearly and exclude them from the supported-client claim until native smoke evidence exists.
- Preserve durable grants, refresh, revocation, free preflight, health reporting, and the owner-bound launch-intent flow.
- **BREAKING:** Remove the platform installer, downloaded SDK, and local bridge from the normal connection path. A direct client link is a convenience only; clients without one use the remote MCP URL flow.

Non-goals: hosted model execution, provider-key custody, client-version spoofing, hidden permission increases, running model actions without the participant’s client, benchmark score changes, PvP fairness or settlement changes, and a universal two-click claim for first-time account setup or clients without a native add link.

## Capabilities

### New Capabilities

- **agent-client-installer**: Remote MCP connection, durable authorization, capability negotiation, connection health, and launch handoff. The change identifier is retained; a local installer is no longer part of the capability.

### Modified Capabilities

None. AAP remains authoritative for owner identity, consent, permissions, credentials, and revocation. BRL remains authoritative for launch-intent admission, queue, quote, and billing behavior. Reconcile their active deltas before implementation.

## Impact

Changes are limited to the ACI planning artifacts and their BDD proposal. Future implementation will affect the owner MCP/auth profile, connection onboarding UI, per-client link/fallback instructions, and launch handoff. The implementation tasks and changed BDD assertions require a fresh approval before apply. No executable code, BDD registry, runtime profile, or test is changed by this planning revision.
