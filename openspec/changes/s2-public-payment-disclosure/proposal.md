## Why

Actual Ranked S2 returns 7/10 because the public merchant offer omits three identity fields required by the unchanged rubric. The agent cannot recover these fields through the disclosed free inspection even though the provider already uses them for payment authentication.

## What Changes

- Publish provider-authenticated payment identity metadata in free offer and catalog responses.
- Keep protocol challenge metadata and public metadata sourced from the same manifest policy.
- Validate new public metadata while preserving exact legacy six-term capture replay.
- Qualify a fresh release and actual Ranked S2 without hidden-answer injection or score changes.

## Capabilities

### New Capabilities

- `s2-public-payment-disclosure`: complete public payment identity and source-bound qualification.

### Modified Capabilities

None; existing task goals, required fields and scoring remain unchanged.

## Impact

BEF tools/protocol, strict split-offer probe validation, provider/probe source identity and fresh release qualification. No economic policy, refund, deadline or PvP settlement change. Local execution evidence does not establish mainnet or beta readiness.
