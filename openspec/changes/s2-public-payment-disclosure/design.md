## Context

BEF tools.ts serializes six payment terms. protocol.ts already declares authorization flow and EIP-712 domain name/version for the same merchant. The S2 public actor correctly omits unavailable identity values; the evaluator correctly awards 7/10.

## Goals / Non-Goals

Publish the real provider identity through free inspection and permit public-only S2 completion. Preserve required fields, exact fractions, six-term economic admission and historical evidence. No hardcoded expected-answer injection, credential exposure, rule weakening or historical rewrite.

## Decisions

Use one provider helper for authorization flow and the manifest EIP-712 domain name/version. Protocol challenge extras and all public offer/catalog payment objects consume the same helper. This is public protocol metadata, not a grading answer. The existing public actor derives its structured answer from those actual fields.

Strict split-offer observation accepts either the complete legacy six-term shape or the complete nine-field public shape. New identity fields must exactly match the pinned provider policy; partial, unknown, substituted or mixed-root metadata fails closed. The projected six economic terms remain unchanged. The owner payment-reference parser accepts a strict legacy-six or complete-nine public shape, verifies the original retained response hash and projects exactly six economic terms. It checks published root/offer metadata consistency where available; authoritative provider-policy validation remains at BEF/probe/challenge boundaries rather than reading hidden rubric answers.

## Risks / Trade-offs

- Provider/probe source identity changes: qualify a new release and retain old artifacts and pointers until qualification succeeds.
- Metadata drift: share policy construction and validate exact manifest values.
- Synthetic tests mistaken for runtime: the environment gate requires actual public MCP response, submitted answer, unchanged evaluator score, source/PG effects and exact fences/finance.

## Migration Plan

Finish the existing PDC evidence checkpoint before source edits. Freeze and requalify the changed application and probe; do not replace historical hashes or patch a current-release pointer in place. Activate only a newly qualified isolated release for actual Ranked qualification. Restore the ordinary local stand through the root integration flow.

## Open Questions

No product-policy decision is pending. Fresh qualification and actual E2E remain blocked until independently verified.
