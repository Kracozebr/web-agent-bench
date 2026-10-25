# Implementation approval

Date: 2026-10-25 (Europe/Moscow).

The owner explicitly approved implementation by replying “Да, давай” to the
request to approve `owner-identity-and-pilot-admission`, its existing twelve
scenarios and the defaults in [stage2-entry-review](../../../docs/stage2-entry-review.md).

Approved scope: unchanged OID-REQ-001–008 and OID-SC-001–012, their existing
negative variants, observations, durable effects, named mappers/adapters and
identity/admission product boundaries. Approved defaults: single-use invitations
stored as verifiers; explicit identity linking without email auto-merge; reject
foreign identity conflicts; explicitly configured administrator; browser logout
separate from agent-wide revocation; initial EOA SIWE verification profile.

Pin compatible dependencies, origins, chain, TTLs and throttles before executing
their boundaries. External Google/browser-wallet evidence remains separately
mandatory. Missing downstream domain implementations remain blocked and cannot
be replaced by fixtures. This approval does not approve the whole AAP, lifecycle,
payments or task-suite changes, production activation or real-funds operations.

Approval permits implementation and acceptance; it is not acceptance evidence.
New scenarios or changed assertions require renewed scope review.
