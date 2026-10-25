# Private cards, delegated connections and owner policy

Status: approved incremental implementation, not full AAP acceptance.
The [approval](approval.md) covers the existing sixteen scenarios. Their full
requirements and mandatory dependencies remain unchanged.

## Implemented boundary

The existing owner application now exposes `/agents`: admitted owners create,
list and edit private cards and select four independent permission settings.
Optional client/model/version metadata is explicitly owner-declared and
unverified. New cards default all permissions to false. Profile and policy
revisions are separate; unsupported owner/publication fields reject.

The Fastify API uses the existing Better Auth session and immutable OID owner ID.
PostgreSQL tables `oid_agent`, `oid_agent_policy` and `oid_agent_operation` store
cards, policy and idempotent receipts. Mutations commit their audit in the same
transaction. Foreign IDs return 404; unadmitted owners and unauthenticated or
forged bearer authority cannot create cards. No public profile endpoint or
publication marker authority was added.

Profile and policy writes serialize on the same immutable agent key. The real
two-tab test exposed a PostgreSQL deadlock between operation-row FK key-share
locks and `FOR UPDATE`; `FOR NO KEY UPDATE` preserves serialization and permits
the FK lock. Both requests at policy revision 2 now produce one 200 and one 409,
one new revision and one committed audit, rather than a 500.

## Initial card-slice evidence

Docker production build/typecheck and additive migration passed. The integrated
browser capture `54747112-38ab-49cd-90df-bfc85eadbae7` used actual controls for
create, profile update and permission saves. Independent `oid_observer`
SELECT-only snapshots correlated operation IDs to committed card/policy/audit
rows; reload retained settings. Direct HTTP negatives separately checked foreign
read/edit, pending creation, forged publication/credential, stale revision,
idempotent retry and changed-payload conflict. A forged credential is not an
actual issued agent credential and does not prove that future authority boundary.

Source inputs were unchanged during the final capture. AAP immutable raw runs
use `artifacts/runs/acceptance/AAP-SC-*/runs/<uuid>/` with three hashed artifacts
each. Read-only filesystem replay verified all 48 artifacts and seven partial
card facts for SC001/006/014. No credential or domain action is repeated by replay.
The existing OID replay also verified its 60 artifacts.

Semantic AAP audit protects all sixteen approved scenarios. The
[AAP report](../../../tests/bdd/changes/agent-access-and-permissions/acceptance-evidence.json)
initially recorded sixteen blocked mandatory gates; pytest skips are mapped to blocked,
and the acceptance command deliberately exits nonzero. Partial card facts do not
pass whole scenarios. The OID report remains three passed / nine blocked.

## Remaining work after the initial card slice

At this initial checkpoint no OAuth/MCP server, browser consent, run/forum operation, ledger/cap or delivered
cancellation effect was claimed. Historical run snapshots and BLP public-marker integration did not
exist yet. Actual-client editions and OAuth/MCP protocol/TTL configuration were unpinned.
These were separate mandatory blockers for the unfinished AAP scenarios.
The next slice was browser OAuth/MCP connection authority followed by actual
domain integration; no stub receipt can replace it.
Sync/archive is not allowed in this state.

## Manual credential follow-up

The next approved slice adds one-time manual issuance, safe status, explicit
replacement and owner-wide access revoke to `/agents`. The actual API verifies
the opaque header credential against its stored verifier, fixed owner/agent/
resource/role, expiry, current access generation and current permission policy.
Owner cookies alone do not authorize agent preflight. The
[configuration profile](configuration.md) pins 256-bit entropy, default 24-hour
expiry, supported bounds, exact resource and throttles before acceptance.

Only verifier material persists in `oid_agent_manual_credential`; grant identities,
operation receipts and audits omit plaintext. Retrying an issuance operation
returns its historical safe receipt with no secret. If the response is lost,
the UI reads safe status and requires an explicit replacement; it does not
silently repeat issuance. Global revoke fences current credentials and writes
one cancellation outbox entry constrained to `pending`. No coordinator delivery
or run cancellation is claimed. New authorization after revoke is not yet exposed.

The Docker browser journey exercised actual issue/replace/revoke controls,
cookie-free header preflight, foreign and agent-self issuance denial, wrong
agent/resource, forged withdrawal scope on a real owner-policy endpoint, safe
operation replay, and independent SQL verifier/grant/audit observations. The
lost-response probe forwards the actual mutation, aborts its committed response,
then observes safe recovery and explicit replacement. A labelled DB fixture
expires only a fresh dedicated grant; a separate SELECT-only role observes the
denial. The same credential observes a changed policy without replacement.
After API restart, revoked credentials remain denied and another agent remains
usable. These local lifecycle facts do not establish actual cancelled-run or
deadline preservation.

AAP-SC-004 now passes all four observations and four negative variants derived
from raw evidence. The other fifteen mandatory AAP gates remain blocked. The
final capture is `526e1103-7151-432b-8c39-fdcbb86259e3`; its SC004 immutable run
is `408d3543-4717-4f37-9ac9-1d567315f943`. Both before/after source inventories
match. The report was recorded against the precommit worktree, explicitly dirty.
The shared evidence-reader now distinguishes the safe `access` state object from
an access token; raw `aap1_` values are rejected under any field name. Scanner
regression and shared tool/traceability tests pass (43 tests). Replay verifies
48 AAP artifacts and 60 OID artifacts without product actions. OID remains
three passed / nine blocked. Task 3.3 is complete; broader connection, revocation
and lifecycle tasks remain open until their full boundaries exist.

## Browser OAuth and MCP follow-up

The [pinned local profile](oauth-profile.md) now runs Better Auth 1.7.12 with the
official MCP SDK 2.4.0. An admitted owner selects an existing agent and reviews
the client, resource, fixed delegation and current four-permission policy in the
actual UI. The signed request stays in component memory and no-referrer POST
bodies after URL scrubbing. A canonical request hash and the authenticated
user/session bind one immutable selection. Grant creation and the approval audit
commit together; denial creates no grant. Direct public provider continuation
and consent endpoints remain closed.

Better Auth owns code consumption, PKCE and signed token issuance. The shared
HTTP/MCP verifier checks the exact issuer and agent-resource audience, then loads
the current owner admission, grant, access generation, revocation and policy.
The official stateless handler rejects legacy traffic and serves
`identity.preflight` under protocol `2026-07-28`. Its bridge forwards both
`mcp-method` and `mcp-name` as well as the version header; omitting these produced
a real SDK 400 during integration. This slice releases only free preflight.

Final Docker capture: `57bf70ef-7b29-48d3-b538-65bf8aa30c05`. Independent
filesystem replay and BDD derivation verify AAP-SC-002, 003 and 004 as passed.
Their immutable raw run IDs are respectively
`9c174b17-9881-427a-bb78-302d3e45564d`,
`6cb75e8c-fad8-4790-b535-5ee5a4e3cc43` and
`84108708-3085-4678-b44e-fc2a56de2978`.
Recorded negatives include denied consent, foreign selection, changed-agent
consent input, expanded scope, substituted redirect/resource/PKCE/issuer,
consumed-code replay and a labelled private code-expiry fixture. SQL observations
prove grant linkage, absent consumed verification, safe exchange audit and no
grant for denied consent. JWT access tokens need no opaque-provider access row;
the verified claims and durable application grant establish the binding.

The real SDK negotiated the modern protocol, listed `identity.preflight` and
called it successfully with OAuth and a manual credential for the same agent.
Both credentials were denied after the owner clicked revoke and remained denied
after API restart. Independent SELECT-only snapshots observed the revoked grants
and access fence. The cancellation outbox still represents pending intent only.

Each acceptance run now creates and retains its own
`oid_acceptance_<run UUID>` database. Random per-run auth secrets cannot decrypt
another run's persisted JWKS; this caused a callback 500 during integration.
Fresh databases isolate those keys and preserve the development database.
The earlier fixture-created development key was repaired by adding a key under
the stable secret while preserving its previous row. Provenance identifies the
fixture database and explicitly records its 120-request auth/SIWE/credential
quotas; this is no production rate-limit acceptance claim.

Backend typecheck, frontend production build, 44 tool/traceability tests and the
16-scenario semantic audit pass. Replay verifies 48 AAP and 60 OID artifacts
without network or product mutations. Source inputs match before/after capture;
the capture records a dirty precommit worktree. Secret scanning rejects raw JWTs
and manual credential values in addition to credential-bearing fields.

The [AAP report](../../../tests/bdd/changes/agent-access-and-permissions/acceptance-evidence.json)
now records three passed and thirteen blocked mandatory gates; OID remains three
passed and nine blocked. BDD skips are recorded as blocked and commands exit
nonzero. SC015 remains blocked without an actual permitted domain operation;
SC016 has no actual pilot-client edition evidence. Current task completion is
8/25, including persistence, both connection routes and the labelled local flow.
Next work is actual forum/run admission, shared billing and delivered lifecycle
cancellation, followed by actual pilot-client compatibility. Sync/archive remain
blocked by the unfinished mandatory gates.

## Reproduction

Use only the Docker runtime described in
[the infrastructure README](../../../infrastructure/owner-identity/README.md).
Stop the dev container before the production acceptance build: both currently
share the source-mounted Next.js `.next` directory. Restart it after capture.

```powershell
docker stop web-agent-bench-oid-dev
./infrastructure/owner-identity/tool.ps1 pnpm --filter @web-agent-bench/owner-web build
./infrastructure/owner-identity/tool.ps1 pnpm --filter @web-agent-bench/owner-acceptance acceptance
./infrastructure/owner-identity/tool.ps1 python tools/run_bdd_acceptance.py --change agent-access-and-permissions
./infrastructure/owner-identity/tool.ps1 python tools/replay_aap_acceptance.py all
docker start web-agent-bench-oid-dev
```

Captures use the declared local Google transport and synthetic EOA fixture, not
actual Google/browser-extension or third-party MCP client compatibility. Runtime
secrets and raw auth material remain outside evidence and tracked files.
