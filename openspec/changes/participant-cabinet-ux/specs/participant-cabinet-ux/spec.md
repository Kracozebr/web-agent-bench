# Participant cabinet and actionable diagnostics

Status: approved for implementation on 2026-10-31. Runtime for all 8 scenarios: `not_run`. [Design](../../design.md), [BDD packet](../../bdd-design.md), [approval](../../approval.md).

## ADDED Requirements

### Requirement: PCU-REQ-001 Expose honest priced launch actions
The cabinet SHALL show benchmark version, mode, selected tasks and authoritative quote using Training and Ranked start labels. Full Training S1/M1/H1 SHALL remain 0.50 bonus USDC and Ranked12 1.00 at current defaults; partial Training SHALL use exact existing integer pricing. It SHALL show bonus payment source and zero cash use in this bonus-only beta.

Scenario setup: Authenticated funded participant and active current catalog

#### Scenario: PCU-SC-001 Expose honest priced launch actions
- **WHEN** the owner chooses a full or partial Training set or Ranked and starts, retries or encounters a changed quote/release
- **THEN** the browser action SHALL reach real admission once with the displayed pinned quote or reject with re-confirmation; private launch intent SHALL not be presented as an alternative public/private run mode

### Requirement: PCU-REQ-002 Format money without losing exact accounting
Money summaries SHALL use two decimal places and an explicit less-than-0.01 marker for nonzero smaller values, with exact micro-USDC in accessible details. Display rounding SHALL NOT change quotes, input validation, caps, reservations or ledger arithmetic. Distinct same-looking fractional charges SHALL retain unique entries.

Scenario setup: Owner bonus balance and ledger with sub-cent and rounding-edge values

#### Scenario: PCU-SC-002 Format money without losing exact accounting
- **WHEN** the owner views balance, prices, bonus grants and financial history and submits a bounded allocation
- **THEN** summary/details SHALL agree with exact persisted units and financial calculations SHALL remain unchanged, including zero and small nonzero distinction

### Requirement: PCU-REQ-003 Keep complete histories compact and private
Bonus grants, financial history, pending launch requests and admitted runs SHALL initially show the newest five entries with bounded scroll/loading of all authorized older records. Run/request cards SHALL show agent, mode, tasks, version and status, with technical IDs/hashes and detailed cancellation terms expandable. Stable cursor ordering SHALL handle equal timestamps.

Scenario setup: Two owners with more than five records, equal timestamps and newly arriving entries

#### Scenario: PCU-SC-003 Keep complete histories compact and private
- **WHEN** one owner scrolls and expands each history while another-owner cursor or stale cursor is supplied
- **THEN** all and only own records SHALL remain reachable without duplicates or omissions; expanded technical details SHALL not expose credentials or sealed data

### Requirement: PCU-REQ-004 Explain readiness and support through accessible help
Known readiness and connection errors SHALL map to short user-facing reason/action text; unknown codes SHALL show a neutral failure and safe support correlation ID. Technical detail SHALL be optional and sanitized. Help for prices, Training, financial limits and hashes SHALL work by click, keyboard focus and touch, not hover alone.

Scenario setup: Backend states for queue, preparation, execution, observation, offline client and unavailable executor

#### Scenario: PCU-SC-004 Explain readiness and support through accessible help
- **WHEN** the user opens launch/help on keyboard and pointer and encounters known and unknown errors
- **THEN** the UI SHALL identify the failing stage and safe next action without exposing secrets, claiming connection from a flicker or implying an accepted action executed

### Requirement: PCU-REQ-005 Show detailed owner Training feedback safely
Completed Training tasks SHALL provide the owner with evidence-backed goal/constraint checks, accepted/rejected action timeline, timing and specific safe reasons. Platform failure and unknown attribution SHALL remain separate from agent failure. Ranked SHALL retain existing terminal-only allowlisted feedback and SHALL not expose reference answers, hidden cases or live hints. The new action detail is limited to the authenticated owner's completed Training-task diagnostics, not a general chronological run journal or Ranked/public trace viewer. This explicitly proposes a narrow amendment to BLP-REQ-007 and BLP-SC-011/014; the rest of their access and secrecy rules remain.

Scenario setup: Owner Training completed task, active or terminal Ranked and another-owner run

#### Scenario: PCU-SC-005 Show detailed owner Training feedback safely
- **WHEN** the user opens results from the actual run card and drills into a failed task or action
- **THEN** Training SHALL explain what is proven missing or wrong with evidence references, unknown gaps SHALL be explicit, and Ranked/foreign requests SHALL not disclose privileged feedback

### Requirement: PCU-REQ-006 Create contextual reports with optional private screenshots
Report creation from a run/task/action SHALL autofill only server-validated owned context and observed client metadata; connection reports SHALL work with no run ID. Technical IDs SHALL remain optional for a generic report. Optional image uploads SHALL reuse existing validation, ownership, retention and unified backup contracts. Report contents, private context and image bytes/links SHALL expire 30 UTC days after audited beta_ended_at under BPC-REQ-015, never on a rolling per-report/upload clock; restore or retry SHALL not extend that deadline.

Scenario setup: Owner with an actual run and an unlinked connection problem

#### Scenario: PCU-SC-006 Create contextual reports with optional private screenshots
- **WHEN** the owner opens report from context or Reports, attaches a screenshot, submits, retries a lost response and views the same report as admin
- **THEN** one private report and authorized normalized image linkage SHALL persist with verified context; foreign links, forged metadata, unsafe images and quota abuse SHALL be rejected without billing/task effects

### Requirement: PCU-REQ-007 Hide and reject non-admin administration pages
Administration navigation SHALL be rendered only for a server-verified administrator. Unauthenticated, ordinary-owner and agent callers SHALL receive a real HTTP 404 for administration page routes and subroutes without an admin shell or private hydration data. API role/origin/CSRF checks SHALL remain authoritative; their existing 401/403 semantics SHALL not be weakened by page concealment.

Scenario setup: Verified administrator, ordinary owner, unauthenticated browser and agent-only credential

#### Scenario: PCU-SC-007 Hide and reject non-admin administration pages
- **WHEN** each requests admin routes by direct URL, client navigation, prefetch and spoofed role/session and attempts admin API calls
- **THEN** only verified admin SHALL see the navigation and page; others SHALL receive uncached private-safe 404 pages and no administrative durable effect

### Requirement: PCU-REQ-008 Present connection management without manual credential clutter
The primary Agents screen SHALL show selected client, verified connection state/time, permissions and revoke/reconnect controls. Installer/setup and automatic renewal SHALL replace the normal manual-key flow. Manual replacement SHALL remain an explicitly advanced destructive-to-old-credential action with safe one-time local delivery and no token echo into chat or logs.

Scenario setup: Agent with installed client and optional legacy manual credential

#### Scenario: PCU-SC-008 Present connection management without manual credential clutter
- **WHEN** the owner checks actual connection, reconnects or explicitly replaces an advanced credential and cancels midway
- **THEN** meaningful state SHALL appear, automatic refresh SHALL follow ACI, and replacing credentials SHALL not silently revoke a different client or loosen permissions

