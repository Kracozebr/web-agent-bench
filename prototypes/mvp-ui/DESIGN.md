# Design notes

The interface keeps the Stitch prototype’s light surface, indigo accent, card, and table basis while reorganizing it into a compact owner workspace. A narrow, persistent top bar carries the product name and simulated environment; navigation and local review scenarios live in a collapsible sidebar. At mobile widths the sidebar becomes a labeled, keyboard-operable drawer.

## Visual system

- CSS custom properties in `styles.css` define editable surface, text, border, accent, status, spacing, radius, and shadow tokens.
- System sans-serif and monospace stacks work without downloaded fonts.
- Cards organize related data; tables remain for run history and ranked comparisons. Score, level, time, fee, and safety observations stay separately labeled.
- The benchmark inventory and quote panel show task openness, weights, the training subset formula, and the full ranked price before handoff.
- Owner screens contain connection, test-fund, permission, and cap details. Public pages show profile metadata and a single selected same-run result; owner/auth/financial fields and closed-task error details stay private.
- Forum, payment, withdrawal, and other later-scope actions are displayed as inactive/clearly deferred views rather than fabricated working features.

## Interaction and accessibility

- The application uses native buttons, inputs, labels, dialog-free guided steps, visible focus rings, a skip link, status announcements, and responsive layout changes. Form controls preserve wizard values on Back.
- Four business permissions start off independently of the connection preflight. A saved profile remains private unless a complete eligible ranked run automatically publishes it or a later-scope public forum action exists; the latter is not implemented here.
- The one-time token fallback displays only a synthetic, powerless string, only once per setup, and never stores it in local state. Browser grant success/refusal/expiry and preflight outcomes are explicitly simulated.
- A waiting handoff is free and does not count as a run. A matching acceptance admits one queued run; the sequence models hold, start debit, task progress, terminal outcomes, and source-aware release/refund behavior.
- All interface state persists locally for review. Prototype scenarios replace it with known fixtures, and **Reset demo** returns the baseline.

## Mock data

Task names, open/closed status, level weights, full prices, baseline per-task credit fractions, and comparison agents are defined in `mock-data.js`. Quote and score arithmetic are pure functions in `domain.js`, shared by the browser and Node smoke check. The baseline public profile and leaderboard use one selected synthetic run with score 61.73%, weight denominator 26, and its own elapsed time and declared agent version. Alder is a comparison fixture; Brook is public without a ranked result. These fixtures do not prove benchmark execution or scoring-service behavior.

The labels “MVP v1”, “Controlled Base fork”, and “controlled x402” name the intended scenario only. No external images, fonts, scripts, APIs, wallet libraries, or runtime service dependencies are loaded.
