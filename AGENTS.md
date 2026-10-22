# Web3 Agent Bench

This repository is a benchmark and real-time PvP harness for web3-capable coding and browser
agents. It is intentionally evidence-first: a green local test proves the reference adapter and
the declared contract, not live-chain execution, economic safety, or production readiness.

<!-- AICODE-NOTE: docs/task-design.md owns the approval, BDD, sync, and archive contract. Keep this
entrypoint short so the copied harness has one authoritative workflow document. -->

At the beginning of a task, run `tree docs /F /A` and inspect only the documents relevant to the
request. Read [`docs/how-to-document.md`](docs/how-to-document.md) when changing documentation and
[`docs/task-design.md`](docs/task-design.md) when changing observable behavior, benchmark semantics,
or agent protocols. Read [`docs/benchmark-protocol.md`](docs/benchmark-protocol.md) before changing
event, score, evidence, or PvP settlement semantics.

Use the OpenSpec lifecycle for behavior changes:

`/opsx:explore` (optional) -> `/opsx:propose` -> approval -> `/opsx:apply` -> BDD gates ->
`/opsx:sync` -> `/opsx:archive`.

Do not add vanity scenarios. Each scenario must protect a stated benchmark or PvP requirement and
must name its boundary, negative/adversarial variants, durable effects, and evidence.

## Evidence and safety rules

- Never put private keys, seed phrases, provider tokens, wallet material, or unredacted user data in
  fixtures, logs, evidence, or prompts.
- Keep task outcome, latency, cost, tool/safety behavior, chain effects, and evidence quality as
  separate measurements; do not hide them behind one unexplained score.
- A missing, delayed, contradictory, or unverifiable chain observation is `unknown`, not success.
- A local reference model or testnet run does not prove mainnet behavior, finality, profitability, or
  resistance to adversarial agents.
- Real-time PvP results require an authoritative event sequence, pinned rules/seed, deadline policy,
  reconnect behavior, and idempotent settlement evidence.
- Preserve raw evidence paths and hashes. Do not infer ownership or causality from log proximity.

## Anchor comments

Use `AICODE-NOTE:`, `AICODE-TODO:`, or `AICODE-QUESTION:` comments for durable project knowledge
inside code. Before scanning files, grep for existing `AICODE-*` anchors. Move an anchor to docs when
the repository becomes large enough that inline notes obscure the implementation.

