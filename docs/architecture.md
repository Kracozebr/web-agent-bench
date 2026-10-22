# Architecture

The initial shape separates normative contracts from executable adapters:

```text
OpenSpec main specs
        │
        ▼
generated Gherkin + named mappers ──► semantic harness audit
        │                                      │
        ▼                                      ▼
reference adapter                     acceptance evidence
        │                                      │
        └──────────────► scenario map ◄────────┘
```

The intended runtime shape is:

```text
agent runner / sandbox
        │ normalized events + raw evidence references
        ▼
benchmark coordinator ──► scorecard and replay bundle
        │
        ├── chain observation adapter (fork/testnet/mainnet, named explicitly)
        └── real-time match authority
                 │ pinned rules + seed + monotonic event log
                 ▼
             result / settlement adapter
```

## Boundary classes

- `reference_model`: deterministic local behavior used to prove the protocol shape.
- `sandbox`: a real agent process with resource, network, filesystem, and key boundaries.
- `chain_observation`: RPC/indexer/receipt evidence with a named network and block/finality policy.
- `match_authority`: the component that owns time, ordering, disconnect handling, and terminal state.
- `settlement`: an idempotent accounting or on-chain action, reconciled against receipts.

A local reference model cannot stand in for a sandbox, chain, match server, or settlement gate. The
BDD gate class must say which boundary was actually exercised.

