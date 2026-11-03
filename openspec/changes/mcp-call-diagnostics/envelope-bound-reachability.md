# Reachability of the 2 KiB envelope boundary

Measured on 2026-11-02 using the current strict `diagnosticEnvelopeSchema` and
`canonicalDiagnosticJson` in the installed owner-identity Docker runtime. This
is a schema measurement with synthetic values, not a physical acceptance run.

With the expanded error-code registry and paired client crash observation, the
independent pinned-source reader derives a maximum of **1168 canonical UTF-8
bytes** across all 26 allowed properties: fixed UUID/hash/timestamp lengths, longest allowed enum values,
eight copies of the longest allowed field path and the longest allowed numeric
representations. The paired fields require source `client`, stage `client_runtime`,
and outcome `error`; the maximum compares this conditional branch with the
branch omitting both fields. A naive independently maximal value for each field
is invalid and overstates the reachable bound. Every string value is ASCII. The source schema admits no
arbitrary message or padding property. The configured ceiling remains 2048.

Consequently, an accepted **2048 canonical-byte** envelope cannot be constructed
under the current stricter field bounds. Whitespace in a transport JSON string
does not increase the reconstructed canonical envelope size. Adding a padding
field solely to make this boundary reachable would weaken the privacy contract.

The initial registry measurement was 1071 bytes; successive finite-registry
expansions produced 1076 and then 1081 bytes; the paired observation raises the
conditional maximum to 1168. Its actual HTTP witness remains a required physical
gate. Recompute this value from pinned current schema
instead of freezing either historical measurement as a product limit.

The owner approved the following interpretation on 2026-11-02:
«Да, согласую такую проверку без ослабления лимитов».
The physical probe distinguishes this schema-dominated bound from any reachable
transport or quota bound:
retain the configured 2048 ceiling, verify the maximum representable valid
envelope, and reject exact 2048/2049-byte envelopes containing unsupported or
overlong fields. Do not claim that either oversized envelope was accepted. The
physical reader independently reconstructs finite property bounds from the
pinned schema source, compares the actual exported JSON Schema, derives the
maximum and verifies its actual accepted witness plus strict 2048/2049 rejection.
For other dominated ceilings, it reconstructs allocation totals from independent
SQL/SQLite aggregate rows and checks the actual earlier blocker against pinned
allocation/physical-reserve rules. It rejects application usage counters and
artificially seeded quota totals. Every configured ceiling is unchanged. All six
physical gates remain blocked until actual captures pass; the measurement and
reader unit tests are not acceptance evidence.
