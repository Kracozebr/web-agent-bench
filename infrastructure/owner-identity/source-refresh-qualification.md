# Fresh source qualification

This is an operator workflow for the approved S2 public payment-identity correction. It runs
the existing strict source-refresh comparators and generates a new candidate. It does not
change task goals, prices, deadlines, scores, historical artifacts, or the current release pointers.

Keep the original Google server and all physical jobs stopped until qualification and the
subsequent owner acceptance captures finish. Confirm that existing generations are fenced before
recreating the API. Freeze the BEF source, including its tests, before computing the three hashes.

Run the host plan from the repository root:

```powershell
pwsh -NoProfile -File infrastructure/owner-identity/qualify-source-refresh.ps1
```

The printed `preflight` command invokes the existing Docker tool runtime with `--plan`. It only
reads sources and prints the exact application, probe, and manifest hashes. The PowerShell plan
itself runs no Docker command. After the root coordinator gives GO, run:

```powershell
pwsh -NoProfile -File infrastructure/owner-identity/qualify-source-refresh.ps1 -Execute `
  -ApplicationSha256 <frozen-app-sha256> -ProbeSha256 <frozen-probe-sha256> `
  -ManifestSha256 <frozen-manifest-sha256> -ObserverPort 55432
```

The wrapper builds the API image and recreates only API/gateway. It preserves PostgreSQL,
Anvil, source-proxy quota counters, and credentials. Reference scripts require the qualification
gateway ports: API 38783, RPC 18545/28545, facilitators 34021/44021. The observer port is explicit.
Pass the same ports to subsequent owner acceptance jobs. No provider URL or secret is a CLI value.

The serial qualification records a fresh read-only feasibility witness, verifies it independently,
captures and fences all 15 current cases (12 Ranked and S1/M1/H1 Training), verifies original raw
artifacts, rebuilds cases under the immutable semantic baseline, reviews minimum actions, verifies
reference semantics, assembles a candidate release, and validates its separately hash-pinned inputs.
The unchanged environment manifest gets a fresh retained raw snapshot; changing its semantic hash
causes this source-only workflow to stop. Reference capture success alone is insufficient.

Each stage records its command, exit status, sanitized logs, and pinned outputs under
`artifacts/runs/bts-source-refresh-qualification/<capture-id>/`. Any failed stage stops the pipeline.
Do not retry an incomplete physical reference until its generation/cleanup state is understood.
The source-proxy's existing cap remains in force; unavailable metrics or an exhausted cap block
qualification. Script and source hashes and both current pointer files are checked throughout.

Success is `validated_candidate_not_activated`. The final report names `candidate-inputs.json`
and `proposed-current-task-release.json`; neither is copied over a current file. Review the
validated artifact and activate through the existing release workflow only after qualification
and explicit root coordination. New PDC Ranked S2=1/1 and agent-report E2E captures are separate
required evidence. This workflow proves local reference conformance, not production readiness.
