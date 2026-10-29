# Local Codex owner-identity qualification

This note records how to run the native Codex CLI against the local owner-identity MCP server. It is an operator procedure, not a benchmark acceptance contract. The commands and artifacts below reproduce a local authenticated-client attempt; they do not establish benchmark success.

## Prerequisites and scope

- Run from a Windows x64 checkout with the local web application and owner-identity MCP endpoint ready at `http://127.0.0.1:3000/api/agent/mcp`.
- Use the complete official `@openai/codex` 0.165.0 Windows x64 package. The runner requires and verifies `codex.exe`, `codex-code-mode-host.exe`, `codex-package.json`, `codex-resources/`, and `codex-path/`; extracting only the CLI executable is unsupported.
- The pinned upstream source is [Codex v0.165.0 config schema](https://raw.githubusercontent.com/openai/codex/rust-v0.165.0/codex-rs/core/config.schema.json). The runner pins SHA-256 for the executable, code-mode host, and package manifest and checks them before it reads credentials or starts a model run.
- The native client uses the operator's existing Codex OAuth login and default model. Model usage counts against that Codex account; internal USDC bonuses apply only to the platform. The separate local bearer authorizes calls to this MCP server.
- The runner uses a read-only CLI sandbox, ephemeral session, isolated temporary `CODEX_HOME`, and no shell, browser, plugin, or subagent tools. Its private auth alias is a hard link to the existing `auth.json`, not a copy; the runner checks that the alias and source remain the same file and removes only its private alias after the child exits. It does not mutate the user's Codex configuration.

## Private inputs and local paths

Keep the MCP bearer in `.local/owner-identity/google-local/codex-manual-credential.txt`. Keep nonsensitive task instructions in a separate prompt file, such as `.local/owner-identity/google-local/codex-preflight-prompt.txt`. Never put the bearer in a prompt, command argument, Codex config, screenshot, report, or committed file; do not print or inspect its contents during routine operation.

The runner writes only a bounded sanitized JSON summary and a `.progress.json` sidecar beside it. These retain fixed event/tool counts, selected usage counters, status enums, and allowlisted error codes; they do not retain model messages, tool arguments/results, bearer values, or raw CLI transcripts. Choose new output names for each attempt; existing output paths are rejected.

## Native CLI procedure

Set the repository root and paths in PowerShell. The runner defaults to the pinned executable path below. An operator can pass `-CodexExecutablePath` when the verified full bundle is kept elsewhere.

```powershell
$repo = 'C:\onchain\Proj\web-agent-bench'
Set-Location $repo
$runner = Join-Path $repo 'infrastructure\owner-identity\run-codex-google-local.ps1'
$credential = Join-Path $repo '.local\owner-identity\google-local\codex-manual-credential.txt'
$prompt = Join-Path $repo '.local\owner-identity\google-local\codex-preflight-prompt.txt'
$output = Join-Path $repo '.local\owner-identity\google-local\codex-preflight.json'

# Preflight: expose only the identity check.
& $runner `
  -PrivateCredentialFile $credential `
  -NonsensitivePromptFile $prompt `
  -SanitizedOutputPath $output `
  -EnabledMcpTools @('identity.preflight')
```

Only after preflight and explicit task authorization, a task run can enable the identity check plus the five currently exposed `runs.*` tools. This is a broader capability set than preflight; do not enable it for diagnosis-only prompts.

```powershell
$output = Join-Path $repo '.local\owner-identity\google-local\codex-task-01.json'
& $runner `
  -PrivateCredentialFile $credential `
  -NonsensitivePromptFile (Join-Path $repo '.local\owner-identity\google-local\codex-task-prompt.txt') `
  -SanitizedOutputPath $output `
  -EnabledMcpTools @(
    'identity.preflight',
    'runs.task_action',
    'runs.task_action_status',
    'runs.finish_task',
    'runs.current_task',
    'runs.accept_launch_intent'
  )
```

The helper scopes MCP approval to the explicitly enabled tool names and leaves the CLI sandbox read-only. Screenshot and support-report tools are separate capabilities (`support.screenshot.begin`, `support.screenshot.chunk`, `support.screenshot.finish`, `support.report`, `support.report_receipt`); add them only for an explicitly authorized reporting operation. The browser screenshot/report workflow is separate from model execution and must not be described as proof that the model completed a task.

## Reading the evidence

Inspect the sanitized JSON and its progress sidecar, not a raw transcript. A successful preflight is evidence that this native Codex client authenticated to the local service and completed the preflight tool call. For the verified preflight 09, the private local artifact is `.local/owner-identity/google-local/codex-preflight-09.json`; its observed summary was `status=turn_completed`, one MCP call to `identity.preflight`, one completed call, one allowed preflight result, zero denied results, zero client/MCP errors, and CLI exit code 0. The independent local database observation recorded four MCP requests including initialization traffic. These are local client/service observations only.

`taskOutcome` intentionally remains `unknown`. Recoverable MCP operation errors are counted separately (`turn_completed_with_tool_errors`); they do not turn a completed model turn into a client-runtime failure. Preflight readiness requires an actual allowed result, not just exit code 0. Client runtime errors and unsafe auth cleanup still make the helper fail.

A completed model turn, a tool call, a screenshot, or a support report alone does not prove task correctness, benchmark acceptance, durable task completion, safe economic behavior, or chain effects. Do not call this beta-target validation, mainnet validation, a solver result, or a passed benchmark. Preserve any separate task receipt, screenshot, and backend/database evidence under their own evidence procedures and report each boundary independently.
