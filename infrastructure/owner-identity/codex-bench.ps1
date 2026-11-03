[CmdletBinding()]
param(
    [ValidateSet('Login', 'Start', 'Check', 'Run', 'DiagnosticsLogin', 'DiagnosticsStatus', 'DiagnosticsRetry', 'DiagnosticsExport')]
    [string]$Action = 'Start',
    [string]$HandoffFile,
    [string]$Origin = 'http://127.0.0.1:3000',
    [string]$LocalCaseId
)
$ErrorActionPreference = 'Stop'
$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
# AICODE-NOTE: Only exec --json exposes the supported safe client diagnostic stream.
# The helper uses its own OAuth grant and OS credential entry, never Codex's cache.
if ($Action -in @('Run', 'DiagnosticsLogin', 'DiagnosticsStatus', 'DiagnosticsRetry', 'DiagnosticsExport') -or ($Action -eq 'Start' -and $HandoffFile)) {
    $helperAction = switch ($Action) {
        'DiagnosticsLogin' { 'login' }
        'DiagnosticsStatus' { 'status' }
        'DiagnosticsRetry' { 'retry' }
        'DiagnosticsExport' { 'export' }
        default { 'run' }
    }
    $helperArguments = @((Join-Path $repoRoot 'tools/mcp-diagnostics-launcher.mjs'), $helperAction, '--origin', $Origin)
    if ($HandoffFile) { $helperArguments += @('--handoff-file', [IO.Path]::GetFullPath($HandoffFile)) }
    if ($LocalCaseId) { $helperArguments += @('--local-case-id', $LocalCaseId) }
    & node @helperArguments
    if ($LASTEXITCODE -ne 0) { throw "Diagnostic launcher exited with code $LASTEXITCODE" }
    return
}
$executable = Join-Path $repoRoot '.local/codex-runner-inspection/package/vendor/x86_64-pc-windows-msvc/bin/codex.exe'
if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) { throw 'Verified Codex 0.165.0 bundle is missing' }
# AICODE-NOTE: Keep login and execution on the same native OAuth store. This
# launcher never reads or injects a manual platform credential.
Remove-Item Env:W3_BENCH_TOKEN -ErrorAction SilentlyContinue
$cliArguments = @('--no-daemon', '-c', 'mcp_oauth_credentials_store="file"',
    '-c', 'cli_auth_credentials_store="file"', '-c', 'mcp_oauth_callback_port=38765',
    '-c', 'mcp_oauth_callback_url="http://127.0.0.1:38765/callback"',
    '-c', 'mcp_servers.w3bench_user.enabled=true')
switch ($Action) {
    'Login' { $cliArguments += @('mcp', 'login', 'w3bench_user', '--scopes', 'agent:operate,offline_access') }
    'Check' { $cliArguments += @('mcp', 'get', 'w3bench_user', '--json') }
    'Start' {
        Write-Host 'Interactive TUI: client-side diagnostics unsupported. Use Run -HandoffFile for safe per-call collection and automatic delivery.'
        # Benchmark solving uses only the participant MCP surface. Avoid local
        # execution or unrelated plugins during this dedicated client session.
        foreach ($feature in @('apps', 'plugins', 'multi_agent', 'shell_tool', 'unified_exec',
            'shell_snapshot', 'browser_use', 'browser_use_external', 'browser_use_full_cdp_access',
            'computer_use', 'browser_annotation_api')) { $cliArguments += @('--disable', $feature) }
        $cliArguments += @('--sandbox', 'read-only', '-c', 'project_doc_max_bytes=0',
            '-c', 'mcp_servers.w3bench_user.required=true')
    }
}
& $executable @cliArguments
if ($LASTEXITCODE -ne 0) { throw "Codex exited with code $LASTEXITCODE" }
