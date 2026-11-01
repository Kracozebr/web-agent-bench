[CmdletBinding()]
param(
    [ValidateSet('Login', 'Start', 'Check')]
    [string]$Action = 'Start'
)
$ErrorActionPreference = 'Stop'
$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
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
