[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$PrivateCredentialFile,

    [Parameter(Mandatory = $true)]
    [string]$NonsensitivePromptFile,

    [Parameter(Mandatory = $true)]
    [string]$SanitizedOutputPath,

    [string]$CodexExecutablePath,

    [Parameter(Mandatory = $true)]
    [string[]]$EnabledMcpTools
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# AICODE-NOTE: This opt-in local model runner uses the user's existing CODEX_HOME auth, keeps the
# owner bearer in the Codex child environment, disables local execution and unrelated tool surfaces,
# and retains only bounded sanitized event metadata. It is a model attempt, not benchmark acceptance.
$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$workspace = Join-Path $repoRoot '.local/owner-identity/google-local/codex-workspace'
$helper = Join-Path $PSScriptRoot 'run-codex-google-local.mjs'
$node = Get-Command node.exe -ErrorAction SilentlyContinue

if (-not $node -or -not (Test-Path -LiteralPath $helper -PathType Leaf)) {
    Write-Output '{"status":"blocked","errorCode":"runner_dependency_unavailable"}'
    exit 2
}

if (-not $CodexExecutablePath) {
    $CodexExecutablePath = Join-Path $repoRoot '.local/codex-runner-inspection/package/vendor/x86_64-pc-windows-msvc/bin/codex.exe'
}

try {
    $null = New-Item -ItemType Directory -Force -Path $workspace
    $psi = [Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $node.Source
    $psi.WorkingDirectory = $repoRoot
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $nodeArguments = @(
        $helper,
        '--private-credential-file', [IO.Path]::GetFullPath($PrivateCredentialFile),
        '--nonsensitive-prompt-file', [IO.Path]::GetFullPath($NonsensitivePromptFile),
        '--sanitized-output-path', [IO.Path]::GetFullPath($SanitizedOutputPath),
        '--codex-executable', [IO.Path]::GetFullPath($CodexExecutablePath),
        '--workspace', [IO.Path]::GetFullPath($workspace)
    )
    if ($EnabledMcpTools -and $EnabledMcpTools.Count -gt 0) {
        $nodeArguments += @('--enabled-mcp-tools', (ConvertTo-Json -InputObject @($EnabledMcpTools) -Compress))
    }
    foreach ($argument in $nodeArguments) {
        $psi.ArgumentList.Add([string]$argument)
    }

    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $psi
    if (-not $process.Start()) { throw 'start_failed' }
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()
    $process.WaitForExit()
    $stdout = $stdoutTask.GetAwaiter().GetResult()
    $null = $stderrTask.GetAwaiter().GetResult()
    if ($stdout) {
        Write-Output $stdout.Trim()
    } else {
        Write-Output '{"status":"blocked","errorCode":"helper_process_failed"}'
    }
    exit $process.ExitCode
} catch {
    Write-Output '{"status":"blocked","errorCode":"runner_start_failed"}'
    exit 2
}
