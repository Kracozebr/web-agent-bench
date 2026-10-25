param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ToolArguments
)
$ErrorActionPreference = 'Stop'
if (-not $ToolArguments -or $ToolArguments.Count -eq 0) {
    throw 'Pass a container command, for example: ./infrastructure/owner-identity/tool.ps1 pnpm --filter @web-agent-bench/owner-web check'
}
& docker compose -f (Join-Path $PSScriptRoot 'compose.yaml') run --rm --no-deps runtime @ToolArguments
exit $LASTEXITCODE
