param(
    [ValidateSet('Start', 'Restart', 'Status', 'Stop')]
    [string]$Action = 'Status',
    [switch]$EnableExecutor
)
$ErrorActionPreference = 'Stop'
$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$containerName = 'oid-google-local'
$composeFile = Join-Path $PSScriptRoot 'compose.yaml'
$googleComposeFile = Join-Path $PSScriptRoot 'compose.google-local.yaml'
Push-Location $repoRoot
try {
    $exists = & docker ps -a --filter "name=^/$containerName$" --format '{{.Names}}'
    if ($LASTEXITCODE -ne 0) { throw 'Docker is unavailable' }
    if ($exists) {
        $project = & docker inspect $containerName --format '{{index .Config.Labels "com.docker.compose.project"}}'
        if ($LASTEXITCODE -ne 0 -or $project -ne 'web-agent-bench-oid') { throw 'Refusing an unrelated container' }
    }
    if ($Action -eq 'Status') {
        & docker ps -a --filter "name=^/$containerName$" --format '{{.Names}} {{.Status}} {{.Ports}}'
        if (Test-Path -LiteralPath '.local/owner-identity/google-local/ready.json') {
            Get-Content -LiteralPath '.local/owner-identity/google-local/ready.json'
        }
        return
    }
    if ($exists -and $Action -eq 'Start') { throw 'Container already exists; use Restart to retain its database and private runtime state' }
    if ($exists -and $Action -in @('Restart', 'Stop')) {
        & docker stop $containerName
        if ($LASTEXITCODE -ne 0) { throw 'Could not stop local Google runtime' }
        & docker rm $containerName
        if ($LASTEXITCODE -ne 0) { throw 'Could not remove stopped local Google container' }
    }
    if ($Action -eq 'Stop') { return }
    if (-not (Test-Path -LiteralPath '.local/owner-identity/secrets/google-oauth-local.json')) {
        throw 'Save the Web application OAuth JSON under .local/owner-identity/secrets/google-oauth-local.json first'
    }
    $env:OID_GOOGLE_LOCAL_EXECUTOR_ENABLED = if ($EnableExecutor) { 'true' } else { 'false' }
    & docker compose -f $composeFile -f $googleComposeFile run -d --no-deps --service-ports --name $containerName runtime node /workspace/infrastructure/owner-identity/google-local-runtime.mjs
    if ($LASTEXITCODE -ne 0) { throw 'Could not start local Google runtime' }
    Write-Output 'Starting isolated real-Google local runtime. Wait for google_local_ready in: docker logs oid-google-local'
} finally { Pop-Location }
