param(
    [ValidateSet('BEF-SC-001', 'BEF-SC-002', 'BEF-SC-003', 'BEF-SC-004', 'BEF-SC-005', 'BEF-SC-006', 'BEF-SC-007', 'BEF-SC-008', 'BEF-SC-009', 'BEF-SC-010', 'BEF-SC-011', 'BEF-SC-012')]
    [string]$ScenarioId,
    [switch]$Acceptance,
    [switch]$SyncedMain,
    [string]$SecretDirectory = (Join-Path $PSScriptRoot '.local/secrets')
)

$ErrorActionPreference = 'Stop'
$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$secretRoot = [System.IO.Path]::GetFullPath($SecretDirectory)
$python = Join-Path $repoRoot '.venv/Scripts/python.exe'

function Read-Secret([string]$Name) {
    $path = Join-Path $secretRoot $Name
    if (-not [System.IO.File]::Exists($path)) { throw "Required local secret file is missing: $path" }
    $value = [System.IO.File]::ReadAllText($path).Trim()
    if ([string]::IsNullOrWhiteSpace($value)) { throw "Required local secret file is empty: $path" }
    return $value
}

function PortOrDefault([string]$Name, [string]$Default) {
    $value = [Environment]::GetEnvironmentVariable($Name, 'Process')
    if ([string]::IsNullOrWhiteSpace($value)) { return $Default }
    return $value
}

if (-not [System.IO.File]::Exists($python)) { throw 'Project .venv Python is unavailable; bootstrap the approved BDD environment first.' }
if ($Acceptance -and $ScenarioId) {
    throw 'ScenarioId filters mapper mode only; omit it when running full acceptance with -Acceptance.'
}

$names = @(
    'BEF_API_BASE_URL', 'BEF_DATABASE_OBSERVER_URL', 'BEF_ADMIN_KEY', 'BEF_SERVICE_KEY',
    'BEF_SOURCE_PROXY_URL', 'BEF_LOCAL_RPC_PROXY_URL_BEF_ENV_A', 'BEF_LOCAL_RPC_PROXY_URL_BEF_ENV_B',
    'BEF_FACILITATOR_URL_BEF_ENV_A', 'BEF_FACILITATOR_URL_BEF_ENV_B', 'BEF_SPEC_PROFILE'
)
$prior = @{}
foreach ($name in $names) { $prior[$name] = [Environment]::GetEnvironmentVariable($name, 'Process') }

try {
    $observerPassword = Read-Secret 'database-observer-password'
    $apiPort = PortOrDefault 'BEF_API_HOST_PORT' '8783'
    $observerPort = PortOrDefault 'BEF_DATABASE_HOST_PORT' '55432'
    $sourcePort = PortOrDefault 'BEF_SOURCE_PROXY_HOST_PORT' '18544'
    $localPortA = PortOrDefault 'BEF_LOCAL_RPC_A_HOST_PORT' '18545'
    $localPortB = PortOrDefault 'BEF_LOCAL_RPC_B_HOST_PORT' '28545'
    $facilitatorPortA = PortOrDefault 'BEF_FACILITATOR_A_HOST_PORT' '14021'
    $facilitatorPortB = PortOrDefault 'BEF_FACILITATOR_B_HOST_PORT' '24021'
    $env:BEF_API_BASE_URL = "http://127.0.0.1:$apiPort"
    $env:BEF_DATABASE_OBSERVER_URL = "postgres://bef_observer:$observerPassword@127.0.0.1:$observerPort/bef"
    $env:BEF_ADMIN_KEY = Read-Secret 'admin-key'
    $env:BEF_SERVICE_KEY = Read-Secret 'service-key'
    $env:BEF_SOURCE_PROXY_URL = "http://127.0.0.1:$sourcePort"
    $env:BEF_LOCAL_RPC_PROXY_URL_BEF_ENV_A = "http://127.0.0.1:$localPortA"
    $env:BEF_LOCAL_RPC_PROXY_URL_BEF_ENV_B = "http://127.0.0.1:$localPortB"
    $env:BEF_FACILITATOR_URL_BEF_ENV_A = "http://127.0.0.1:$facilitatorPortA"
    $env:BEF_FACILITATOR_URL_BEF_ENV_B = "http://127.0.0.1:$facilitatorPortB"
    if ($SyncedMain) { $env:BEF_SPEC_PROFILE = 'synced-main' }
    else { $env:BEF_SPEC_PROFILE = 'active-delta' }

    if ($Acceptance) {
        $arguments = @('tools/run_bdd_acceptance.py')
        if (-not $SyncedMain) { $arguments += @('--change', 'benchmark-environment-feasibility') }
    }
    elseif ($SyncedMain) {
        $arguments = @('-m', 'pytest', 'tests/bdd/mappers', 'tests/bdd/traceability', '-q')
        if ($ScenarioId) {
            $arguments += @('-k', "test_$($ScenarioId.ToLower().Replace('-', '_'))")
        }
    }
    else {
        $arguments = @(
            '-m', 'pytest',
            'tests/bdd/mappers/test_benchmark_environment_feasibility_bdd.py',
            '--change', 'benchmark-environment-feasibility',
            '-q'
        )
        if ($ScenarioId) {
            $arguments += @('-k', "test_$($ScenarioId.ToLower().Replace('-', '_'))")
        }
    }
    Push-Location $repoRoot
    try { & $python @arguments; $exitCode = $LASTEXITCODE }
    finally { Pop-Location }
}
finally {
    foreach ($name in $names) {
        if ($null -eq $prior[$name]) { [Environment]::SetEnvironmentVariable($name, $null, 'Process') }
        else { [Environment]::SetEnvironmentVariable($name, $prior[$name], 'Process') }
    }
    $observerPassword = $null
}

exit $exitCode
