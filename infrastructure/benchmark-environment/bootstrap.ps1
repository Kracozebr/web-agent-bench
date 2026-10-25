param(
    [string]$SecretDirectory = (Join-Path $PSScriptRoot '.local/secrets')
)

$ErrorActionPreference = 'Stop'
$secretRoot = [System.IO.Path]::GetFullPath($SecretDirectory)
[void][System.IO.Directory]::CreateDirectory($secretRoot)

function Write-SecretFile([string]$Name, [string]$Value) {
    $path = Join-Path $secretRoot $Name
    [System.IO.File]::WriteAllText($path, $Value, [System.Text.UTF8Encoding]::new($false))
}

function Read-SecretFile([string]$Name) {
    $path = Join-Path $secretRoot $Name
    if (-not [System.IO.File]::Exists($path)) {
        throw "Required local secret file is missing: $path"
    }
    $value = [System.IO.File]::ReadAllText($path).Trim()
    if ([string]::IsNullOrWhiteSpace($value)) {
        throw "Required local secret file is empty: $path"
    }
    return $value
}

function New-UrlSafeSecret([int]$ByteCount = 48) {
    $bytes = [byte[]]::new($ByteCount)
    $generator = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $generator.GetBytes($bytes)
        return [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
    }
    finally {
        $generator.Dispose()
        [Array]::Clear($bytes, 0, $bytes.Length)
    }
}

foreach ($name in @('admin-key', 'service-key', 'postgres-owner-password', 'database-api-password', 'database-observer-password')) {
    $path = Join-Path $secretRoot $name
    if ([System.IO.File]::Exists($path)) {
        $existing = Read-SecretFile $name
        if ($existing.Length -lt 32) { throw "Local secret file is too short: $path" }
    }
    else {
        Write-SecretFile $name (New-UrlSafeSecret)
    }
}

$ownerPassword = Read-SecretFile 'postgres-owner-password'
$apiPassword = Read-SecretFile 'database-api-password'
$observerPassword = Read-SecretFile 'database-observer-password'
Write-SecretFile 'database-owner-url' "postgres://bef_owner:$ownerPassword@postgres:5432/bef"
Write-SecretFile 'database-api-url' "postgres://bef_api:$apiPassword@postgres:5432/bef"

$sourceUrlPath = Join-Path $secretRoot 'source-rpc-url'
if ([System.IO.File]::Exists($sourceUrlPath)) {
    $sourceUrl = Read-SecretFile 'source-rpc-url'
    $parsed = $null
    if (-not [Uri]::TryCreate($sourceUrl, [UriKind]::Absolute, [ref]$parsed) -or
        $parsed.Scheme -notin @('https', 'http') -or [string]::IsNullOrWhiteSpace($parsed.Host)) {
        throw "The local source RPC secret must contain an absolute HTTP(S) endpoint: $sourceUrlPath"
    }
}
else {
    Write-Host "Create $sourceUrlPath with the approved read-only Base RPC URL; rerun this bootstrap after adding it."
    Write-Host 'The endpoint value is never printed or added to command arguments.'
}

Write-Host "Generated or retained local BEF credentials under $secretRoot; secret values were not displayed."
Write-Host 'The database observer URL is assembled in memory by run-bdd.ps1 from the observer password file.'

if (-not [System.IO.File]::Exists($sourceUrlPath) -or [string]::IsNullOrWhiteSpace([System.IO.File]::ReadAllText($sourceUrlPath))) {
    exit 2
}
