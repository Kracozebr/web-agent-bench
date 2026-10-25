param([int]$DatabasePort = 55433)
$ErrorActionPreference = 'Stop'
$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$secretRoot = Join-Path $repoRoot '.local/owner-identity/secrets'
[void][IO.Directory]::CreateDirectory($secretRoot)
foreach ($name in @('owner-password', 'observer-password', 'auth-secret')) {
    $secretPath = Join-Path $secretRoot $name
    if (-not [IO.File]::Exists($secretPath)) {
        $bytes = [byte[]]::new(48)
        [Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
        $secretValue = [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+','-').Replace('/','_')
        [IO.File]::WriteAllText($secretPath, $secretValue, [Text.UTF8Encoding]::new($false))
        [Array]::Clear($bytes, 0, $bytes.Length)
    }
    if ([IO.File]::ReadAllText($secretPath).Trim().Length -lt 32) {
        throw "Local secret is too short: $name"
    }
}
$ownerPassword = [IO.File]::ReadAllText((Join-Path $secretRoot 'owner-password')).Trim()
$observerPassword = [IO.File]::ReadAllText((Join-Path $secretRoot 'observer-password')).Trim()
[IO.File]::WriteAllText((Join-Path $secretRoot 'database-url'), "postgres://oid_owner:${ownerPassword}@127.0.0.1:$DatabasePort/owner_identity")
[IO.File]::WriteAllText((Join-Path $secretRoot 'observer-database-url'), "postgres://oid_observer:${observerPassword}@127.0.0.1:$DatabasePort/owner_identity")
Write-Host 'Local OID credentials retained/generated under ignored .local/owner-identity; no values displayed.'
