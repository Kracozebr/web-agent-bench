param(
    [ValidateSet('oid_acceptance_1cd165376c254469960b85ef058ab3ca')]
    [string]$SourceDatabase = 'oid_acceptance_1cd165376c254469960b85ef058ab3ca',
    [ValidatePattern('^[a-f0-9]{32}$')]
    [string]$CheckpointId = [Guid]::NewGuid().ToString('N'),
    [switch]$PreflightOnly,
    [switch]$ContinueCheckpoint,
    [switch]$CryptoSelfTestOnly
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$composePath = Join-Path $PSScriptRoot 'compose.yaml'
$captureComposePath = Join-Path $PSScriptRoot 'compose.reports-acceptance.yaml'
$artifactRelative = ".local/owner-identity/report-restore-rehearsals/$CheckpointId"
$artifactRoot = Join-Path $repositoryRoot ($artifactRelative -replace '/', [IO.Path]::DirectorySeparatorChar)
$journalRoot = Join-Path $artifactRoot 'journal'
$composePrefix = @('-f', $composePath, '-f', $captureComposePath)
$oldDatabaseHostPort = $env:OID_DATABASE_HOST_PORT
$env:OID_DATABASE_HOST_PORT = '65433'

function Write-NewJson([string]$Path, [object]$Value) {
    $directory = [IO.Path]::GetDirectoryName($Path)
    [void][IO.Directory]::CreateDirectory($directory)
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes(($Value | ConvertTo-Json -Depth 16) + "`n")
    $stream = [IO.File]::Open($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    } finally { $stream.Dispose() }
    return [ordered]@{ bytes = $bytes.Length; sha256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }
}

function Invoke-Docker([string[]]$Arguments) {
    $output = & docker @Arguments 2>$null
    if ($LASTEXITCODE -ne 0) { throw 'docker_command_failed' }
    return @($output | ForEach-Object { $_.ToString() })
}

function Invoke-Compose([string[]]$Arguments) {
    return Invoke-Docker (@('compose') + $composePrefix + $Arguments)
}

function Write-JournalEvent([string]$Name, [object]$Fields) {
    $ordinal = switch ($Name) {
        'started' { '000' }
        'preflight-complete' { '001' }
        'preflight-failed' { '001' }
        'preflight-revalidated' { '002' }
        'encryption-primitives-verified' { '003' }
        'source-dump-started' { '004' }
        'source-dump-complete' { '005' }
        'ciphertext-tamper-negative-tested' { '006' }
        'bundle-finalize-started' { '007' }
        'bundle-finalized' { '008' }
        'restore-input-staging-started' { '009' }
        'bundle-key-recovery-verified' { '010' }
        'restore-database-creation-started' { '011' }
        'restore-verification-started' { '012' }
        'restore-verified' { '013' }
        'expired-input-staging-started' { '014' }
        'expired-database-creation-started' { '015' }
        'expired-fixture-preparation-started' { '016' }
        'expired-fixture-prepared' { '017' }
        'expired-retention-not-run' { '018' }
        'expired-cleanup-started' { '019' }
        'expired-cleanup-complete' { '020' }
        'sanitized-dump-started' { '021' }
        'sanitized-dump-complete' { '022' }
        'sanitized-inventory-finalize-started' { '023' }
        'sanitized-inventory-finalized' { '024' }
        'complete' { '025' }
        'failed' { '999' }
        default { throw 'invalid_journal_event' }
    }
    $row = [ordered]@{
        schemaVersion = 'bpc-report-restore-journal/v1'
        event = $Name
        checkpointId = $CheckpointId
        sourceDatabase = $SourceDatabase
        restoreDatabasePrefix = 'oid_restore_'
        artifactRelative = $artifactRelative
        occurredAt = [DateTime]::UtcNow.ToString('o')
        writesMayBeEnabled = $false
    }
    foreach ($key in $Fields.Keys) { $row[$key] = $Fields[$key] }
    return Write-NewJson (Join-Path $journalRoot "$ordinal-$Name.json") $row
}

function Get-RehearsalSourceHashes {
    $sourceDirectory = Join-Path $repositoryRoot 'packages/owner-identity/src'
    if (-not [IO.Directory]::Exists($sourceDirectory)) { throw 'rehearsal_source_missing' }
    $paths = @(
        Get-ChildItem -LiteralPath $sourceDirectory -Force -File -Recurse | ForEach-Object {
            if ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'rehearsal_source_unsafe' }
            [IO.Path]::GetRelativePath($repositoryRoot, $_.FullName).Replace('\', '/')
        }
    ) + @(
        'packages/owner-identity/package.json',
        'pnpm-lock.yaml',
        'infrastructure/owner-identity/rehearse-report-backup-restore.ps1',
        'infrastructure/owner-identity/rehearse-report-backup-restore.mjs',
        'infrastructure/owner-identity/beta-backup-inventory.mjs'
    )
    $hashes = [ordered]@{}
    foreach ($relativePath in ($paths | Sort-Object -Unique)) {
        $path = Join-Path $repositoryRoot ($relativePath -replace '/', [IO.Path]::DirectorySeparatorChar)
        if (-not [IO.File]::Exists($path)) { throw 'rehearsal_source_missing' }
        $hashes[$relativePath] = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    return $hashes
}

function Invoke-PinnedHelper([string]$Phase, [string[]]$ExtraArguments = @()) {
    $arguments = @(
        'run', '--rm', '--no-deps', '-T', 'runtime',
        'pnpm', '--filter', '@web-agent-bench/owner-identity', 'exec', 'node', '--import', 'tsx',
        '/workspace/infrastructure/owner-identity/rehearse-report-backup-restore.mjs',
        '--phase', $Phase,
        '--source-database', $SourceDatabase,
        '--checkpoint-id', $CheckpointId,
        '--artifact-relative', $artifactRelative
    ) + $ExtraArguments
    $output = Invoke-Compose $arguments
    $jsonLine = @($output | Where-Object { $_.TrimStart().StartsWith('{') } | Select-Object -Last 1)
    if ($jsonLine.Count -ne 1) { throw 'pinned_helper_result_missing' }
    try { $result = $jsonLine[0] | ConvertFrom-Json -AsHashtable } catch { throw 'pinned_helper_result_invalid' }
    if ($result.phase -ne $Phase -or $result.ContainsKey('errorCode')) { throw 'pinned_helper_phase_failed' }
    return $result
}

function Assert-UnservedSource {
    $composeRows = @(Invoke-Compose @('ps', '--format', 'json') | Where-Object { $_.Trim() } | ForEach-Object { $_ | ConvertFrom-Json -AsHashtable })
    $runningRows = @($composeRows | Where-Object { $_.State -eq 'running' })
    if ($runningRows.Count -ne 1 -or $runningRows[0].Service -ne 'postgres') { throw 'source_must_remain_unserved' }
    $allProjectIds = @(Invoke-Docker @('ps', '-q', '--filter', 'label=com.docker.compose.project=web-agent-bench-oid') | Where-Object { $_ -match '^[a-f0-9]{12,64}$' })
    foreach ($id in $allProjectIds) {
        $labels = @(Invoke-Docker @('inspect', '--format', '{{ index .Config.Labels "com.docker.compose.service" }}|{{ index .Config.Labels "com.docker.compose.oneoff" }}', $id))
        if ($labels.Count -ne 1) { throw 'compose_runtime_identity_unknown' }
        $parts = $labels[0].Split('|')
        if ($parts.Count -ne 2) { throw 'compose_runtime_identity_unknown' }
        if ($parts[0] -eq 'postgres' -and $parts[1] -eq 'false') { continue }
        if ($parts[0] -eq 'runtime' -and $parts[1] -eq 'true') {
            $command = @(Invoke-Docker @('inspect', '--format', '{{json .Config.Cmd}}', $id))
            $knownOfflineScripts = '(?i)(?:validate-difficulty-v2-release|verify-difficulty-v2-references|review-difficulty-v2-minima|' +
                'assemble-difficulty-v2-release|assemble-difficulty-v2-candidates|assemble-task-release-candidate|' +
                'assemble-ranked-task-candidates|assemble-training-task-candidates|verify-task-reference-inventory|' +
                'verify-runtime-feasibility|verify-release-feasibility)\.mjs'
            $knownOfflineCheck = '(?i)(?:--test\b|test:[a-z0-9:_-]+|typecheck\b|lint\b|node[^\]]{0,100}--check\b)'
            if ($command.Count -ne 1 -or ($command[0] -notmatch $knownOfflineScripts -and $command[0] -notmatch $knownOfflineCheck) -or
                $command[0] -match '(?i)server|next\s+start|(^|[^a-z])serve([^a-z]|$)|(^|[^a-z])dev([^a-z]|$)') {
                throw 'source_must_remain_unserved'
            }
            # AICODE-NOTE: Allow only named offline release tools/checks; live server processes and all non-approved commands fail closed.
            continue
        }
        throw 'source_must_remain_unserved'
    }
}

function Invoke-Pg([string]$Database, [string]$Query) {
    if ($Database -ne 'postgres' -and $Database -notmatch '^oid_(acceptance|restore)_[a-f0-9]{32}$') { throw 'database_name_rejected' }
    $output = Invoke-Compose @('exec', '-T', 'postgres', 'psql', '-U', 'oid_owner', '-d', $Database,
        '-X', '-A', '-t', '-v', 'ON_ERROR_STOP=1', '-c', $Query)
    return ($output -join "`n").Trim()
}

function Assert-NewRestoreDatabase([string]$Database) {
    if ($Database -notmatch '^oid_restore_[a-f0-9]{32}$') { throw 'restore_database_rejected' }
    $exists = Invoke-Pg 'postgres' "SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname='$Database')::text"
    if ($exists -ne 'false') { throw 'restore_database_already_exists' }
}

function New-RestoreDatabase([string]$Database, [string]$ContainerDump, [string]$Purpose) {
    Assert-NewRestoreDatabase $Database
    $event = if ($Purpose -eq 'restore') { 'restore-database-creation-started' } else { 'expired-database-creation-started' }
    [void](Write-JournalEvent $event ([ordered]@{ restoreDatabase = $Database; purpose = $Purpose; databaseMutation = 'isolated_restore_database_only' }))
    $result = Invoke-Compose @('exec', '-T', 'postgres', 'createdb', '-U', 'oid_owner', '-T', 'template0', $Database)
    $result = Invoke-Compose @('exec', '-T', 'postgres', 'pg_restore', '-U', 'oid_owner', '-d', $Database,
        '--exit-on-error', '--no-owner', '--no-acl', $ContainerDump)
    $grantSql = "GRANT CONNECT ON DATABASE `"$Database`" TO oid_observer; GRANT USAGE ON SCHEMA public TO oid_observer; GRANT SELECT ON ALL TABLES IN SCHEMA public TO oid_observer; GRANT SELECT ON ALL SEQUENCES IN SCHEMA public TO oid_observer; ALTER DEFAULT PRIVILEGES FOR ROLE oid_owner IN SCHEMA public GRANT SELECT ON TABLES TO oid_observer;"
    [void](Invoke-Pg $Database $grantSql)
}

function New-DumpPath([string]$Name) {
    $path = "/tmp/sc022-report-$CheckpointId-$Name.dump"
    if ($path -notmatch '^/tmp/sc022-report-[a-f0-9]{32}-(source|restore|expired)\.dump$') { throw 'container_dump_path_rejected' }
    return $path
}

function Write-NewBytes([string]$Path, [byte[]]$Bytes) {
    if ([IO.File]::Exists($Path)) { throw 'protected_key_already_exists' }
    $createdByThisCall = $false
    $stream = $null
    try {
        $stream = [IO.File]::Open($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        $createdByThisCall = $true
        $stream.Write($Bytes, 0, $Bytes.Length); $stream.Flush($true)
    } catch {
        $disposeFailed = $false
        if ($stream) { try { $stream.Dispose() } catch { $disposeFailed = $true }; $stream = $null }
        $deleteFailed = $false
        if ($createdByThisCall) { try { [IO.File]::Delete($Path) } catch { $deleteFailed = $true } }
        if ($disposeFailed -or $deleteFailed) { throw 'new_file_cleanup_failed' }
        throw 'new_file_write_failed'
    } finally { if ($stream) { $stream.Dispose() } }
}

function New-BundleKey {
    Add-Type -AssemblyName System.Security
    $secretsDirectory = Join-Path $repositoryRoot '.local/owner-identity/secrets'
    [void][IO.Directory]::CreateDirectory($secretsDirectory)
    $script:bundleKeyPath = Join-Path $secretsDirectory "report-restore-$CheckpointId.dpapi"
    $key = New-Object byte[] 64
    $random = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $random.GetBytes($key) } finally { $random.Dispose() }
    $entropy = [Text.Encoding]::UTF8.GetBytes("BPC-SC022:$CheckpointId")
    try {
        $protected = [Security.Cryptography.ProtectedData]::Protect($key, $entropy, [Security.Cryptography.DataProtectionScope]::CurrentUser)
        [void](Write-NewBytes $script:bundleKeyPath $protected)
        return ,$key
    } catch {
        [Array]::Clear($key, 0, $key.Length)
        throw 'protected_key_write_failed'
    }
}

function Unprotect-BundleKey([string]$Path) {
    Add-Type -AssemblyName System.Security
    if (-not [IO.File]::Exists($Path)) { throw 'protected_key_missing' }
    $entropy = [Text.Encoding]::UTF8.GetBytes("BPC-SC022:$CheckpointId")
    try { $key = [Security.Cryptography.ProtectedData]::Unprotect([IO.File]::ReadAllBytes($Path), $entropy, [Security.Cryptography.DataProtectionScope]::CurrentUser) }
    catch { throw 'protected_key_unprotect_failed' }
    if ($key.Length -ne 64) { [Array]::Clear($key, 0, $key.Length); throw 'protected_key_invalid' }
    return ,$key
}

function Get-KeyParts([byte[]]$Key) {
    if ($Key.Length -ne 64) { throw 'bundle_key_invalid' }
    $aesKey = New-Object byte[] 32
    $macKey = New-Object byte[] 32
    [Array]::Copy($Key, 0, $aesKey, 0, 32)
    [Array]::Copy($Key, 32, $macKey, 0, 32)
    return @{ Aes = $aesKey; Mac = $macKey }
}

function Add-HmacForFile([string]$Path, [byte[]]$MacKey) {
    $hmac = [Security.Cryptography.HMACSHA256]::new($MacKey)
    $inputStream = [IO.File]::OpenRead($Path)
    $buffer = New-Object byte[] (1024 * 1024)
    try {
        while (($read = $inputStream.Read($buffer, 0, $buffer.Length)) -gt 0) { [void]$hmac.TransformBlock($buffer, 0, $read, $buffer, 0) }
        [void]$hmac.TransformFinalBlock([byte[]]@(), 0, 0)
        return ,$hmac.Hash
    } finally { $inputStream.Dispose(); $hmac.Dispose() }
}

function Encrypt-Dump([string]$PlainPath, [string]$EncryptedPath, [byte[]]$Key) {
    $parts = Get-KeyParts $Key
    $header = [Text.Encoding]::ASCII.GetBytes("BPC-SC022-DBENC-V1`n")
    $iv = New-Object byte[] 16
    $random = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $random.GetBytes($iv) } finally { $random.Dispose() }
    $temporary = $EncryptedPath
    if ([IO.File]::Exists($temporary)) { throw 'encrypted_dump_path_exists' }
    $aes = [Security.Cryptography.Aes]::Create()
    $inputStream = $null; $output = $null; $crypto = $null
    $destinationCreatedByThisCall = $false
    try {
        $aes.KeySize = 256; $aes.Mode = [Security.Cryptography.CipherMode]::CBC; $aes.Padding = [Security.Cryptography.PaddingMode]::PKCS7
        $aes.Key = $parts.Aes; $aes.IV = $iv
        $inputStream = [IO.File]::OpenRead($PlainPath)
        $output = [IO.File]::Open($temporary, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        $destinationCreatedByThisCall = $true
        $output.Write($header, 0, $header.Length); $output.Write($iv, 0, $iv.Length)
        $crypto = [Security.Cryptography.CryptoStream]::new($output, $aes.CreateEncryptor(), [Security.Cryptography.CryptoStreamMode]::Write, $true)
        $inputStream.CopyTo($crypto)
        $crypto.FlushFinalBlock()
        $crypto.Dispose(); $crypto = $null
        $output.Flush($true); $output.Dispose(); $output = $null
        $tag = Add-HmacForFile $temporary $parts.Mac
        $append = [IO.File]::Open($temporary, [IO.FileMode]::Append, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try { $append.Write($tag, 0, $tag.Length); $append.Flush($true) } finally { $append.Dispose() }
    } catch {
        $script:cryptoFailureType = $_.Exception.GetType().Name
        $script:cryptoFailureLine = $_.InvocationInfo.ScriptLineNumber
        $script:cryptoFailureInnerType = if ($_.Exception.InnerException) { $_.Exception.InnerException.GetType().Name } else { 'none' }
        $script:cryptoFailureHResult = if ($_.Exception.InnerException) { $_.Exception.InnerException.HResult } else { $_.Exception.HResult }
        if ($crypto) { $crypto.Dispose() }; if ($output) { $output.Dispose() }; if ($inputStream) { $inputStream.Dispose() }
        if ($destinationCreatedByThisCall) { [IO.File]::Delete($temporary) }
        throw 'dump_encryption_failed'
    } finally {
        if ($crypto) { $crypto.Dispose() }; if ($output) { $output.Dispose() }; if ($inputStream) { $inputStream.Dispose() }
        [Array]::Clear($parts.Aes, 0, $parts.Aes.Length)
        [Array]::Clear($parts.Mac, 0, $parts.Mac.Length)
        $aes.Dispose()
    }
    return [ordered]@{
        bytes = (Get-Item -LiteralPath $EncryptedPath).Length
        sha256 = (Get-FileHash -LiteralPath $EncryptedPath -Algorithm SHA256).Hash.ToLowerInvariant()
        plaintextBytes = (Get-Item -LiteralPath $PlainPath).Length
        plaintextSha256 = (Get-FileHash -LiteralPath $PlainPath -Algorithm SHA256).Hash.ToLowerInvariant()
    }
}

function Read-Exact([IO.Stream]$Stream, [byte[]]$Buffer, [int]$Offset, [int]$Count) {
    $readTotal = 0
    while ($readTotal -lt $Count) {
        $read = $Stream.Read($Buffer, $Offset + $readTotal, $Count - $readTotal)
        if ($read -le 0) { throw 'encrypted_dump_truncated' }
        $readTotal += $read
    }
}

function Decrypt-Dump([string]$EncryptedPath, [string]$PlainPath, [byte[]]$Key) {
    $parts = Get-KeyParts $Key
    $header = [Text.Encoding]::ASCII.GetBytes("BPC-SC022-DBENC-V1`n")
    if ([IO.File]::Exists($PlainPath)) { throw 'plaintext_temp_already_exists' }
    $plaintextCreatedByThisCall = $false
    $file = [IO.File]::OpenRead($EncryptedPath)
    $length = $file.Length
    $headerLength = $header.Length + 16
    if ($length -lt ($headerLength + 16 + 32)) { $file.Dispose(); throw 'encrypted_dump_truncated' }
    $macOffset = $length - 32
    $hmac = [Security.Cryptography.HMACSHA256]::new($parts.Mac)
    $buffer = New-Object byte[] (1024 * 1024)
    try {
        $remaining = $macOffset
        while ($remaining -gt 0) { $read = $file.Read($buffer, 0, [int][Math]::Min($buffer.Length, $remaining)); if ($read -le 0) { throw 'encrypted_dump_truncated' }; [void]$hmac.TransformBlock($buffer, 0, $read, $buffer, 0); $remaining -= $read }
        [void]$hmac.TransformFinalBlock([byte[]]@(), 0, 0)
        $actualTag = $hmac.Hash
        $expectedTag = New-Object byte[] 32
        $file.Position = $macOffset; Read-Exact $file $expectedTag 0 32
        if (-not [Security.Cryptography.CryptographicOperations]::FixedTimeEquals($actualTag, $expectedTag)) { throw 'encrypted_dump_authentication_failed' }
        $file.Position = 0
        $observedHeader = New-Object byte[] $header.Length
        Read-Exact $file $observedHeader 0 $header.Length
        if (-not [Security.Cryptography.CryptographicOperations]::FixedTimeEquals($observedHeader, $header)) { throw 'encrypted_dump_format_rejected' }
        $iv = New-Object byte[] 16; Read-Exact $file $iv 0 16
        $cipherLength = $macOffset - $headerLength
        if ($cipherLength -lt 16 -or ($cipherLength % 16) -ne 0) { throw 'encrypted_dump_format_rejected' }
        $aes = [Security.Cryptography.Aes]::Create()
        $decryptor = $null; $output = $null
        try {
            $aes.KeySize = 256; $aes.Mode = [Security.Cryptography.CipherMode]::CBC; $aes.Padding = [Security.Cryptography.PaddingMode]::PKCS7
            $aes.Key = $parts.Aes; $aes.IV = $iv
            $decryptor = $aes.CreateDecryptor()
            $output = [IO.File]::Open($PlainPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
            $plaintextCreatedByThisCall = $true
            $file.Position = $headerLength
            $remaining = $cipherLength
            $cipher = New-Object byte[] (1024 * 1024)
            $clear = New-Object byte[] (1024 * 1024)
            while ($remaining -gt 16) {
                $take = [int][Math]::Min($cipher.Length, $remaining - 16)
                $take -= ($take % 16)
                Read-Exact $file $cipher 0 $take
                $written = $decryptor.TransformBlock($cipher, 0, $take, $clear, 0)
                $output.Write($clear, 0, $written)
                $remaining -= $take
            }
            $last = New-Object byte[] 16; Read-Exact $file $last 0 16
            $final = $decryptor.TransformFinalBlock($last, 0, 16)
            $output.Write($final, 0, $final.Length); $output.Flush($true)
        } finally {
            if ($output) { $output.Dispose() }; if ($decryptor) { $decryptor.Dispose() }; $aes.Dispose()
        }
    } catch {
        if ($plaintextCreatedByThisCall) { [IO.File]::Delete($PlainPath) }
        throw 'encrypted_dump_verification_failed'
    } finally {
        $file.Dispose(); $hmac.Dispose()
        [Array]::Clear($parts.Aes, 0, $parts.Aes.Length)
        [Array]::Clear($parts.Mac, 0, $parts.Mac.Length)
    }
}

function Copy-ContainerDumpToHost([string]$ContainerDump, [string]$HostDump) {
    if ([IO.File]::Exists($HostDump)) { throw 'host_dump_temp_already_exists' }
    $hostDumpCreatedByThisCall = $false
    try {
        $reservation = [IO.File]::Open($HostDump, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        $hostDumpCreatedByThisCall = $true
        $reservation.Dispose()
        $ids = @(Invoke-Compose @('ps', '-q', 'postgres') | Where-Object { $_ -match '^[a-f0-9]{12,64}$' })
        if ($ids.Count -ne 1) { throw 'postgres_container_missing_or_ambiguous' }
        [void](Invoke-Docker @('cp', "$($ids[0]):$ContainerDump", $HostDump))
        if (-not [IO.File]::Exists($HostDump) -or (Get-Item -LiteralPath $HostDump).Length -lt 1) { throw 'host_dump_copy_missing' }
    } catch {
        if ($hostDumpCreatedByThisCall) { [IO.File]::Delete($HostDump) }
        throw 'host_dump_copy_failed'
    }
}

function Create-EncryptedDatabaseDump([string]$Database, [string]$Label, [string]$EncryptedPath, [byte[]]$Key) {
    $containerDump = New-DumpPath $Label
    $hostDump = Join-Path ([IO.Path]::GetTempPath()) "sc022-report-$CheckpointId-$Label-$([Guid]::NewGuid().ToString('N')).dump"
    if ([IO.File]::Exists($hostDump)) { throw 'host_dump_temp_already_exists' }
    $containerDumpCreatedByThisCall = $false
    $hostDumpCreatedByThisCall = $false
    try {
        [void](Invoke-Compose @('exec', '-T', 'postgres', 'sh', '-c', "umask 077; set -C; : > '$containerDump'"))
        $containerDumpCreatedByThisCall = $true
        [void](Invoke-Compose @('exec', '-T', 'postgres', 'pg_dump', '-U', 'oid_owner', '-d', $Database,
            '-Fc', '--no-owner', '--no-acl', '-f', $containerDump))
        Copy-ContainerDumpToHost $containerDump $hostDump
        $hostDumpCreatedByThisCall = $true
        return Encrypt-Dump $hostDump $EncryptedPath $Key
    } finally {
        $cleanupFailed = $false
        if ($hostDumpCreatedByThisCall) {
            try { [IO.File]::Delete($hostDump) } catch { $cleanupFailed = $true }
        }
        if ($containerDumpCreatedByThisCall) {
            try { Remove-ContainerDump $containerDump } catch { $cleanupFailed = $true }
        }
        if ($cleanupFailed) { throw 'temporary_dump_cleanup_failed' }
    }
}

function Copy-EncryptedDumpToContainer([string]$EncryptedPath, [string]$Label, [byte[]]$Key, [string]$ExpectedPlainSha256) {
    $containerDump = New-DumpPath $Label
    $hostPlain = Join-Path ([IO.Path]::GetTempPath()) "sc022-report-$CheckpointId-$Label-restore.dump"
    if ([IO.File]::Exists($hostPlain)) { throw 'plaintext_temp_already_exists' }
    $hostPlainCreatedByThisCall = $false
    $containerDumpCreatedByThisCall = $false
    try {
        [void](Invoke-Compose @('exec', '-T', 'postgres', 'sh', '-c', "umask 077; set -C; : > '$containerDump'"))
        $containerDumpCreatedByThisCall = $true
        Decrypt-Dump $EncryptedPath $hostPlain $Key
        $hostPlainCreatedByThisCall = $true
        $plainSha = (Get-FileHash -LiteralPath $hostPlain -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($plainSha -ne $ExpectedPlainSha256) { throw 'decrypted_dump_hash_mismatch' }
        $script:lastDecryptedDumpSha256 = $plainSha
        $ids = @(Invoke-Compose @('ps', '-q', 'postgres') | Where-Object { $_ -match '^[a-f0-9]{12,64}$' })
        if ($ids.Count -ne 1) { throw 'postgres_container_missing_or_ambiguous' }
        [void](Invoke-Docker @('cp', $hostPlain, "$($ids[0]):$containerDump"))
    } catch {
        if ($containerDumpCreatedByThisCall) { Remove-ContainerDump $containerDump }
        throw 'container_restore_dump_staging_failed'
    } finally {
        if ($hostPlainCreatedByThisCall) {
            try { [IO.File]::Delete($hostPlain) }
            catch {
                if ($containerDumpCreatedByThisCall) { Remove-ContainerDump $containerDump }
                throw 'host_plaintext_cleanup_failed'
            }
        }
    }
    return $containerDump
}

function Test-EncryptedDumpRejectsTamper([string]$EncryptedPath, [byte[]]$Key) {
    $originalBefore = (Get-FileHash -LiteralPath $EncryptedPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $tamperedPath = Join-Path ([IO.Path]::GetTempPath()) "sc022-report-$CheckpointId-tampered.enc"
    $plaintextPath = Join-Path ([IO.Path]::GetTempPath()) "sc022-report-$CheckpointId-tampered.dump"
    if ([IO.File]::Exists($tamperedPath) -or [IO.File]::Exists($plaintextPath)) { throw 'tamper_temp_already_exists' }
    $tamperedPathCreatedByThisCall = $false
    $plaintextPathCreatedByThisCall = $false
    $rejected = $false
    try {
        $source = [IO.File]::OpenRead($EncryptedPath)
        $destination = $null
        try {
            $destination = [IO.File]::Open($tamperedPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
            $tamperedPathCreatedByThisCall = $true
            $source.CopyTo($destination); $destination.Flush($true)
        } finally {
            $source.Dispose()
            if ($destination) { $destination.Dispose() }
        }
        $file = [IO.File]::Open($tamperedPath, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
        try {
            $file.Position = ([Text.Encoding]::ASCII.GetByteCount("BPC-SC022-DBENC-V1`n") + 16 + 3)
            $byte = $file.ReadByte()
            if ($byte -lt 0) { throw 'tamper_offset_out_of_range' }
            $file.Position -= 1
            $file.WriteByte([byte]($byte -bxor 1))
            $file.Flush($true)
        } finally { $file.Dispose() }
        $tamperedSha = (Get-FileHash -LiteralPath $tamperedPath -Algorithm SHA256).Hash.ToLowerInvariant()
        try { Decrypt-Dump $tamperedPath $plaintextPath $Key; $plaintextPathCreatedByThisCall = $true }
        catch { if ($_.Exception.Message -match 'encrypted_dump_verification_failed|encrypted_dump_authentication_failed') { $rejected = $true } else { throw 'tamper_negative_unexpected_error' } }
        $plaintextCreated = [IO.File]::Exists($plaintextPath)
        $originalAfter = (Get-FileHash -LiteralPath $EncryptedPath -Algorithm SHA256).Hash.ToLowerInvariant()
        if (-not $rejected -or $plaintextCreated -or $originalAfter -ne $originalBefore) { throw 'tamper_negative_verification_failed' }
        return [ordered]@{ tamperRejected = $true; plaintextCreated = $false; originalCiphertextUnchanged = $true; originalCiphertextSha256 = $originalBefore; tamperedCiphertextSha256 = $tamperedSha }
    } finally {
        if ($tamperedPathCreatedByThisCall) { [IO.File]::Delete($tamperedPath) }
        if ($plaintextPathCreatedByThisCall) { [IO.File]::Delete($plaintextPath) }
    }
}

function Test-EncryptionPrimitives {
    $plainPath = Join-Path ([IO.Path]::GetTempPath()) "sc022-report-$CheckpointId-selftest-source.txt"
    $encryptedPath = Join-Path ([IO.Path]::GetTempPath()) "sc022-report-$CheckpointId-selftest.enc"
    $restoredPath = Join-Path ([IO.Path]::GetTempPath()) "sc022-report-$CheckpointId-selftest-restored.txt"
    $preservationPath = Join-Path ([IO.Path]::GetTempPath()) "sc022-report-$CheckpointId-selftest-preserve.txt"
    $cipherPreservationPath = Join-Path ([IO.Path]::GetTempPath()) "sc022-report-$CheckpointId-selftest-preserve.enc"
    $writeFailurePath = Join-Path ([IO.Path]::GetTempPath()) "sc022-report-$CheckpointId-selftest-write-failure.tmp"
    $failedOutputDirectory = Join-Path ([IO.Path]::GetTempPath()) "sc022-report-$CheckpointId-selftest-output-directory"
    foreach ($path in @($plainPath, $encryptedPath, $restoredPath, $preservationPath, $cipherPreservationPath, $writeFailurePath)) {
        if ([IO.File]::Exists($path)) { throw 'selftest_temp_already_exists' }
    }
    if ([IO.Directory]::Exists($failedOutputDirectory)) { throw 'selftest_temp_already_exists' }
    $ownedPaths = [ordered]@{}
    foreach ($path in @($plainPath, $encryptedPath, $restoredPath, $preservationPath, $cipherPreservationPath)) { $ownedPaths[$path] = $false }
    $failedOutputDirectoryCreatedByThisCall = $false
    $payloadText = ('SC022 local encryption self-test payload.' * 4096) -join ''
    $payload = [Text.Encoding]::UTF8.GetBytes($payloadText)
    $key = New-Object byte[] 64
    $random = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $random.GetBytes($key) } finally { $random.Dispose() }
    try {
        $script:cryptoSelfTestStage = 'dpapi-roundtrip'
        Add-Type -AssemblyName System.Security
        $testEntropy = [Text.Encoding]::UTF8.GetBytes("BPC-SC022-self-test:$CheckpointId")
        $wrappedTestKey = [Security.Cryptography.ProtectedData]::Protect($key, $testEntropy, [Security.Cryptography.DataProtectionScope]::CurrentUser)
        $recoveredTestKey = [Security.Cryptography.ProtectedData]::Unprotect($wrappedTestKey, $testEntropy, [Security.Cryptography.DataProtectionScope]::CurrentUser)
        if (-not [Security.Cryptography.CryptographicOperations]::FixedTimeEquals($key, $recoveredTestKey)) { throw 'dpapi_self_test_mismatch' }
        [Array]::Clear($recoveredTestKey, 0, $recoveredTestKey.Length)
        [Array]::Clear($wrappedTestKey, 0, $wrappedTestKey.Length)
        $script:cryptoSelfTestStage = 'write-source'
        try { Write-NewBytes $writeFailurePath $null; throw 'write_failure_negative_not_observed' }
        catch { if ($_.Exception.Message -ne 'new_file_write_failed') { throw 'partial_write_cleanup_self_test_failed' } }
        if ([IO.File]::Exists($writeFailurePath)) { throw 'partial_write_cleanup_self_test_failed' }
        [void](Write-NewBytes $plainPath $payload)
        $ownedPaths[$plainPath] = $true
        $script:cryptoSelfTestStage = 'preserve-failed-encryption-target'
        [void][IO.Directory]::CreateDirectory($failedOutputDirectory)
        $failedOutputDirectoryCreatedByThisCall = $true
        try { Encrypt-Dump $plainPath $failedOutputDirectory $key; throw 'existing_encryption_target_collision_not_observed' }
        catch { if ($_.Exception.Message -ne 'dump_encryption_failed') { throw 'failed_encryption_target_preservation_failed' } }
        if (-not [IO.Directory]::Exists($failedOutputDirectory)) { throw 'failed_encryption_target_preservation_failed' }
        $script:cryptoSelfTestStage = 'encrypt'
        $encrypted = Encrypt-Dump $plainPath $encryptedPath $key
        $ownedPaths[$encryptedPath] = $true
        $script:cryptoSelfTestStage = 'decrypt'
        Decrypt-Dump $encryptedPath $restoredPath $key
        $ownedPaths[$restoredPath] = $true
        $script:cryptoSelfTestStage = 'round-trip-hash'
        $sourceHash = (Get-FileHash -LiteralPath $plainPath -Algorithm SHA256).Hash.ToLowerInvariant()
        $restoredHash = (Get-FileHash -LiteralPath $restoredPath -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($sourceHash -ne $restoredHash) { throw 'encryption_roundtrip_hash_mismatch' }
        $script:cryptoSelfTestStage = 'preserve-existing-ciphertext'
        $cipherSentinel = [Text.Encoding]::UTF8.GetBytes('preserve-this-existing-encrypted-file')
        [void](Write-NewBytes $cipherPreservationPath $cipherSentinel)
        $ownedPaths[$cipherPreservationPath] = $true
        $cipherPreservationHashBefore = (Get-FileHash -LiteralPath $cipherPreservationPath -Algorithm SHA256).Hash.ToLowerInvariant()
        try { Encrypt-Dump $plainPath $cipherPreservationPath $key; throw 'existing_ciphertext_overwritten' }
        catch { if ($_.Exception.Message -notmatch 'encrypted_dump_path_exists') { throw 'existing_ciphertext_preservation_failed' } }
        $cipherPreservationHashAfter = (Get-FileHash -LiteralPath $cipherPreservationPath -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($cipherPreservationHashBefore -ne $cipherPreservationHashAfter) { throw 'existing_ciphertext_preservation_failed' }
        $script:cryptoSelfTestStage = 'preserve-existing-plaintext'
        $sentinel = [Text.Encoding]::UTF8.GetBytes('preserve-this-existing-local-file')
        [void](Write-NewBytes $preservationPath $sentinel)
        $ownedPaths[$preservationPath] = $true
        $preservationHashBefore = (Get-FileHash -LiteralPath $preservationPath -Algorithm SHA256).Hash.ToLowerInvariant()
        try { Decrypt-Dump $encryptedPath $preservationPath $key; throw 'existing_plaintext_overwritten' }
        catch { if ($_.Exception.Message -notmatch 'plaintext_temp_already_exists') { throw 'existing_plaintext_preservation_failed' } }
        $preservationHashAfter = (Get-FileHash -LiteralPath $preservationPath -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($preservationHashBefore -ne $preservationHashAfter) { throw 'existing_plaintext_preservation_failed' }
        $script:cryptoSelfTestStage = 'tamper-negative'
        $tamper = Test-EncryptedDumpRejectsTamper $encryptedPath $key
        return [ordered]@{ dpapiKeyRecoveryVerified = $true; roundTripVerified = $true; tamperRejected = $tamper.tamperRejected; plaintextCreatedFromTampered = $tamper.plaintextCreated; preexistingPlaintextPreserved = $true; preexistingCiphertextPreserved = $true; partialWriteCleanupVerified = $true; failedEncryptionTargetPreserved = $true; payloadBytes = $payload.Length }
    } finally {
        foreach ($path in $ownedPaths.Keys) { if ($ownedPaths[$path]) { [IO.File]::Delete($path) } }
        if ($failedOutputDirectoryCreatedByThisCall) { [IO.Directory]::Delete($failedOutputDirectory, $false) }
        [Array]::Clear($key, 0, $key.Length)
    }
}

function Remove-ContainerDump([string]$ContainerDump) {
    if ($ContainerDump -notmatch '^/tmp/sc022-report-[a-f0-9]{32}-(source|restore|expired)\.dump$') { throw 'container_dump_path_rejected' }
    [void](Invoke-Compose @('exec', '-T', 'postgres', 'rm', '-f', '--', $ContainerDump))
}

if ($CryptoSelfTestOnly) {
    try {
        $script:cryptoSelfTestStage = 'initialize'
        $cryptoResult = Test-EncryptionPrimitives
        if (-not $cryptoResult.dpapiKeyRecoveryVerified -or -not $cryptoResult.roundTripVerified -or -not $cryptoResult.tamperRejected -or
            $cryptoResult.plaintextCreatedFromTampered -or -not $cryptoResult.preexistingPlaintextPreserved -or -not $cryptoResult.preexistingCiphertextPreserved -or
            -not $cryptoResult.partialWriteCleanupVerified -or -not $cryptoResult.failedEncryptionTargetPreserved) {
            throw 'encryption_primitives_self_test_failed'
        }
        $cryptoResult | ConvertTo-Json -Compress
        exit 0
    } catch {
        [Console]::Error.WriteLine((ConvertTo-Json -Compress ([ordered]@{ phase = 'crypto-self-test'; errorCode = 'encryption_primitives_self_test_failed'; stage = $script:cryptoSelfTestStage; errorType = $script:cryptoFailureType; innerType = $script:cryptoFailureInnerType; errorLine = $script:cryptoFailureLine; hResult = $script:cryptoFailureHResult })))
        exit 1
    }
}

$createdArtifact = $false
$stage = 'initialize'
$databaseMutation = 'not_started'
$bundleKey = $null
try {
    if ($PreflightOnly -and $ContinueCheckpoint) { throw 'preflight_only_cannot_continue' }
    if ($ContinueCheckpoint) {
        if (-not [IO.Directory]::Exists($artifactRoot)) { throw 'checkpoint_artifact_missing' }
        $createdArtifact = $true
        $startedJournalPath = Join-Path $journalRoot '000-started.json'
        $preflightJournalPath = Join-Path $journalRoot '001-preflight-complete.json'
        if (-not [IO.File]::Exists($startedJournalPath) -or -not [IO.File]::Exists($preflightJournalPath)) { throw 'checkpoint_preflight_journal_missing' }
        $startedJournal = Get-Content -LiteralPath $startedJournalPath -Raw | ConvertFrom-Json -AsHashtable
        $preflightJournal = Get-Content -LiteralPath $preflightJournalPath -Raw | ConvertFrom-Json -AsHashtable
        if ($startedJournal.checkpointId -ne $CheckpointId -or $startedJournal.sourceDatabase -ne $SourceDatabase -or
            $startedJournal.sourceCaptureId -ne '1cd16537-6c25-4469-960b-85ef058ab3ca' -or
            $preflightJournal.sourcePreflightStatus -ne 'passed' -or $preflightJournal.nextMutation -ne 'not_started') {
            throw 'checkpoint_preflight_journal_invalid'
        }
        $sourceToolHashes = $startedJournal.rehearsalSourceSha256
        $sourceBeforePath = Join-Path $artifactRoot 'bundle/evidence/source-before.json'
        if (-not [IO.File]::Exists($sourceBeforePath)) { throw 'checkpoint_source_before_missing' }
        $sourceBeforeEvidenceSha256 = (Get-FileHash -LiteralPath $sourceBeforePath -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($sourceBeforeEvidenceSha256 -ne $preflightJournal.sourceBeforeEvidenceSha256) { throw 'checkpoint_source_before_hash_mismatch' }
    } else {
        if ([IO.Directory]::Exists($artifactRoot)) { throw 'artifact_checkpoint_already_exists' }
        [void][IO.Directory]::CreateDirectory($artifactRoot)
        $createdArtifact = $true
        $sourceToolHashes = Get-RehearsalSourceHashes
        [void](Write-JournalEvent 'started' ([ordered]@{
            scope = 'read_only_source_preflight'
            sourceCaptureId = '1cd16537-6c25-4469-960b-85ef058ab3ca'
            rehearsalSourceSha256 = $sourceToolHashes
            captureSourceInputMapSha256Basis = 'stable 384-input hash map from the local report acceptance capture; not current tool source or target image digest'
        }))
    }

    $stage = 'runtime-image'
    $runtimeImage = @(Invoke-Docker @('image', 'inspect', '--format', '{{.Id}}', 'web-agent-bench-oid-runtime:local'))
    if ($runtimeImage.Count -ne 1 -or -not $runtimeImage[0].StartsWith('sha256:')) { throw 'pinned_runtime_image_missing' }
    $stage = 'postgres-health'
    $containerIds = @(Invoke-Compose @('ps', '-q', 'postgres') | Where-Object { $_ -match '^[a-f0-9]{12,64}$' })
    if ($containerIds.Count -ne 1) { throw 'postgres_container_missing_or_ambiguous' }
    $script:postgresContainerId = $containerIds[0]
    $health = @(Invoke-Docker @('inspect', '--format', '{{.State.Health.Status}}', $containerIds[0]))
    if ($health.Count -ne 1 -or $health[0].Trim() -ne 'healthy') { throw 'postgres_container_not_healthy' }
    $stage = 'unserved-guard'
    Assert-UnservedSource

    if ($ContinueCheckpoint) {
        $stage = 'source-read-only-preflight-revalidation'
        $currentToolHashes = Get-RehearsalSourceHashes
        if ((ConvertTo-Json -InputObject $sourceToolHashes -Compress) -cne (ConvertTo-Json -InputObject $currentToolHashes -Compress)) {
            throw 'rehearsal_source_changed_since_preflight'
        }
        $result = Invoke-PinnedHelper 'verify-preflight'
        $summary = $result
    } else {
        $stage = 'source-read-only-preflight'
        $result = Invoke-PinnedHelper 'preflight'
        $summary = $result.summary
    }
    if ($summary.sourceDatabase -ne $SourceDatabase -or $summary.sourceCaptureId -ne '1cd16537-6c25-4469-960b-85ef058ab3ca' -or
        $summary.boundary -ne 'local_unserved_acceptance_database_read_only' -or
        $summary.sourceObserverIdentity.database -ne $SourceDatabase -or
        $summary.sourceObserverIdentity.role -ne 'oid_observer' -or $summary.sourceObserverIdentity.readOnly -ne 'on') {
        throw 'source_preflight_identity_or_boundary_mismatch'
    }
    $sourceToolHashesAfterPreflight = Get-RehearsalSourceHashes
    if ((ConvertTo-Json -InputObject $sourceToolHashes -Compress) -cne (ConvertTo-Json -InputObject $sourceToolHashesAfterPreflight -Compress)) {
        throw 'rehearsal_source_changed_during_preflight'
    }
    if ($ContinueCheckpoint) {
        if ($summary.status -ne 'revalidated' -or -not $summary.sourceStable -or $summary.sourceBeforeEvidenceSha256 -ne $sourceBeforeEvidenceSha256) {
            throw 'checkpoint_preflight_revalidation_failed'
        }
        $event = Write-JournalEvent 'preflight-revalidated' ([ordered]@{
            runtimeImageId = $runtimeImage[0]
            databaseTableCount = $summary.publicTableCount
            databaseTotalsSha256 = $summary.databaseTotalsSha256
            reportCount = $summary.reportCount
            uploadRowCount = $summary.uploadRows
            screenshotCount = $summary.screenshotCount
            screenshotBytes = $summary.screenshotBytes
            captureSourceInputMapSha256 = $summary.captureSourceInputMapSha256
            sourceClosureSha256 = $summary.sourceClosureSha256
            sourceBeforeEvidenceSha256 = $summary.sourceBeforeEvidenceSha256
            rehearsalSourceSha256 = $sourceToolHashes
            sourcePreflightStatus = 'revalidated'
            nextMutation = 'not_started'
        })
    } else {
      $event = Write-JournalEvent 'preflight-complete' ([ordered]@{
        runtimeImageId = $runtimeImage[0]
        databaseTableCount = $summary.publicTableCount
        databaseTotalsSha256 = $summary.databaseTotalsSha256
        reportCount = $summary.reportCount
        uploadRowCount = $summary.uploadRows
        screenshotCount = $summary.screenshotCount
        screenshotBytes = $summary.screenshotBytes
        captureSourceInputMapSha256 = $summary.captureSourceInputMapSha256
        sourceClosureSha256 = $summary.sourceClosureSha256
        rehearsalSourceSha256 = $sourceToolHashes
        sourceBeforeEvidenceSha256 = (Get-FileHash -LiteralPath (Join-Path $artifactRoot 'bundle/evidence/source-before.json') -Algorithm SHA256).Hash.ToLowerInvariant()
        sourcePreflightStatus = 'passed'
        nextMutation = 'not_started'
      })
    }

    if ($PreflightOnly) {
        [ordered]@{
        checkpointId = $CheckpointId
        preflightStatus = 'passed'
        databaseTableCount = $summary.publicTableCount
        reportCount = $summary.reportCount
        uploadRowCount = $summary.uploadRows
        screenshotCount = $summary.screenshotCount
        screenshotBytes = $summary.screenshotBytes
        sourceDatabaseTotalsSha256 = $summary.databaseTotalsSha256
        captureSourceInputMapSha256 = $summary.captureSourceInputMapSha256
        journalSha256 = $event.sha256
        artifactPath = $artifactRoot
        databaseMutation = 'not_started'
        } | ConvertTo-Json -Depth 8
        return
    }

    $stage = 'encryption-primitives-self-test'
    $encryptionSelfTest = Test-EncryptionPrimitives
    if (-not $encryptionSelfTest.dpapiKeyRecoveryVerified -or -not $encryptionSelfTest.roundTripVerified -or -not $encryptionSelfTest.tamperRejected -or
        $encryptionSelfTest.plaintextCreatedFromTampered -or -not $encryptionSelfTest.preexistingPlaintextPreserved -or -not $encryptionSelfTest.preexistingCiphertextPreserved -or
        -not $encryptionSelfTest.partialWriteCleanupVerified -or -not $encryptionSelfTest.failedEncryptionTargetPreserved) {
        throw 'encryption_primitives_self_test_failed'
    }
    [void](Write-JournalEvent 'encryption-primitives-verified' $encryptionSelfTest)

    $sourceDumpPath = Join-Path $artifactRoot 'bundle/database.dump.enc'
    $stage = 'source-database-dump'
    Assert-UnservedSource
    [void](Write-JournalEvent 'source-dump-started' ([ordered]@{ sourceDatabase = $SourceDatabase; databaseMutation = 'temporary_source_dump_only' }))
    $databaseMutation = 'temporary_source_dump_only'
    $bundleKey = New-BundleKey
    $sourceDump = Create-EncryptedDatabaseDump $SourceDatabase 'source' $sourceDumpPath $bundleKey
    [Array]::Clear($bundleKey, 0, $bundleKey.Length)
    $bundleKey = Unprotect-BundleKey $script:bundleKeyPath
    $protectedKeyFileSha256 = (Get-FileHash -LiteralPath $script:bundleKeyPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $databaseMutation = 'encrypted_dump_saved_source_unchanged'
    [void](Write-JournalEvent 'source-dump-complete' ([ordered]@{
        encryptedDumpBytes = $sourceDump.bytes
        encryptedDumpSha256 = $sourceDump.sha256
        plaintextBytes = $sourceDump.plaintextBytes
        plaintextSha256 = $sourceDump.plaintextSha256
        protectedKeyReference = (Resolve-Path -LiteralPath $script:bundleKeyPath).Path.Substring($repositoryRoot.Length + 1)
        protectedKeyFileSha256 = $protectedKeyFileSha256
        keyRecoveryMethod = 'DPAPI_current_user_unprotect'
        sourceDatabaseMutation = 'none'
    }))
    $stage = 'ciphertext-authentication-negative'
    $tamperResult = Test-EncryptedDumpRejectsTamper $sourceDumpPath $bundleKey
    [void](Write-JournalEvent 'ciphertext-tamper-negative-tested' $tamperResult)

    $stage = 'source-dump-finalize'
    [void](Write-JournalEvent 'bundle-finalize-started' ([ordered]@{ databaseMutation = 'none' }))
    $bundleResult = Invoke-PinnedHelper -Phase 'finalize'
    if ($bundleResult.inventory.schemaVersion -ne 'beta-backup-inventory/v1' -or $bundleResult.verified.integrity -ne 'passed') {
        throw 'backup_inventory_verification_failed'
    }
    [void](Write-JournalEvent 'bundle-finalized' ([ordered]@{
        fileCount = $bundleResult.inventory.files.Count
        databaseTotalsSha256 = $bundleResult.inventory.databaseTotalsSha256
        reconciliationEvidenceSha256 = $bundleResult.inventory.reconciliationEvidenceSha256
        sourceStable = $bundleResult.sourceStable
        databaseMutation = 'none'
    }))

    $restoreDatabase = "oid_restore_$([Guid]::NewGuid().ToString('N'))"
    $restoreDump = $null
    $stage = 'restore-database'
    [void](Write-JournalEvent 'restore-input-staging-started' ([ordered]@{ restoreDatabase = $restoreDatabase; databaseMutation = 'isolated_restore_database_only' }))
    $databaseMutation = 'isolated_restore_database_only'
    try {
        $restoreDump = Copy-EncryptedDumpToContainer $sourceDumpPath 'restore' $bundleKey $sourceDump.plaintextSha256
        if ($script:lastDecryptedDumpSha256 -ne $sourceDump.plaintextSha256) { throw 'saved_key_decrypt_verification_failed' }
        [void](Write-JournalEvent 'bundle-key-recovery-verified' ([ordered]@{
            keyRecoveryMethod = 'DPAPI_current_user_unprotect'
            protectedKeyFileSha256 = $protectedKeyFileSha256
            decryptedPlaintextSha256 = $script:lastDecryptedDumpSha256
            matchesCapturedPgDump = $true
            rawKeyLogged = $false
        }))
        New-RestoreDatabase $restoreDatabase $restoreDump 'restore'
    } finally { if ($restoreDump) { Remove-ContainerDump $restoreDump } }

    $stage = 'restore-verification'
    [void](Write-JournalEvent 'restore-verification-started' ([ordered]@{ restoreDatabase = $restoreDatabase; databaseMutation = 'isolated_restore_database_only' }))
    $restoreResult = Invoke-PinnedHelper -Phase 'verify-restore' -ExtraArguments @('--restore-database', $restoreDatabase)
    if (-not $restoreResult.sourceUnchanged -or -not $restoreResult.restoredTablesAndSequencesMatch) { throw 'isolated_restore_verification_failed' }
    [void](Write-JournalEvent 'restore-verified' ([ordered]@{
        restoreDatabase = $restoreDatabase
        sourceUnchanged = $restoreResult.sourceUnchanged
        sourceFingerprintMatchesCheckpoint = $restoreResult.sourceFingerprintMatchesCheckpoint
        restoredTablesAndSequencesMatch = $restoreResult.restoredTablesAndSequencesMatch
        restoredScreenshotCount = $restoreResult.restoredScreenshotCount
        reportRetryStatus = $restoreResult.reportRetry.status
        databaseMutation = 'isolated_restore_database_only'
    }))

    $expiredDatabase = "oid_restore_$([Guid]::NewGuid().ToString('N'))"
    $stage = 'expired-clone-database'
    [void](Write-JournalEvent 'expired-input-staging-started' ([ordered]@{ restoreDatabase = $expiredDatabase; databaseMutation = 'isolated_restore_database_only' }))
    $expiredDump = Copy-EncryptedDumpToContainer $sourceDumpPath 'expired' $bundleKey $sourceDump.plaintextSha256
    try { New-RestoreDatabase $expiredDatabase $expiredDump 'expired' }
    finally { Remove-ContainerDump $expiredDump }

    $stage = 'expired-clone-preparation'
    [void](Write-JournalEvent 'expired-fixture-preparation-started' ([ordered]@{ restoreDatabase = $expiredDatabase; databaseMutation = 'isolated_restore_database_only' }))
    $prepared = Invoke-PinnedHelper -Phase 'prepare-expired' -ExtraArguments @('--expired-database', $expiredDatabase)
    $expiredStatus = $prepared.status
    $cleanup = $null
    if ($expiredStatus -eq 'prepared') {
        [void](Write-JournalEvent 'expired-fixture-prepared' ([ordered]@{ restoreDatabase = $expiredDatabase; reportCount = $prepared.reportCountBeforeCleanup; imageCount = $prepared.imageCountBeforeCleanup; syntheticClosureOnly = $true }))
        $stage = 'expired-clone-retention-cleanup'
        [void](Write-JournalEvent 'expired-cleanup-started' ([ordered]@{ restoreDatabase = $expiredDatabase; databaseMutation = 'synthetic_expired_clone_only' }))
        $cleanup = Invoke-PinnedHelper -Phase 'cleanup-expired' -ExtraArguments @('--expired-database', $expiredDatabase)
        if ($cleanup.status -ne 'synthetic_retention_cleanup_verified' -or -not $cleanup.sourceDatabaseUnchanged) { throw 'expired_clone_cleanup_verification_failed' }
        $expiredStatus = $cleanup.status
        [void](Write-JournalEvent 'expired-cleanup-complete' ([ordered]@{
            restoreDatabase = $expiredDatabase
            cleanupIterations = $cleanup.cleanupIterations
            reportsBefore = $cleanup.reportsBefore
            reportsAfter = $cleanup.reportsAfter
            uploadsBefore = $cleanup.uploadsBefore
            uploadsAfter = $cleanup.uploadsAfter
            deletionReceipts = $cleanup.deletionReceipts
            nonReportTablesUnchanged = $cleanup.nonReportTablesUnchanged
            nonReportSequencesUnchanged = $cleanup.nonReportSequencesUnchanged
            sourceDatabaseUnchanged = $cleanup.sourceDatabaseUnchanged
            databaseMutation = 'synthetic_expired_clone_only'
        }))
        $expiredRoot = Join-Path $artifactRoot ("expired-clone/$expiredDatabase" -replace '/', [IO.Path]::DirectorySeparatorChar)
        $sanitizedDumpPath = Join-Path $expiredRoot 'database.dump.enc'
        $stage = 'sanitized-clone-dump'
        [void](Write-JournalEvent 'sanitized-dump-started' ([ordered]@{ restoreDatabase = $expiredDatabase; databaseMutation = 'synthetic_expired_clone_only' }))
        $sanitizedDump = Create-EncryptedDatabaseDump $expiredDatabase 'expired' $sanitizedDumpPath $bundleKey
        [void](Write-JournalEvent 'sanitized-dump-complete' ([ordered]@{ encryptedDumpBytes = $sanitizedDump.bytes; encryptedDumpSha256 = $sanitizedDump.sha256; databaseMutation = 'synthetic_expired_clone_only' }))
        $stage = 'sanitized-inventory-finalize'
        [void](Write-JournalEvent 'sanitized-inventory-finalize-started' ([ordered]@{ databaseMutation = 'none' }))
        $sanitized = Invoke-PinnedHelper -Phase 'finalize-expired' -ExtraArguments @('--expired-database', $expiredDatabase)
        [void](Write-JournalEvent 'sanitized-inventory-finalized' ([ordered]@{ restoreDatabase = $expiredDatabase; status = $sanitized.status; databaseMutation = 'none' }))
    } else {
        [void](Write-JournalEvent 'expired-retention-not-run' ([ordered]@{ restoreDatabase = $expiredDatabase; reasonCode = $prepared.reasonCode; databaseMutation = 'isolated_restore_database_only' }))
    }

    $stage = 'complete-source-hash-check'
    $sourceToolHashesAfterRun = Get-RehearsalSourceHashes
    $toolSourcesStable = (ConvertTo-Json -InputObject $sourceToolHashes -Compress) -ceq (ConvertTo-Json -InputObject $sourceToolHashesAfterRun -Compress)
    if (-not $toolSourcesStable) { throw 'rehearsal_source_changed_during_run' }
    $stage = 'complete'
    [void](Write-JournalEvent 'complete' ([ordered]@{
        restoreDatabase = $restoreDatabase
        expiredDatabase = $expiredDatabase
        expiredRetentionStatus = $expiredStatus
        sourceStable = $bundleResult.sourceStable
        rehearsalSourceSha256 = $sourceToolHashes
        rehearsalSourceStable = $toolSourcesStable
        captureSourceInputMapSha256 = $summary.captureSourceInputMapSha256
        protectedKeyFileSha256 = $protectedKeyFileSha256
        keyRecoveryMethod = 'DPAPI_current_user_unprotect'
        databaseMutation = 'isolated_restore_databases_retained'
    }))
    [ordered]@{
        checkpointId = $CheckpointId
        preflightStatus = 'passed'
        backupInventory = 'passed'
        isolatedRestore = 'passed'
        ciphertextTamperRejected = $tamperResult.tamperRejected
        sourceUnchanged = $restoreResult.sourceUnchanged -and ($null -eq $cleanup -or
            ($cleanup.sourceDatabaseUnchanged -and $cleanup.sourceClosureUnchanged -and $cleanup.sourceImagesUnchanged))
        reportCount = $summary.reportCount
        screenshotCount = $summary.screenshotCount
        restoredScreenshotCount = $restoreResult.restoredScreenshotCount
        expiredRetention = $expiredStatus
        captureSourceInputMapSha256 = $summary.captureSourceInputMapSha256
        rehearsalSourceSha256 = $sourceToolHashes
        protectedKeyFileSha256 = $protectedKeyFileSha256
        bonusAndBenchmarkRuns = 'not_proven_by_report_only_source_capture'
        targetHostAcceptance = 'not_run'
        artifactPath = $artifactRoot
    } | ConvertTo-Json -Depth 8
} catch {
    $failure = $_
    $safeCode = if ($failure.Exception.Message -match '^[a-z0-9_]+$') { $failure.Exception.Message } else { 'rehearsal_failed' }
    if ($createdArtifact) {
        try { [void](Write-JournalEvent 'failed' ([ordered]@{
            errorCode = $safeCode
            stage = $stage
            errorType = $failure.Exception.GetType().Name
            scriptLine = $failure.InvocationInfo.ScriptLineNumber
            databaseMutation = $databaseMutation
        })) } catch { }
    }
    [Console]::Error.WriteLine((ConvertTo-Json -Compress ([ordered]@{ checkpointId = $CheckpointId; stage = $stage; errorCode = $safeCode; databaseMutation = $databaseMutation })))
    exit 1
} finally {
    if ($bundleKey -is [byte[]]) { [Array]::Clear($bundleKey, 0, $bundleKey.Length) }
    if ($null -eq $oldDatabaseHostPort) { Remove-Item Env:OID_DATABASE_HOST_PORT -ErrorAction SilentlyContinue }
    else { $env:OID_DATABASE_HOST_PORT = $oldDatabaseHostPort }
}
