param(
    [string]$JobRoot,
    [string]$BackupRoot,
    [string]$ComposeFile = (Join-Path $PSScriptRoot 'compose.yaml'),
    [string]$RecoveryPrivateKeyPath,
    [string]$RecoveryPublicKeyPath,
    [switch]$InitializeRecoveryKey,
    [switch]$RunJobBroker,
    [switch]$Once
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$script:SafeJobErrorCodes = @(
    'database_name_invalid','database_observation_failed','database_observation_invalid','dump_output_invalid','dump_path_exists',
    'dump_stage_failed','dump_copy_failed','container_dump_cleanup_failed','postgres_container_lookup_failed',
    'postgres_container_missing_or_ambiguous','restore_database_already_exists','restore_database_create_failed',
    'restore_database_create_unverified','restore_database_missing','restore_dump_integrity_failed','restore_dump_copy_failed',
    'restore_stage_exists','restore_stage_probe_failed','pg_dump_failed','pg_restore_failed','restore_container_dump_cleanup_failed',
    'restore_checkpoint_identity_invalid','restore_creation_identity_invalid','restore_database_ownership_unproven',
    'restore_database_empty_check_failed','restore_database_not_empty','restore_database_marker_write_failed','restore_observer_grant_failed',
    'operator_recovery_private_key_missing','operator_recovery_envelope_invalid','operator_recovery_private_key_invalid',
    'operator_recovery_content_key_invalid','operator_recovery_material_invalid','operator_recovery_failed'
)

function Stop-Safe([string]$Code) { throw "bpc_$Code" }
function Get-SafeJobErrorCode($ErrorRecord) {
    if ($ErrorRecord.Exception.Message -match '^bpc_([a-z_]+)$' -and $Matches[1] -in $script:SafeJobErrorCodes) { return $Matches[1] }
    return 'job_failed'
}
function Test-Absolute([string]$Path) { return [IO.Path]::IsPathRooted($Path) }
function Get-ContainedPath([string]$Root, [string]$Path) {
    $rootFull = [IO.Path]::GetFullPath($Root).TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    $pathFull = [IO.Path]::GetFullPath($Path)
    if (-not $pathFull.StartsWith($rootFull, [StringComparison]::OrdinalIgnoreCase)) { Stop-Safe 'path_outside_root' }
    return $pathFull
}
function Assert-NoReparsePath([string]$Path, [switch]$AllowMissingFinal) {
    $full = [IO.Path]::GetFullPath($Path)
    $root = [IO.Path]::GetPathRoot($full)
    $current = $root
    $parts = $full.Substring($root.Length).Split([IO.Path]::DirectorySeparatorChar, [StringSplitOptions]::RemoveEmptyEntries)
    for ($i = 0; $i -lt $parts.Length; $i++) {
        $current = Join-Path $current $parts[$i]
        if (-not [IO.File]::Exists($current) -and -not [IO.Directory]::Exists($current)) {
            if ($AllowMissingFinal -and $i -eq ($parts.Length - 1)) { return $full }
            Stop-Safe 'path_missing'
        }
        $item = Get-Item -LiteralPath $current -Force
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { Stop-Safe 'path_reparse_point' }
        if ($i -lt ($parts.Length - 1) -and -not $item.PSIsContainer) { Stop-Safe 'path_parent_invalid' }
    }
    return $full
}
function Write-NewBytes([string]$Path, [byte[]]$Bytes) {
    $stream = $null
    $created = $false
    try {
        $stream = [IO.File]::Open($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        $created = $true
        $stream.Write($Bytes, 0, $Bytes.Length)
        $stream.Flush($true)
        $stream.Dispose(); $stream = $null
    } catch {
        if ($stream) { $stream.Dispose() }
        if ($created) { [IO.File]::Delete($Path) }
        Stop-Safe 'exclusive_write_failed'
    }
}
function Write-Result([string]$JobDirectory, [string]$JobId, [string]$Kind, [hashtable]$Fields) {
    $result = [ordered]@{ schemaVersion = 'beta-backup-host-result/v1'; jobId = $JobId; kind = $Kind; status = 'complete' }
    foreach ($key in $Fields.Keys) { $result[$key] = $Fields[$key] }
    $json = ConvertTo-Json -InputObject $result -Depth 8 -Compress
    Write-NewBytes (Join-Path $JobDirectory 'result.json') ([Text.Encoding]::UTF8.GetBytes($json + "`n"))
}
function Write-SafeJobFailureLog([string]$JobId, [string]$Kind) {
    [Console]::Out.WriteLine((ConvertTo-Json -Compress ([ordered]@{ event = 'host_job_failed'; jobId = $JobId; kind = $Kind })))
}
function Invoke-Docker([string[]]$Arguments, [string]$SafeCode, [switch]$Capture) {
    $output = & docker @Arguments 2>$null
    if ($LASTEXITCODE -ne 0) { Stop-Safe $SafeCode }
    if ($Capture) { return @($output | ForEach-Object { [string]$_ }) }
}
function Invoke-Compose([string[]]$Arguments, [string]$SafeCode, [switch]$Capture) {
    $output = & docker compose -f $script:ComposeFull @Arguments 2>$null
    if ($LASTEXITCODE -ne 0) { Stop-Safe $SafeCode }
    if ($Capture) { return @($output | ForEach-Object { [string]$_ }) }
}
function Get-PostgresContainerId {
    $rows = @(Invoke-Compose @('ps', '-q', 'postgres') 'postgres_container_lookup_failed' -Capture)
    $ids = @($rows | Where-Object { $_ -match '^[a-f0-9]{12,64}$' })
    if ($ids.Count -ne 1) { Stop-Safe 'postgres_container_missing_or_ambiguous' }
    return $ids[0]
}
function Assert-JobRequest($Request, [string]$JobDirectory, [string]$DirectoryId) {
    if ($Request.schemaVersion -ne 'beta-backup-host-job/v1' -or $Request.jobId -ne $DirectoryId -or
        $Request.jobId -notmatch '^[a-f0-9]{32}$' -or $Request.kind -notin @('pg_dump','database_exists','create_restore_database','pg_restore','recover_material')) {
        Stop-Safe 'job_request_invalid'
    }
    $allowed = switch ($Request.kind) {
        'pg_dump' { @('schemaVersion','jobId','kind','databaseName','dumpRelativePath') }
        'database_exists' { @('schemaVersion','jobId','kind','databaseName') }
        'create_restore_database' { @('schemaVersion','jobId','kind','databaseName','checkpointId') }
        'pg_restore' { @('schemaVersion','jobId','kind','databaseName','checkpointId','creationJobId','dumpRelativePath','dumpSha256') }
        'recover_material' { @('schemaVersion','jobId','kind','checkpointId','ephemeralPublicKeyPem','envelopeRelativePath','responseRelativePath') }
    }
    if (@($Request.PSObject.Properties.Name | Where-Object { $_ -notin $allowed }).Count -gt 0) { Stop-Safe 'job_request_fields_invalid' }
    if ($Request.kind -in @('pg_dump','database_exists','create_restore_database','pg_restore') -and
        $Request.databaseName -notmatch '^[A-Za-z0-9_]{1,63}$') { Stop-Safe 'database_name_invalid' }
    if ($Request.kind -eq 'pg_dump' -and ($Request.databaseName -notmatch '^(owner_identity|oid_acceptance_[a-f0-9]{32})$' -or $Request.dumpRelativePath -ne 'database.dump')) {
        Stop-Safe 'source_database_scope_invalid'
    }
    if ($Request.kind -in @('create_restore_database','pg_restore') -and $Request.databaseName -notmatch '^oid_restore_[a-f0-9]{32}$') {
        Stop-Safe 'restore_database_scope_invalid'
    }
    if ($Request.kind -eq 'pg_restore' -and ($Request.dumpRelativePath -ne 'restore.dump' -or $Request.dumpSha256 -notmatch '^[0-9a-f]{64}$')) {
        Stop-Safe 'restore_dump_request_invalid'
    }
    if ($Request.kind -in @('create_restore_database','pg_restore') -and
        ($Request.checkpointId -notmatch '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$')) {
        Stop-Safe 'restore_checkpoint_identity_invalid'
    }
    if ($Request.kind -eq 'pg_restore' -and $Request.creationJobId -notmatch '^[a-f0-9]{32}$') {
        Stop-Safe 'restore_creation_identity_invalid'
    }
    if ($Request.kind -eq 'recover_material' -and ($Request.checkpointId -notmatch '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89a-f][0-9a-f]{3}-[0-9a-f]{12}$' -or
        $Request.envelopeRelativePath -ne 'recovery-envelope.json' -or $Request.responseRelativePath -ne 'recovered-material.enc' -or
        [string]::IsNullOrWhiteSpace($Request.ephemeralPublicKeyPem))) {
        Stop-Safe 'recovery_request_invalid'
    }
}
function Test-DatabaseExists([string]$DatabaseName) {
    $sql = "SELECT CASE WHEN EXISTS (SELECT 1 FROM pg_database WHERE datname='$DatabaseName') THEN 'true' ELSE 'false' END"
    $rows = @(Invoke-Compose @('exec','-T','postgres','psql','-X','-U','oid_owner','-d','owner_identity','-Atqc',$sql) 'database_observation_failed' -Capture)
    if ($rows.Count -ne 1 -or $rows[0] -notin @('true','false')) { Stop-Safe 'database_observation_invalid' }
    return ($rows[0] -eq 'true')
}
function Invoke-PgDump([string]$JobId, [string]$DatabaseName, [string]$JobDirectory) {
    $containerId = Get-PostgresContainerId
    $containerPath = "/tmp/bpc-$JobId.dump"
    $hostPath = Join-Path $JobDirectory 'database.dump'
    if ([IO.File]::Exists($hostPath) -or [IO.File]::Exists($containerPath)) { Stop-Safe 'dump_path_exists' }
    try {
        Invoke-Compose @('exec','-T','postgres','sh','-c',"umask 077; set -C; : > '$containerPath'") 'dump_stage_failed'
        Invoke-Compose @('exec','-T','postgres','pg_dump','-U','oid_owner','-d',$DatabaseName,'-Fc','--no-owner','--no-acl','-f',$containerPath) 'pg_dump_failed'
        Invoke-Docker @('cp',"${containerId}:$containerPath",$hostPath) 'dump_copy_failed'
        $file = Get-Item -LiteralPath $hostPath -Force
        if (($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or $file.Length -le 0) { Stop-Safe 'dump_output_invalid' }
        $sha = (Get-FileHash -LiteralPath $hostPath -Algorithm SHA256).Hash.ToLowerInvariant()
        return @{ dumpBytes = $file.Length; dumpSha256 = $sha }
    } finally {
        Invoke-Compose @('exec','-T','postgres','rm','-f','--',$containerPath) 'container_dump_cleanup_failed'
    }
}
function Get-DatabaseComment([string]$DatabaseName) {
    $sql = "SELECT coalesce(shobj_description(oid,'pg_database'),'') FROM pg_database WHERE datname='$DatabaseName'"
    $rows = @(Invoke-Compose @('exec','-T','postgres','psql','-X','-U','oid_owner','-d','owner_identity','-Atqc',$sql) 'database_observation_failed' -Capture)
    if ($rows.Count -ne 1) { Stop-Safe 'database_observation_invalid' }
    return $rows[0]
}
function Assert-RestoreDatabaseOwnedAndEmpty([string]$DatabaseName, [string]$CheckpointId, [string]$CreationJobId) {
    $expectedMarker = "BPC-SC022-RESTORE/v1:${CheckpointId}:$CreationJobId"
    if ((Get-DatabaseComment $DatabaseName) -ne $expectedMarker) { Stop-Safe 'restore_database_ownership_unproven' }
    $sql = "SELECT count(*)::int FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN ('r','p','v','m','S','f')"
    $rows = @(Invoke-Compose @('exec','-T','postgres','psql','-X','-U','oid_owner','-d',$DatabaseName,'-Atqc',$sql) 'restore_database_empty_check_failed' -Capture)
    if ($rows.Count -ne 1 -or $rows[0] -ne '0') { Stop-Safe 'restore_database_not_empty' }
}
function Invoke-CreateRestoreDatabase([string]$DatabaseName, [string]$CheckpointId, [string]$CreationJobId) {
    if (Test-DatabaseExists $DatabaseName) { Stop-Safe 'restore_database_already_exists' }
    $sql = "CREATE DATABASE `"$DatabaseName`" TEMPLATE template0"
    Invoke-Compose @('exec','-T','postgres','psql','-X','-U','oid_owner','-d','owner_identity','-v','ON_ERROR_STOP=1','-c',$sql) 'restore_database_create_failed'
    if (-not (Test-DatabaseExists $DatabaseName)) { Stop-Safe 'restore_database_create_unverified' }
    $marker = "BPC-SC022-RESTORE/v1:${CheckpointId}:$CreationJobId"
    $commentSql = "COMMENT ON DATABASE `"$DatabaseName`" IS '$marker'"
    Invoke-Compose @('exec','-T','postgres','psql','-X','-U','oid_owner','-d','owner_identity','-v','ON_ERROR_STOP=1','-c',$commentSql) 'restore_database_marker_write_failed'
    Assert-RestoreDatabaseOwnedAndEmpty $DatabaseName $CheckpointId $CreationJobId
    $observerSql = "GRANT CONNECT ON DATABASE `"$DatabaseName`" TO oid_observer; GRANT USAGE ON SCHEMA public TO oid_observer; ALTER DEFAULT PRIVILEGES FOR ROLE oid_owner IN SCHEMA public GRANT SELECT ON TABLES TO oid_observer; ALTER DEFAULT PRIVILEGES FOR ROLE oid_owner IN SCHEMA public GRANT SELECT ON SEQUENCES TO oid_observer;"
    Invoke-Compose @('exec','-T','postgres','psql','-X','-U','oid_owner','-d',$DatabaseName,'-v','ON_ERROR_STOP=1','-c',$observerSql) 'restore_observer_grant_failed'
    return @{ databaseName = $DatabaseName; checkpointId = $CheckpointId; creationJobId = $CreationJobId; createdFresh = $true }
}
function Invoke-PgRestore([string]$JobId, [string]$DatabaseName, [string]$JobDirectory, [string]$ExpectedSha, [string]$CheckpointId, [string]$CreationJobId) {
    if (-not (Test-DatabaseExists $DatabaseName)) { Stop-Safe 'restore_database_missing' }
    Assert-RestoreDatabaseOwnedAndEmpty $DatabaseName $CheckpointId $CreationJobId
    $hostPath = Get-ContainedPath $JobDirectory (Join-Path $JobDirectory 'restore.dump')
    Assert-NoReparsePath $hostPath | Out-Null
    $file = Get-Item -LiteralPath $hostPath -Force
    if ($file.Length -le 0 -or (Get-FileHash -LiteralPath $hostPath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $ExpectedSha) {
        Stop-Safe 'restore_dump_integrity_failed'
    }
    $containerId = Get-PostgresContainerId
    $containerPath = "/tmp/bpc-$JobId-restore.dump"
    if (Test-ContainerFileExists $containerPath) { Stop-Safe 'restore_stage_exists' }
    try {
        Invoke-Docker @('cp',$hostPath,"${containerId}:$containerPath") 'restore_dump_copy_failed'
        Invoke-Compose @('exec','-T','postgres','pg_restore','-U','oid_owner','-d',$DatabaseName,'--exit-on-error','--no-owner','--no-acl','--single-transaction',$containerPath) 'pg_restore_failed'
        return @{ databaseName = $DatabaseName; checkpointId = $CheckpointId; creationJobId = $CreationJobId;
            dumpSha256 = $ExpectedSha; restored = $true }
    } finally {
        Invoke-Compose @('exec','-T','postgres','rm','-f','--',$containerPath) 'restore_container_dump_cleanup_failed'
    }
}
function Test-ContainerFileExists([string]$Path) {
    $rows = @(Invoke-Compose @('exec','-T','postgres','sh','-c',"test -e '$Path' && echo yes || echo no") 'restore_stage_probe_failed' -Capture)
    return ($rows -contains 'yes')
}
function Invoke-RecoverMaterial($Request, [string]$JobDirectory) {
    if (-not $script:RecoveryPrivateFull -or -not [IO.File]::Exists($script:RecoveryPrivateFull)) { Stop-Safe 'operator_recovery_private_key_missing' }
    $envelopePath = Get-ContainedPath $JobDirectory (Join-Path $JobDirectory $Request.envelopeRelativePath)
    Assert-NoReparsePath $envelopePath | Out-Null
    $envelope = Get-Content -LiteralPath $envelopePath -Raw | ConvertFrom-Json
    if ($envelope.schemaVersion -ne 'beta-backup-recovery-envelope/v1' -or $envelope.checkpointId -ne $Request.checkpointId -or
        $envelope.algorithm -ne 'RSA-OAEP-SHA256+A256GCM') { Stop-Safe 'operator_recovery_envelope_invalid' }
    Add-Type -AssemblyName System.Security
    $entropy = [Text.Encoding]::UTF8.GetBytes('BPC-SC022-OPERATOR-RECOVERY-KEY/v1')
    $wrappedPrivate = [IO.File]::ReadAllBytes($script:RecoveryPrivateFull)
    $pkcs8 = $null; $operatorRsa = $null; $contentKey = $null; $plaintext = $null; $responseKey = $null; $iv = $null
    try {
        $pkcs8 = [Security.Cryptography.ProtectedData]::Unprotect($wrappedPrivate, $entropy, [Security.Cryptography.DataProtectionScope]::CurrentUser)
        $operatorRsa = [Security.Cryptography.RSA]::Create()
        $read = 0; $operatorRsa.ImportPkcs8PrivateKey($pkcs8, [ref]$read)
        if ($read -ne $pkcs8.Length) { Stop-Safe 'operator_recovery_private_key_invalid' }
        $contentKey = $operatorRsa.Decrypt([Convert]::FromBase64String($envelope.encryptedContentKeyBase64), [Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)
        if ($contentKey.Length -ne 32) { Stop-Safe 'operator_recovery_content_key_invalid' }
        $ciphertext = [Convert]::FromBase64String($envelope.ciphertextBase64)
        $tag = [Convert]::FromBase64String($envelope.tagBase64)
        $iv = [Convert]::FromBase64String($envelope.ivBase64)
        $aad = [Text.Encoding]::ASCII.GetBytes("beta-backup-recovery-envelope/v1`n$($Request.checkpointId)")
        $plaintext = New-Object byte[] $ciphertext.Length
        $aes = [Security.Cryptography.AesGcm]::new($contentKey, 16)
        try { $aes.Decrypt($iv, $ciphertext, $tag, $plaintext, $aad) } finally { $aes.Dispose() }
        $material = [Text.Encoding]::UTF8.GetString($plaintext) | ConvertFrom-Json
        if ($material.schemaVersion -ne 'beta-backup-recovery-envelope/v1' -or $material.checkpointId -ne $Request.checkpointId -or
            $material.bundleKeyBase64 -notmatch '^[A-Za-z0-9+/]{43}=$' -or
            @('authSecret','bonusCodeVerifierSecret','googleClientId','googleClientSecret' | Where-Object {
                $value = [string]$material.runtimeSecrets.$_; $value.Length -lt 16
            }).Count -gt 0) { Stop-Safe 'operator_recovery_material_invalid' }
        $runtimeRsa = [Security.Cryptography.RSA]::Create()
        try {
            $runtimeRsa.ImportFromPem([string]$Request.ephemeralPublicKeyPem)
            $responseKey = New-Object byte[] 32
            $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
            try { $rng.GetBytes($responseKey) } finally { $rng.Dispose() }
            $iv = New-Object byte[] 12
            $rng2 = [Security.Cryptography.RandomNumberGenerator]::Create()
            try { $rng2.GetBytes($iv) } finally { $rng2.Dispose() }
            $responseCiphertext = New-Object byte[] $plaintext.Length
            $responseTag = New-Object byte[] 16
            $responseAad = [Text.Encoding]::ASCII.GetBytes("beta-backup-host-recovery-response/v1`n$($Request.checkpointId)")
            $responseAes = [Security.Cryptography.AesGcm]::new($responseKey, 16)
            try { $responseAes.Encrypt($iv, $plaintext, $responseCiphertext, $responseTag, $responseAad) } finally { $responseAes.Dispose() }
            $response = [ordered]@{ schemaVersion = 'beta-backup-host-recovery-response/v1'; checkpointId = $Request.checkpointId;
                encryptedContentKeyBase64 = [Convert]::ToBase64String($runtimeRsa.Encrypt($responseKey, [Security.Cryptography.RSAEncryptionPadding]::OaepSHA256));
                ivBase64 = [Convert]::ToBase64String($iv); ciphertextBase64 = [Convert]::ToBase64String($responseCiphertext);
                tagBase64 = [Convert]::ToBase64String($responseTag) }
            $responsePath = Join-Path $JobDirectory 'recovered-material.enc'
            Write-NewBytes $responsePath ([Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject $response -Compress) + "`n"))
            return @{ recoveryResponseBytes = (Get-Item -LiteralPath $responsePath).Length }
        } finally { $runtimeRsa.Dispose() }
    } catch {
        if ($_.Exception.Message -match '^bpc_[a-z_]+$') { throw }
        Stop-Safe 'operator_recovery_failed'
    } finally {
        if ($pkcs8) { [Array]::Clear($pkcs8,0,$pkcs8.Length) }
        if ($wrappedPrivate) { [Array]::Clear($wrappedPrivate,0,$wrappedPrivate.Length) }
        if ($contentKey) { [Array]::Clear($contentKey,0,$contentKey.Length) }
        if ($plaintext) { [Array]::Clear($plaintext,0,$plaintext.Length) }
        if ($responseKey) { [Array]::Clear($responseKey,0,$responseKey.Length) }
        if ($operatorRsa) { $operatorRsa.Dispose() }
    }
}
function Invoke-Request($Request, [string]$JobDirectory) {
    switch ($Request.kind) {
        'pg_dump' { return Invoke-PgDump $Request.jobId $Request.databaseName $JobDirectory }
        'database_exists' { return @{ databaseName = $Request.databaseName; exists = (Test-DatabaseExists $Request.databaseName) } }
        'create_restore_database' { return Invoke-CreateRestoreDatabase $Request.databaseName $Request.checkpointId $Request.jobId }
        'pg_restore' { return Invoke-PgRestore $Request.jobId $Request.databaseName $JobDirectory $Request.dumpSha256 $Request.checkpointId $Request.creationJobId }
        'recover_material' { return Invoke-RecoverMaterial $Request $JobDirectory }
        default { Stop-Safe 'job_kind_invalid' }
    }
}
function Process-OneJob([string]$Directory) {
    Assert-NoReparsePath $Directory | Out-Null
    $directoryItem = Get-Item -LiteralPath $Directory -Force
    if (($directoryItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or $directoryItem.Name -notmatch '^[a-f0-9]{32}$') { Stop-Safe 'job_directory_invalid' }
    $requestPath = Join-Path $Directory 'request.json'
    $resultPath = Join-Path $Directory 'result.json'
    if (-not [IO.File]::Exists($requestPath) -or [IO.File]::Exists($resultPath)) { return $false }
    $startedPath = Join-Path $Directory 'started.json'
    try { Write-NewBytes $startedPath ([Text.Encoding]::UTF8.GetBytes("`n")) }
    catch {
        try { Write-Result $Directory $directoryItem.Name 'unknown' @{ status = 'failed'; errorCode = 'job_already_started' } }
        catch { Write-SafeJobFailureLog $directoryItem.Name 'unknown'; return $true }
        Write-SafeJobFailureLog $directoryItem.Name 'unknown'
        return $true
    }
    $kind = 'unknown'
    try {
        $request = Get-Content -LiteralPath $requestPath -Raw | ConvertFrom-Json
        $kind = [string]$request.kind
        Assert-JobRequest $request $Directory $directoryItem.Name
        $fields = Invoke-Request $request $Directory
        Write-Result $Directory $directoryItem.Name $kind $fields
    } catch {
        $code = Get-SafeJobErrorCode $_
        try { Write-Result $Directory $directoryItem.Name $kind @{ status = 'failed'; errorCode = $code } }
        catch { Write-SafeJobFailureLog $directoryItem.Name $kind; return $true }
        Write-SafeJobFailureLog $directoryItem.Name $kind
    }
    return $true
}

if ($InitializeRecoveryKey) {
    if (-not (Test-Absolute $BackupRoot) -or -not (Test-Absolute $RecoveryPrivateKeyPath) -or -not (Test-Absolute $RecoveryPublicKeyPath)) { Stop-Safe 'recovery_key_paths_must_be_absolute' }
    $script:BackupFull = [IO.Path]::GetFullPath($BackupRoot)
    $script:RecoveryPrivateFull = [IO.Path]::GetFullPath($RecoveryPrivateKeyPath)
    $publicFull = [IO.Path]::GetFullPath($RecoveryPublicKeyPath)
    $operatorRoot = Join-Path $script:BackupFull 'operator'
    Assert-NoReparsePath $script:BackupFull -AllowMissingFinal | Out-Null
    if (-not [IO.Directory]::Exists($script:BackupFull)) { [void][IO.Directory]::CreateDirectory($script:BackupFull) }
    Assert-NoReparsePath $operatorRoot -AllowMissingFinal | Out-Null
    if (-not [IO.Directory]::Exists($operatorRoot)) { [void][IO.Directory]::CreateDirectory($operatorRoot) }
    if (-not (Get-ContainedPath $operatorRoot $script:RecoveryPrivateFull) -or -not (Get-ContainedPath $operatorRoot $publicFull)) { Stop-Safe 'recovery_key_path_invalid' }
    if ([IO.File]::Exists($script:RecoveryPrivateFull) -or [IO.File]::Exists($publicFull)) { Stop-Safe 'recovery_key_already_initialized' }
    Add-Type -AssemblyName System.Security
    $rsa = [Security.Cryptography.RSA]::Create(3072)
    $privateBytes = $rsa.ExportPkcs8PrivateKey()
    $entropy = [Text.Encoding]::UTF8.GetBytes('BPC-SC022-OPERATOR-RECOVERY-KEY/v1')
    $protected = $null
    try {
        $protected = [Security.Cryptography.ProtectedData]::Protect($privateBytes, $entropy, [Security.Cryptography.DataProtectionScope]::CurrentUser)
        Write-NewBytes $script:RecoveryPrivateFull $protected
        Write-NewBytes $publicFull ([Text.Encoding]::ASCII.GetBytes($rsa.ExportSubjectPublicKeyInfoPem()))
    } finally {
        [Array]::Clear($privateBytes,0,$privateBytes.Length)
        if ($protected) { [Array]::Clear($protected,0,$protected.Length) }
        $rsa.Dispose()
    }
    [Console]::Out.WriteLine((ConvertTo-Json -Compress ([ordered]@{ status = 'recovery_key_initialized'; publicKeyPath = $publicFull; privateKeyRecovery = 'dpapi_current_user_external' })))
    exit 0
}

if ($RunJobBroker) {
    if (-not (Test-Absolute $JobRoot) -or -not (Test-Absolute $BackupRoot) -or -not (Test-Absolute $ComposeFile) -or
        -not (Test-Absolute $RecoveryPrivateKeyPath)) { Stop-Safe 'host_paths_must_be_absolute' }
    $script:JobRootFull = Assert-NoReparsePath $JobRoot -AllowMissingFinal
    $script:BackupFull = Assert-NoReparsePath $BackupRoot
    $script:ComposeFull = Assert-NoReparsePath $ComposeFile
    $script:RecoveryPrivateFull = Assert-NoReparsePath $RecoveryPrivateKeyPath
    if (-not [IO.Directory]::Exists($script:JobRootFull)) { [void][IO.Directory]::CreateDirectory($script:JobRootFull) }
    Assert-NoReparsePath $script:JobRootFull | Out-Null
    if (-not [IO.Directory]::Exists($script:BackupFull) -or -not [IO.File]::Exists($script:ComposeFull)) { Stop-Safe 'host_root_missing' }
    do {
        $processed = $false
        foreach ($job in Get-ChildItem -LiteralPath $script:JobRootFull -Directory -Recurse -Depth 2 -Force) {
            if ($job.Name -notmatch '^[a-f0-9]{32}$' -or -not [IO.File]::Exists((Join-Path $job.FullName 'request.json'))) { continue }
            try { if (Process-OneJob $job.FullName) { $processed = $true; if ($Once) { break } } }
            catch {
                $jobId = [string]$job.Name
                $kind = 'unknown'
                $code = 'job_worker_failure'
                if ($jobId -match '^[a-f0-9]{32}$') {
                    try {
                        $request = Get-Content -LiteralPath (Join-Path $job.FullName 'request.json') -Raw | ConvertFrom-Json
                        if ($request.kind -in @('pg_dump','database_exists','create_restore_database','pg_restore','recover_material')) { $kind = [string]$request.kind }
                    } catch { }
                    $code = Get-SafeJobErrorCode $_
                    if (-not [IO.File]::Exists((Join-Path $job.FullName 'result.json'))) {
                        try { Write-Result $job.FullName $jobId $kind @{ status = 'failed'; errorCode = $code } } catch { }
                    }
                    Write-SafeJobFailureLog $jobId $kind
                }
            }
        }
        if ($Once) { break }
        Start-Sleep -Milliseconds 250
    } while ($true)
    exit 0
}

Stop-Safe 'select_initialize_or_run_job_broker'
