param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^oid_acceptance_[a-f0-9]{32}$')]
    [string]$SourceDatabase
)
$ErrorActionPreference = 'Stop'
$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$composePath = Join-Path $PSScriptRoot 'compose.yaml'
$checkpointId = [Guid]::NewGuid().ToString('N')
$restoreDatabase = "oid_restore_$checkpointId"
$containerDump = "/tmp/oid-restore-$checkpointId.dump"
$bundleDirectory = Join-Path $repositoryRoot ".local/owner-identity/restore-rehearsals/$checkpointId"

function Invoke-Pg([string]$Database, [string]$Query) {
    $result = & docker compose -f $composePath exec -T postgres psql -U oid_owner -d $Database -X -A -t -v ON_ERROR_STOP=1 -c $Query
    if ($LASTEXITCODE -ne 0) { throw 'Local restore PostgreSQL query failed' }
    return ($result -join "`n").Trim()
}

function Read-TableFingerprints([string]$Database) {
    $tableNames = Invoke-Pg $Database "SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename"
    $fingerprints = @()
    foreach ($tableName in ($tableNames -split "`n")) {
        if ($tableName -notmatch '^[A-Za-z_][A-Za-z0-9_]*$') { throw 'Unexpected local table name' }
        $count = [long](Invoke-Pg $Database "SELECT count(*) FROM public.$tableName")
        if ($count -gt 100000) { throw 'Local fixture exceeds bounded rehearsal size' }
        # AICODE-NOTE: Hash full rows inside PostgreSQL; never export auth, verifier or user rows as diagnostic text.
        $fingerprintSql = @'
SELECT encode(sha256(convert_to(coalesce(string_agg(row_text, E'\n' ORDER BY row_text COLLATE "C"),''),'UTF8')),'hex')
FROM (SELECT row_to_json(t)::text AS row_text FROM public.{0} t) rows
'@ -f $tableName
        $digest = Invoke-Pg $Database $fingerprintSql
        if ($digest -notmatch '^[a-f0-9]{64}$') { throw 'Invalid local table fingerprint' }
        $fingerprints += [ordered]@{ table = $tableName; rows = $count; sha256 = $digest }
    }
    return $fingerprints
}

# This deliberately cannot target the primary DB or claim screenshot/retention/worker recovery acceptance.
# A unique restore DB and private dump are retained for inspection; no source rows are changed or removed.
$startedAt = [DateTime]::UtcNow
$imageCount = [long](Invoke-Pg $SourceDatabase 'SELECT count(*) FROM oid_support_image_upload')
$reportCount = [long](Invoke-Pg $SourceDatabase 'SELECT count(*) FROM oid_support_report')
if ($imageCount -ne 0 -or $reportCount -ne 0) { throw 'Use the full report-aware backup path for a DB containing reports or uploads' }
$before = @(Read-TableFingerprints $SourceDatabase)
New-Item -ItemType Directory -Path $bundleDirectory | Out-Null
& docker compose -f $composePath exec -T postgres pg_dump -U oid_owner -d $SourceDatabase -Fc --no-owner --no-acl -f $containerDump
if ($LASTEXITCODE -ne 0) { throw 'Local database dump failed' }
$containerId = (& docker compose -f $composePath ps -q postgres).Trim()
if ($containerId -notmatch '^[a-f0-9]{12,64}$') { throw 'Cannot identify the PostgreSQL container' }
$dumpPath = Join-Path $bundleDirectory 'database.dump'
& docker cp "${containerId}:$containerDump" $dumpPath
if ($LASTEXITCODE -ne 0) { throw 'Private dump copy failed' }
& docker compose -f $composePath exec -T postgres createdb -U oid_owner -T template0 $restoreDatabase
if ($LASTEXITCODE -ne 0) { throw 'Isolated restore database creation failed' }
& docker compose -f $composePath exec -T postgres pg_restore -U oid_owner -d $restoreDatabase --exit-on-error --no-owner --no-acl $containerDump
if ($LASTEXITCODE -ne 0) { throw 'Isolated restore failed' }
$after = @(Read-TableFingerprints $SourceDatabase)
$restored = @(Read-TableFingerprints $restoreDatabase)
$beforeJson = ConvertTo-Json -InputObject $before -Depth 8 -Compress
if ($beforeJson -cne (ConvertTo-Json -InputObject $after -Depth 8 -Compress)) { throw 'Source fixture changed during rehearsal; result is inconclusive' }
if ($beforeJson -cne (ConvertTo-Json -InputObject $restored -Depth 8 -Compress)) { throw 'Restored table rows differ from the source fixture' }
$result = [ordered]@{
    schemaVersion = 'bpc-local-bonus-restore-rehearsal/v1'
    checkpointId = $checkpointId
    boundary = 'isolated_local_postgresql_bonus_fixture'
    sourceDatabase = $SourceDatabase
    restoreDatabase = $restoreDatabase
    startedAt = $startedAt.ToString('o')
    finishedAt = [DateTime]::UtcNow.ToString('o')
    elapsedSeconds = ([DateTime]::UtcNow - $startedAt).TotalSeconds
    dumpSha256 = (Get-FileHash -LiteralPath $dumpPath -Algorithm SHA256).Hash.ToLowerInvariant()
    dumpBytes = (Get-Item -LiteralPath $dumpPath).Length
    tables = $restored
    sourceUnchanged = $true
    restoredRowsMatch = $true
    screenshotRestore = 'not_run'
    interruptedRunReconciliation = 'not_run'
    safeOperationRetry = 'not_run'
    betaGateStatus = 'blocked'
    writesMayBeEnabled = $false
}
$result | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $bundleDirectory 'rehearsal.json') -Encoding utf8
[ordered]@{ checkpointId = $checkpointId; restoredTableCount = $restored.Count; restoredRowsMatch = $true; betaGateStatus = 'blocked'; evidencePath = (Join-Path $bundleDirectory 'rehearsal.json') } | ConvertTo-Json
