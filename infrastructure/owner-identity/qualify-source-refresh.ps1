param(
  [switch]$Execute,
  [string]$ApplicationSha256,
  [string]$ProbeSha256,
  [string]$ManifestSha256,
  [ValidateRange(1,65535)][int]$ObserverPort = 55432
)
$ErrorActionPreference = 'Stop'
$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
if ([System.IO.Path]::GetFullPath((Get-Location).Path) -ne $repoRoot) { throw 'Run from the repository root' }
$befCompose = @('compose','-f','infrastructure/benchmark-environment/compose.yaml')
$toolCompose = @('compose','-f','infrastructure/owner-identity/compose.yaml','--profile','tools','run','--rm','--no-deps',
  '-e','BEF_API_HOST_PORT=38783','-e',"BEF_DATABASE_OBSERVER_HOST_PORT=$ObserverPort",'-e','BEF_SOURCE_PROXY_HOST_PORT=18544',
  'runtime','node','--import','./packages/owner-identity/node_modules/tsx/dist/loader.mjs','infrastructure/owner-identity/qualify-source-refresh.mjs')
if (-not $Execute) {
  # Plan only: no Docker command, source write, service restart or release-pointer change.
  [ordered]@{ schemaVersion='bts-source-refresh-host-plan/v1'; execute=$false;
    preflight=@('docker')+$toolCompose+@('--plan');
    build=@('docker')+$befCompose+@('build','api');
    restart=@('docker')+$befCompose+@('up','-d','--no-deps','--force-recreate','api','gateway');
    qualification=@('docker')+$toolCompose+@('--execute','--application-sha256','<frozen-app-sha256>',
      '--probe-sha256','<frozen-probe-sha256>','--manifest-sha256','<frozen-manifest-sha256>');
    preserved=@('source-proxy process and quota','postgres volume','Anvil instances','current release pointers');
    prerequisite='Root confirms no shared executor or active generation; source frozen; explicit GO' } | ConvertTo-Json -Depth 8
  return
}
foreach ($digest in @($ApplicationSha256,$ProbeSha256,$ManifestSha256)) {
  if ($digest -cnotmatch '^[0-9a-f]{64}$') { throw 'Execute requires all three exact frozen SHA-256 pins' }
}
$settings = @{ BEF_API_HOST_PORT='38783';BEF_DATABASE_HOST_PORT=[string]$ObserverPort;BEF_LOCAL_RPC_A_HOST_PORT='18545';
  BEF_LOCAL_RPC_B_HOST_PORT='28545';BEF_FACILITATOR_A_HOST_PORT='34021';BEF_FACILITATOR_B_HOST_PORT='44021';BEF_SOURCE_PROXY_HOST_PORT='18544' }
$previous = @{}
try {
  foreach ($key in $settings.Keys) { $previous[$key] = [Environment]::GetEnvironmentVariable($key,'Process'); [Environment]::SetEnvironmentVariable($key,$settings[$key],'Process') }
  # Only the API changed. Preserve the source proxy's cumulative quota and the existing
  # database/fork/cache state; each reference creates and fences its own fresh generation.
  & docker @befCompose build api
  if ($LASTEXITCODE -ne 0) { throw 'BEF API image build failed' }
  & docker @befCompose up -d --no-deps --force-recreate api gateway
  if ($LASTEXITCODE -ne 0) { throw 'BEF API/gateway recreation failed' }
  $ready = $false
  for ($attempt=0; $attempt -lt 90; $attempt++) {
    try { $health = Invoke-RestMethod -Uri 'http://127.0.0.1:38783/healthz' -TimeoutSec 2
      if ($health.status -eq 'ready' -and $health.manifestSha256 -eq $ManifestSha256 -and $health.applicationSourceSha256 -eq $ApplicationSha256) { $ready=$true;break } } catch {}
    Start-Sleep -Seconds 1
  }
  if (-not $ready) { throw 'New API did not confirm the frozen manifest/application source pins' }
  & docker @toolCompose --execute --application-sha256 $ApplicationSha256 --probe-sha256 $ProbeSha256 --manifest-sha256 $ManifestSha256
  if ($LASTEXITCODE -ne 0) { throw 'Fresh source qualification blocked; inspect its new qualification.json; pointers were not promoted' }
} finally {
  foreach ($key in $settings.Keys) { [Environment]::SetEnvironmentVariable($key,$previous[$key],'Process') }
}
