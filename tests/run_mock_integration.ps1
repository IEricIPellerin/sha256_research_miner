#tests\run_mock_integration.ps1
param(
  [Parameter(Mandatory=$true)][string]$Miner,
  [Parameter(Mandatory=$true)][string]$Server,
  [Parameter(Mandatory=$true)][string]$ProjectRoot
)
$ErrorActionPreference = 'Stop'
$testRoot = Join-Path ([IO.Path]::GetTempPath()) ("srm_mock_integration_" + [Guid]::NewGuid().ToString('N'))
$testConfigDirectory = Join-Path $testRoot 'config'
$testStateDirectory = Join-Path $testRoot 'state'
$testResultsDirectory = Join-Path $testRoot 'results'
[IO.Directory]::CreateDirectory($testConfigDirectory) | Out-Null
[IO.Directory]::CreateDirectory($testStateDirectory) | Out-Null
[IO.Directory]::CreateDirectory($testResultsDirectory) | Out-Null
$configuration = Get-Content -LiteralPath (Join-Path $ProjectRoot 'config\mock.json') -Raw | ConvertFrom-Json
$configuration.logging.directory = 'results'
$testConfig = Join-Path $testConfigDirectory 'mock.json'
[IO.File]::WriteAllText(
  $testConfig,
  ($configuration | ConvertTo-Json -Depth 10),
  [Text.UTF8Encoding]::new($false))

$checkpointTemporary = Join-Path $testStateDirectory 'mock_state.json.tmp'
$checkpointLock = [IO.File]::Open(
  $checkpointTemporary,
  [IO.FileMode]::OpenOrCreate,
  [IO.FileAccess]::ReadWrite,
  [IO.FileShare]::None)
$serverProcess = Start-Process -FilePath $Server -ArgumentList '3334' -WorkingDirectory $ProjectRoot -PassThru -WindowStyle Hidden
try {
  Start-Sleep -Milliseconds 300
  $minerProcess = Start-Process -FilePath $Miner -ArgumentList '--config',$testConfig -WorkingDirectory $ProjectRoot -PassThru -WindowStyle Hidden
  try {
    if (-not $serverProcess.WaitForExit(15000)) { throw 'mock server did not receive two submissions within 15 seconds' }
    if ($serverProcess.ExitCode -ne 0) { throw "mock server exited with $($serverProcess.ExitCode)" }
    $deadline = [DateTime]::UtcNow.AddSeconds(3)
    $acceptedAudits = @()
    $rejectedAudits = @()
    do {
      Start-Sleep -Milliseconds 100
      $audits = @(Get-ChildItem -LiteralPath $testResultsDirectory -Filter 'share_audit_*.json' -ErrorAction SilentlyContinue |
        ForEach-Object {
          try { Get-Content -LiteralPath $_.FullName -Raw | ConvertFrom-Json } catch { $null }
        })
      $acceptedAudits = @($audits | Where-Object {
        $_.submission.status -eq 'accepted' -and
          $_.submission.nonce -eq $_.nonce.stratum_hex
      })
      $rejectedAudits = @($audits | Where-Object {
        $_.submission.status -eq 'rejected' -and
          $_.submission.server_response.error[1] -eq 'Mock rejection' -and
          $_.submission.nonce -eq $_.nonce.stratum_hex
      })
    } while (($acceptedAudits.Count -lt 1 -or $rejectedAudits.Count -lt 1) -and
      [DateTime]::UtcNow -lt $deadline)
    if ($acceptedAudits.Count -lt 1 -or $rejectedAudits.Count -lt 1) {
      throw "mock integration did not durably update the accepted and rejected share audits"
    }
    $strictUtf8 = [Text.UTF8Encoding]::new($false, $true)
    $sessionText = ((Get-ChildItem -LiteralPath $testResultsDirectory -Filter 'session_*.log') |
      ForEach-Object {
        $bytes = [IO.File]::ReadAllBytes($_.FullName)
        try {
          $strictUtf8.GetString($bytes)
        } catch {
          $legacyText = [Text.Encoding]::GetEncoding(1252).GetString($bytes)
          throw "session log is not UTF-8; decoded tail: $($legacyText.Substring([Math]::Max(0, $legacyText.Length - 500)))"
        }
      }) -join "`n"
    if ($sessionText -notmatch 'sauvegarde au lancement du job impossible') {
      throw 'simulated checkpoint failure was not logged while Stratum stayed connected'
    }
  } finally {
    if (-not $minerProcess.HasExited) { $minerProcess.Kill(); $minerProcess.WaitForExit() }
  }
} finally {
  if (-not $serverProcess.HasExited) { $serverProcess.Kill(); $serverProcess.WaitForExit() }
  $checkpointLock.Dispose()
  if ([IO.Directory]::Exists($testRoot)) { [IO.Directory]::Delete($testRoot, $true) }
}
