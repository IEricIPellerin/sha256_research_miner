param(
  [Parameter(Mandatory=$true)][string]$Miner,
  [Parameter(Mandatory=$true)][string]$Server,
  [Parameter(Mandatory=$true)][string]$ProjectRoot
)
$ErrorActionPreference = 'Stop'
$serverProcess = Start-Process -FilePath $Server -ArgumentList '3334' -WorkingDirectory $ProjectRoot -PassThru -WindowStyle Hidden
try {
  Start-Sleep -Milliseconds 300
  $minerProcess = Start-Process -FilePath $Miner -ArgumentList '--config','config/mock.json' -WorkingDirectory $ProjectRoot -PassThru -WindowStyle Hidden
  try {
    if (-not $serverProcess.WaitForExit(15000)) { throw 'mock server did not receive two submissions within 15 seconds' }
    if ($serverProcess.ExitCode -ne 0) { throw "mock server exited with $($serverProcess.ExitCode)" }
    Start-Sleep -Milliseconds 500
  } finally {
    if (-not $minerProcess.HasExited) { $minerProcess.Kill(); $minerProcess.WaitForExit() }
  }
} finally {
  if (-not $serverProcess.HasExited) { $serverProcess.Kill(); $serverProcess.WaitForExit() }
}
