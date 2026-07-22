[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProcessName = 'remote-codex-edge-client'

if ($env:OS -ne 'Windows_NT') {
    throw 'EDGE_PM2_WINDOWS_REQUIRED'
}

$pm2 = (Get-Command 'pm2.cmd' -CommandType Application -ErrorAction Stop).Source
& $pm2 'stop' $ProcessName
if ($LASTEXITCODE -ne 0) {
    throw 'EDGE_PM2_STOP_FAILED'
}

[pscustomobject]@{
    ok = $true
    event = 'edge_pm2_stop_requested'
    processName = $ProcessName
} | ConvertTo-Json -Compress
