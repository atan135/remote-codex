[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProcessName = 'remote-codex-edge-client'

if ($env:OS -ne 'Windows_NT') {
    throw 'EDGE_PM2_WINDOWS_REQUIRED'
}

$pm2 = (Get-Command 'pm2.cmd' -CommandType Application -ErrorAction Stop).Source
& $pm2 'restart' $ProcessName
if ($LASTEXITCODE -ne 0) {
    throw 'EDGE_PM2_RESTART_FAILED'
}

[pscustomobject]@{
    ok = $true
    event = 'edge_pm2_restart_requested'
    processName = $ProcessName
} | ConvertTo-Json -Compress
