[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ReleaseRoot,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ConfigRoot,

    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$')]
    [string]$Manifest = 'manifest.json'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProcessName = 'remote-codex-edge-client'
$TaskName = 'RemoteCodex-EdgeClient'

function Resolve-LocalDirectory {
    param([Parameter(Mandatory = $true)][string]$Path)

    $resolved = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
    if (-not [System.IO.Path]::IsPathRooted($resolved) -or $resolved.StartsWith('\\')) {
        throw 'EDGE_PM2_LOCAL_PATH_REQUIRED'
    }
    if (-not (Test-Path -LiteralPath $resolved -PathType Container)) {
        throw 'EDGE_PM2_DIRECTORY_REQUIRED'
    }
    return $resolved.TrimEnd('\')
}

if ($env:OS -ne 'Windows_NT') {
    throw 'EDGE_PM2_WINDOWS_REQUIRED'
}

$release = Resolve-LocalDirectory -Path $ReleaseRoot
$config = Resolve-LocalDirectory -Path $ConfigRoot
$hostCli = Join-Path $release 'edge-client-host\dist\cli-main.js'
$opsCli = Join-Path $release 'ops\dist\cli-main.js'
if (-not (Test-Path -LiteralPath $hostCli -PathType Leaf) -or -not (Test-Path -LiteralPath $opsCli -PathType Leaf)) {
    throw 'EDGE_PM2_RELEASE_INCOMPLETE'
}

$task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($null -ne $task -and $task.State -eq 'Running') {
    throw 'EDGE_PM2_TASK_RUNNING'
}

$node = (Get-Command 'node.exe' -CommandType Application -ErrorAction Stop).Source
$pm2 = (Get-Command 'pm2.cmd' -CommandType Application -ErrorAction Stop).Source

& $node $opsCli 'deployment' 'validate' '--root' $config '--manifest' $Manifest
if ($LASTEXITCODE -ne 0) {
    throw 'EDGE_PM2_DEPLOYMENT_INVALID'
}

& $pm2 'start' $hostCli '--name' $ProcessName '--cwd' $release '--interpreter' $node '--' '--root' $config '--manifest' $Manifest
if ($LASTEXITCODE -ne 0) {
    throw 'EDGE_PM2_START_FAILED'
}

[pscustomobject]@{
    ok = $true
    event = 'edge_pm2_start_requested'
    processName = $ProcessName
} | ConvertTo-Json -Compress
