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
$TaskName = 'RemoteCodex-EdgeClient'

function Resolve-ApprovedAddresses {
    param([Parameter(Mandatory = $true)][string]$Hostname)

    return @(
        Resolve-DnsName -Name $Hostname -Type A_AAAA -DnsOnly -ErrorAction Stop |
            Where-Object { $_.Type -eq 'A' -or $_.Type -eq 'AAAA' } |
            ForEach-Object { $_.IPAddress }
    )
}

$release = (Resolve-Path -LiteralPath $ReleaseRoot -ErrorAction Stop).Path.TrimEnd('\')
$config = (Resolve-Path -LiteralPath $ConfigRoot -ErrorAction Stop).Path.TrimEnd('\')
$opsCli = Join-Path $release 'ops\dist\cli-main.js'
$hostCli = Join-Path $release 'edge-client-host\dist\cli-main.js'
$node = (Get-Command 'node.exe' -CommandType Application -ErrorAction Stop).Source

& $node $opsCli 'deployment' 'validate' '--root' $config '--manifest' $Manifest | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw 'EDGE_STATUS_DEPLOYMENT_INVALID'
}

$manifestPath = Join-Path $config $Manifest
$manifestDocument = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
if ($manifestDocument.component -ne 'edge-client' -or $manifestDocument.configPath -notmatch '^[A-Za-z0-9][A-Za-z0-9._/-]{0,255}$' -or $manifestDocument.configPath -match '(^|/)\.\.(/|$)') {
    throw 'EDGE_STATUS_MANIFEST_INVALID'
}
$configPath = Join-Path $config $manifestDocument.configPath
$configuration = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
$serverUri = [Uri]$configuration.serverUrl
if (
    $serverUri.Scheme -ne 'wss' -or
    $serverUri.Port -lt 8000 -or
    $serverUri.Port -gt 9000 -or
    $configuration.listenHost -ne '127.0.0.1' -or
    $configuration.listenPort -lt 8000 -or
    $configuration.listenPort -gt 9000
) {
    throw 'EDGE_STATUS_NETWORK_POLICY_INVALID'
}

$serverAddresses = Resolve-ApprovedAddresses -Hostname $serverUri.DnsSafeHost
$task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$taskOwned = $null -ne $task -and @($identity.Name, $identity.User.Value) -contains $task.Principal.UserId
$taskRunning = $taskOwned -and $task.State -eq 'Running'
$taskInfo = if ($taskOwned) { Get-ScheduledTaskInfo -TaskName $TaskName } else { $null }
$processes = @(
    Get-CimInstance Win32_Process -Filter "Name = 'node.exe'" |
        Where-Object { $null -ne $_.CommandLine -and $_.CommandLine.IndexOf($hostCli, [StringComparison]::OrdinalIgnoreCase) -ge 0 }
)

$approvedListenerCount = 0
$unexpectedListenerCount = 0
$wssConnectionCount = 0
$localClientConnectionCount = 0
$unexpectedConnectionCount = 0
$serverPendingConnectionCount = 0
$localPendingConnectionCount = 0
$staleConnectionCount = 0
foreach ($process in $processes) {
    $connections = @(Get-NetTCPConnection -OwningProcess $process.ProcessId -ErrorAction SilentlyContinue)
    foreach ($connection in $connections) {
        if ($connection.State -eq 'Listen') {
            if ($connection.LocalAddress -eq '127.0.0.1' -and $connection.LocalPort -eq $configuration.listenPort) {
                $approvedListenerCount += 1
            } else {
                $unexpectedListenerCount += 1
            }
            continue
        }
        if ($connection.RemotePort -eq 0) {
            continue
        }
        $approvedServer = $connection.RemotePort -eq $serverUri.Port -and $serverAddresses -contains $connection.RemoteAddress
        $localClient = `
            $connection.LocalAddress -eq '127.0.0.1' -and `
            $connection.LocalPort -eq $configuration.listenPort -and `
            $connection.RemoteAddress -eq '127.0.0.1'
        if (-not $approvedServer -and -not $localClient) {
            $unexpectedConnectionCount += 1
            continue
        }
        if ($approvedServer) {
            if ($connection.State -eq 'Established') {
                $wssConnectionCount += 1
            } elseif ($connection.State -eq 'SynSent' -or $connection.State -eq 'SynReceived') {
                $serverPendingConnectionCount += 1
            } else {
                $staleConnectionCount += 1
            }
            continue
        }
        if ($localClient) {
            if ($connection.State -eq 'Established') {
                $localClientConnectionCount += 1
            } elseif ($connection.State -eq 'SynSent' -or $connection.State -eq 'SynReceived') {
                $localPendingConnectionCount += 1
            } else {
                $staleConnectionCount += 1
            }
        }
    }
}

$ok = `
    $taskOwned -and `
    $taskRunning -and `
    $processes.Count -eq 1 -and `
    $wssConnectionCount -eq 1 -and `
    $serverPendingConnectionCount -eq 0 -and `
    $approvedListenerCount -eq 1 -and `
    $unexpectedListenerCount -eq 0 -and `
    $unexpectedConnectionCount -eq 0 -and `
    $staleConnectionCount -eq 0
[pscustomobject]@{
    ok = $ok
    taskInstalled = $null -ne $task
    taskOwned = $taskOwned
    taskRunning = $taskRunning
    taskState = if ($null -eq $task) { 'NotInstalled' } else { [string]$task.State }
    lastTaskResult = if ($null -eq $taskInfo) { $null } else { $taskInfo.LastTaskResult }
    processCount = $processes.Count
    approvedListenerCount = $approvedListenerCount
    unexpectedListenerCount = $unexpectedListenerCount
    wssConnectionCount = $wssConnectionCount
    localClientConnectionCount = $localClientConnectionCount
    serverPendingConnectionCount = $serverPendingConnectionCount
    localPendingConnectionCount = $localPendingConnectionCount
    staleConnectionCount = $staleConnectionCount
    unexpectedConnectionCount = $unexpectedConnectionCount
} | ConvertTo-Json -Compress

if (-not $ok) {
    exit 1
}
