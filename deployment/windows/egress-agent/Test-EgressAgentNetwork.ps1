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
$TaskName = 'RemoteCodex-EgressAgent'

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
$hostCli = Join-Path $release 'egress-agent-host\dist\cli-main.js'
$node = (Get-Command 'node.exe' -CommandType Application -ErrorAction Stop).Source

& $node $opsCli 'deployment' 'validate' '--root' $config '--manifest' $Manifest | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw 'AGENT_NETWORK_DEPLOYMENT_INVALID'
}

$manifestPath = Join-Path $config $Manifest
$manifestDocument = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
if ($manifestDocument.component -ne 'egress-agent' -or $manifestDocument.configPath -notmatch '^[A-Za-z0-9][A-Za-z0-9._/-]{0,255}$' -or $manifestDocument.configPath -match '(^|/)\.\.(/|$)') {
    throw 'AGENT_NETWORK_MANIFEST_INVALID'
}
$configPath = Join-Path $config $manifestDocument.configPath
$configuration = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
$serverUri = [Uri]$configuration.serverUrl
if ($serverUri.Scheme -ne 'wss' -or $serverUri.Port -lt 1 -or $serverUri.Port -gt 65535) {
    throw 'AGENT_NETWORK_SERVER_URL_INVALID'
}

$serverAddresses = Resolve-ApprovedAddresses -Hostname $serverUri.DnsSafeHost
$gatewayAddresses = Resolve-ApprovedAddresses -Hostname $configuration.allowedDestination.hostname
$task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$taskOwned = $null -ne $task -and @($identity.Name, $identity.User.Value) -contains $task.Principal.UserId
$taskRunning = $taskOwned -and $task.State -eq 'Running'
$taskInfo = if ($taskOwned) { Get-ScheduledTaskInfo -TaskName $TaskName } else { $null }
$processes = @(
    Get-CimInstance Win32_Process -Filter "Name = 'node.exe'" |
        Where-Object { $null -ne $_.CommandLine -and $_.CommandLine.IndexOf($hostCli, [StringComparison]::OrdinalIgnoreCase) -ge 0 }
)

$listeningCount = 0
$wssConnectionCount = 0
$gatewayConnectionCount = 0
$unexpectedConnectionCount = 0
$pendingConnectionCount = 0
$staleConnectionCount = 0
foreach ($process in $processes) {
    $connections = @(Get-NetTCPConnection -OwningProcess $process.ProcessId -ErrorAction SilentlyContinue)
    foreach ($connection in $connections) {
        if ($connection.State -eq 'Listen') {
            $listeningCount += 1
            continue
        }
        if ($connection.RemotePort -eq 0) {
            continue
        }
        $approvedServer = $connection.RemotePort -eq $serverUri.Port -and $serverAddresses -contains $connection.RemoteAddress
        $approvedGateway = $connection.RemotePort -eq 443 -and $gatewayAddresses -contains $connection.RemoteAddress
        if (-not $approvedServer -and -not $approvedGateway) {
            $unexpectedConnectionCount += 1
            continue
        }
        if ($approvedServer) {
            if ($connection.State -eq 'Established') {
                $wssConnectionCount += 1
            } elseif ($connection.State -eq 'SynSent' -or $connection.State -eq 'SynReceived') {
                $pendingConnectionCount += 1
            } else {
                $staleConnectionCount += 1
            }
            continue
        }
        if ($approvedGateway) {
            if ($connection.State -eq 'Established') {
                $gatewayConnectionCount += 1
            } elseif ($connection.State -eq 'SynSent' -or $connection.State -eq 'SynReceived') {
                $pendingConnectionCount += 1
            } else {
                $staleConnectionCount += 1
            }
            continue
        }
    }
}

$ok = `
    $taskOwned -and `
    $taskRunning -and `
    $processes.Count -eq 1 -and `
    $wssConnectionCount -eq 1 -and `
    $listeningCount -eq 0 -and `
    $staleConnectionCount -eq 0 -and `
    $unexpectedConnectionCount -eq 0
[pscustomobject]@{
    ok = $ok
    taskInstalled = $null -ne $task
    taskOwned = $taskOwned
    taskRunning = $taskRunning
    taskState = if ($null -eq $task) { 'NotInstalled' } else { [string]$task.State }
    lastTaskResult = if ($null -eq $taskInfo) { $null } else { $taskInfo.LastTaskResult }
    processCount = $processes.Count
    listeningSocketCount = $listeningCount
    wssConnectionCount = $wssConnectionCount
    gatewayConnectionCount = $gatewayConnectionCount
    pendingConnectionCount = $pendingConnectionCount
    staleConnectionCount = $staleConnectionCount
    unexpectedConnectionCount = $unexpectedConnectionCount
} | ConvertTo-Json -Compress

if (-not $ok) {
    exit 1
}
