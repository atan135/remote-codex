[CmdletBinding(SupportsShouldProcess = $true)]
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

function Test-TaskOwnedByCurrentUser {
    param([Parameter(Mandatory = $true)][string]$TaskUserId)

    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $acceptedIds = @($identity.Name, $identity.User.Value)
    $localUserName = $identity.Name.Substring($identity.Name.LastIndexOf('\') + 1)
    if ($localUserName -eq $env:USERNAME) {
        $acceptedIds += $env:USERNAME
    }
    return $acceptedIds -contains $TaskUserId
}

function Resolve-LocalDirectory {
    param([Parameter(Mandatory = $true)][string]$Path)

    $resolved = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
    if (-not [System.IO.Path]::IsPathRooted($resolved) -or $resolved.StartsWith('\\')) {
        throw 'EDGE_INSTALL_LOCAL_PATH_REQUIRED'
    }
    if (-not (Test-Path -LiteralPath $resolved -PathType Container)) {
        throw 'EDGE_INSTALL_DIRECTORY_REQUIRED'
    }
    return $resolved.TrimEnd('\')
}

if ($env:OS -ne 'Windows_NT') {
    throw 'EDGE_INSTALL_WINDOWS_REQUIRED'
}

$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principalCheck = [System.Security.Principal.WindowsPrincipal]::new($identity)
if ($identity.User.Value -eq 'S-1-5-18' -or $principalCheck.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'EDGE_INSTALL_NON_ADMIN_USER_REQUIRED'
}
$existingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($null -ne $existingTask -and -not (Test-TaskOwnedByCurrentUser -TaskUserId $existingTask.Principal.UserId)) {
    throw 'EDGE_TASK_OWNER_MISMATCH'
}

$release = Resolve-LocalDirectory -Path $ReleaseRoot
$config = Resolve-LocalDirectory -Path $ConfigRoot
$hostCli = Join-Path $release 'edge-client-host\dist\cli-main.js'
$opsCli = Join-Path $release 'ops\dist\cli-main.js'
if (-not (Test-Path -LiteralPath $hostCli -PathType Leaf) -or -not (Test-Path -LiteralPath $opsCli -PathType Leaf)) {
    throw 'EDGE_INSTALL_RELEASE_INCOMPLETE'
}

$node = (Get-Command 'node.exe' -CommandType Application -ErrorAction Stop).Source
& $node $opsCli 'deployment' 'validate' '--root' $config '--manifest' $Manifest
if ($LASTEXITCODE -ne 0) {
    throw 'EDGE_INSTALL_DEPLOYMENT_INVALID'
}

$actionArguments = ('"{0}" --root "{1}" --manifest "{2}"' -f $hostCli, $config, $Manifest)
$action = New-ScheduledTaskAction -Execute $node -Argument $actionArguments -WorkingDirectory $release
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $identity.Name
$taskPrincipal = New-ScheduledTaskPrincipal -UserId $identity.Name -LogonType Interactive -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet `
    -MultipleInstances IgnoreNew `
    -RestartCount 3 `
    -RestartInterval (New-TimeSpan -Minutes 1) `
    -ExecutionTimeLimit ([TimeSpan]::Zero) `
    -StartWhenAvailable `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries
$task = New-ScheduledTask -Action $action -Trigger $trigger -Principal $taskPrincipal -Settings $settings

if ($PSCmdlet.ShouldProcess($TaskName, 'Register current-user edge client task')) {
    if ($null -eq $existingTask) {
        Register-ScheduledTask -TaskName $TaskName -InputObject $task | Out-Null
    } else {
        Register-ScheduledTask -TaskName $TaskName -InputObject $task -Force | Out-Null
    }
}

[pscustomobject]@{
    ok = $true
    event = 'edge_task_installed'
    taskName = $TaskName
} | ConvertTo-Json -Compress
