[CmdletBinding(SupportsShouldProcess = $true)]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$TaskName = 'RemoteCodex-EdgeClient'

function Test-TaskOwnedByCurrentUser {
    param([Parameter(Mandatory = $true)][string]$TaskUserId)

    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $acceptedIds = @($identity.Name, $identity.User.Value)
    if ($identity.Name -eq ("{0}\\{1}" -f $env:COMPUTERNAME, $env:USERNAME)) {
        $acceptedIds += $env:USERNAME
    }
    return $acceptedIds -contains $TaskUserId
}

$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue

if ($null -ne $task) {
    if (-not (Test-TaskOwnedByCurrentUser -TaskUserId $task.Principal.UserId)) {
        throw 'EDGE_TASK_OWNER_MISMATCH'
    }
    if ($PSCmdlet.ShouldProcess($TaskName, 'Stop and unregister current-user edge client task')) {
        Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    }
}

[pscustomobject]@{
    ok = $true
    event = 'edge_task_uninstalled'
    taskName = $TaskName
} | ConvertTo-Json -Compress
