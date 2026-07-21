[CmdletBinding()]
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
$task = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
if (-not (Test-TaskOwnedByCurrentUser -TaskUserId $task.Principal.UserId)) {
    throw 'EDGE_TASK_OWNER_MISMATCH'
}

Stop-ScheduledTask -TaskName $TaskName
$deadline = [DateTime]::UtcNow.AddSeconds(15)
do {
    Start-Sleep -Milliseconds 250
    $state = (Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop).State
} while ($state -eq 'Running' -and [DateTime]::UtcNow -lt $deadline)

if ($state -eq 'Running') {
    throw 'EDGE_TASK_STOP_TIMEOUT'
}

[pscustomobject]@{ ok = $true; event = 'edge_task_force_stop_confirmed'; taskName = $TaskName } |
    ConvertTo-Json -Compress
