[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$TaskName = 'RemoteCodex-EgressAgent'
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$task = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
if (@($identity.Name, $identity.User.Value) -notcontains $task.Principal.UserId) {
    throw 'AGENT_TASK_OWNER_MISMATCH'
}

Stop-ScheduledTask -TaskName $TaskName
$deadline = [DateTime]::UtcNow.AddSeconds(15)
do {
    Start-Sleep -Milliseconds 250
    $state = (Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop).State
} while ($state -eq 'Running' -and [DateTime]::UtcNow -lt $deadline)

if ($state -eq 'Running') {
    throw 'AGENT_TASK_STOP_TIMEOUT'
}

[pscustomobject]@{ ok = $true; event = 'agent_task_force_stop_confirmed'; taskName = $TaskName } |
    ConvertTo-Json -Compress
