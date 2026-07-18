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

Start-ScheduledTask -TaskName $TaskName
[pscustomobject]@{ ok = $true; event = 'agent_task_start_requested'; taskName = $TaskName } |
    ConvertTo-Json -Compress
