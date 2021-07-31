<#
.SYNOPSIS
  Script to schedule a script to run witht the highest privileges 
.DESCRIPTION
  Make the modification you want, time, path to script, user to run as, and taskname 
.OUTPUTS
  Creates a scheduled task in task scheduler
.NOTES
  Version:        1.0
  Author:         Christian Tamm
  Creation Date:  2021-08-01
  Purpose/Change: Initial script development
#>

$action = New-ScheduledTaskAction -Execute 'Powershell.exe' ` -Argument '-NoProfile -WindowStyle Hidden -file "C:\MyScripts\myscript.ps1" '
$trigger = New-ScheduledTaskTrigger -Daily -At 06:00
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "MyTaskName" -Description "MyTaskName"  -Principal $principal