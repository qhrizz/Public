<#
.SYNOPSIS
  Script to schedule a single restart of a computer on a monthly basis
.DESCRIPTION
  Make the modification you want, time and taskname 
.OUTPUTS
  Creates a scheduled task in task scheduler
.NOTES
  Version:        1.0
  Author:         Christian Tamm
  Creation Date:  2021-08-01
  Purpose/Change: Initial script development
#>


$action = New-ScheduledTaskAction -Execute 'Powershell.exe' ` -Argument '-NoProfile -WindowStyle Hidden -command "& {Restart-Computer -Force}"'
$trigger = New-ScheduledTaskTrigger -Weekly -WeeksInterval 4 -DaysOfWeek Friday -At 3am
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "Reboot computer" -Description "Reboot computer"  -Principal $principal