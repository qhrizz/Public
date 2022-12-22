<#
.SYNOPSIS
  Script to export Teams data
.DESCRIPTION
  The script exports TeamsgroupName,address, owner, members, whencreated and whenchanged. Export is saved under C:\temp\groups.csv. Change this if needed.
.PARAMETER <Parameter_Name>
    <Brief description of parameter input required. Repeat this attribute if required>
.INPUTS
  None
.OUTPUTS
  C:\temp\groups.csv
.NOTES
  Version:        1.0
  Author:         Christian Tamm
  Creation Date:  2020-04-25
  Purpose/Change: Initial script development
  
.EXAMPLE
  Simpy run the file
#>

Write-Output "DisplayName;Address;Owner;Members;WhenCreated;WhenChanged" | Out-File C:\temp\groups.csv
$groups = Get-UnifiedGroup 
foreach($group in $groups)
    {
        $owner = (Get-UnifiedGroupLinks "$($group.DisplayName)" -LinkType Owner).Name -join "|"
        $memberCount = (Get-UnifiedGroupLinks "$($group.DisplayName)" -LinkType member).count
        "$($group.DisplayName)" + ";" + "$($group.PrimarySMTPAddress)" + ";" + $owner + ";" + $memberCount + ";" + "$($group.WhenCreated)" + ";" + "$($group.WhenChanged)" | out-file C:\temp\groups.csv -Append
    }