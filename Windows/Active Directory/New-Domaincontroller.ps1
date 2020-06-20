<#
.SYNOPSIS
  Simple script to install the ADDS role and promoting the server to a domaincontroller
.DESCRIPTION
  Simple script to install the ADDS role and promoting the server to a domaincontroller
.PARAMETER <Parameter_Name>
    <Brief description of parameter input required. Repeat this attribute if required>
.INPUTS
  None
.OUTPUTS
  None
.NOTES
  Version:        1.0
  Author:         Christian Tamm
  Creation Date:  2020-04-25
  Purpose/Change: Initial script development
  
.EXAMPLE
  Simpy run the file
#>


# Ask for as SafeModeAdministratorPassword 
$SafeModeAdministratorPassword = Read-Host "Specify SafeModeAdministratorPassword password" 
$domainname = Read-Host "Specify domainname, eg bananrepubliken.tarzan" 
$netbiosName = Read-Host "Specify NetBiosName, eg 'BANAN'"

# Install ADDS role 
Install-WindowsFeature AD-Domain-Services   
Import-Module ADDSDeployment 
Install-ADDSForest -CreateDnsDelegation:$false `
-DatabasePath "C:\Windows\NTDS" `
-DomainMode "WinThreshold" `
-DomainName $domainname `
-DomainNetbiosName $netbiosName `
-ForestMode "WinThreshold" `
-InstallDns:$true `
-LogPath "C:\Windows\NTDS" `
-NoRebootOnCompletion:$false `
-SysvolPath "C:\Windows\SYSVOL" `
-SafeModeAdministratorPassword (Write-Output "$SafeModeAdministratorPassword" | ConvertTo-SecureString -AsPlainText -Force) `
-Force:$true
