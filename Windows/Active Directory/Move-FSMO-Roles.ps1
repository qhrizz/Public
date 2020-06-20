<#
.SYNOPSIS
  Script to move FSMO Roles from one domaincontroller to another.
.DESCRIPTION
  Script to move FSMO Roles from one domaincontroller to another.
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


$domain = Read-Host "Enter domainname, for example ad.domain.com"
$moveToDomainController = Read-Host "Enter name of domaincontroller to move to, for example MyDomain-DC01"
#First we can check which server that has the roles. 
Get-ADForest $domain | Format-Table DomainNamingMaster, SchemaMaster
Get-ADDomain $domain | Format-Table InfrastructureMaster, PDCEmulator, RIDMaster
Move-ADDirectoryServerOperationMasterRole “$moveToDomainController” –OperationMasterRole 0,1,2,3,4