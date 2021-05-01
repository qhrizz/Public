<#
.SYNOPSIS
  M365 log export script
.DESCRIPTION
  This script is built upon CISA Sparrow https://github.com/cisagov/Sparrow but with some slight modifications including calling the geojs api to get country for and IP.
  Unified Audit Log and Azure Sign in logs will be exported.
  Only export 5000 logs, can be increased but will take longer to run

.INPUTS
  None
.OUTPUTS
  CSV output to C:\Users\%USERNAME%\Desktop\ExportDir 
.NOTES
  Version:        1.0
  Author:         Christian Tamm
  Creation Date:  2021-02-26
  Purpose/Change: Initial script development
  
  1.1
  Added geojs.io 
  1.2
  The export to csv now has encoding UTF-8
  1.2.1 
  Added mailbox rule parsing 
  

#>

# Globala variabler
[cmdletbinding()]Param(
    [Parameter()]
    [datetime] $StartDate = [DateTime]::UtcNow.AddDays(-364),
    [Parameter()]
    [datetime] $EndDate = [DateTime]::UtcNow,
    [Parameter()]
    [string] $ExportDir = (Join-Path ([Environment]::GetFolderPath("Desktop")) 'ExportDir'),
    [Parameter()]
    [string] $Delimiter = "," # Change this delimiter for localization support of CSV import into Excel
)

# Checks if Azure and Exchange modules are present. Also creates $ExportDir
Function Import-PSModules{

    [cmdletbinding()]Param(
        [Parameter(Mandatory=$true)]
        [string] $ExportDir
        )

    $ModuleArray = @("ExchangeOnlineManagement","AzureADPreview","MSOnline")

    ForEach ($ReqModule in $ModuleArray){
        If ($null -eq (Get-Module $ReqModule -ListAvailable -ErrorAction SilentlyContinue)){
            Write-Verbose "Required module, $ReqModule, is not installed on the system."
            Write-Verbose "Installing $ReqModule from default repository"
            Install-Module -Name $ReqModule -Force
            Write-Verbose "Importing $ReqModule"
            Import-Module -Name $ReqModule
        } ElseIf ($null -eq (Get-Module $ReqModule -ErrorAction SilentlyContinue)){
            Write-Verbose "Importing $ReqModule"
            Import-Module -Name $ReqModule
        }
    }

    #If you want to change the default export directory, please change the $ExportDir value.
    #Otherwise, the default export is the user's home directory, Desktop folder, and ExportDir folder.
    If (!(Test-Path $ExportDir)){
        New-Item -Path $ExportDir -ItemType "Directory" -Force
    }
}

# Function to transform Unified Audit log based on workload to somewhat readable format
# Also calls Get-GeoJSIp function to get IP address location
Function Export-UALData {
    Param(
        [Parameter(ValueFromPipeline=$True)]
        [Object[]]$UALInput,
        [Parameter(Mandatory=$true)]
        [String]$CsvName,
        [Parameter(Mandatory=$true)]
        [String]$WorkloadType,
        [Parameter()]
        [String]$AppendType,
        [Parameter(Mandatory=$true)]
        [string] $ExportDir,
        [Parameter(Mandatory=$true)]
        [string] $Delimiter
        )

        If ($UALInput.Count -eq 5000)
        {
            Write-Host 'Warning: Result set may have been truncated; narrow start/end date.'
        }

        $DataArr = @()
        If ($WorkloadType -eq "AAD") {
            ForEach ($Data in $UALInput){
                $DataProps = [ordered]@{
                    CreationTime = $Data.CreationTime
                    Id = $Data.Id
                    Operation = $Data.Operation
                    Organization = $Data.Organization
                    RecordType = $Data.RecordType
                    ResultStatus = $Data.ResultStatus
                    LogonError = $Data.LogonError
                    UserKey = $Data.UserKey
                    UserType = $Data.UserType
                    Version = $Data.Version
                    Workload = $Data.Workload
                    ClientIP = $Data.ClientIP
                    ClientIPLocation = (Get-GeoJSIp -ip $Data.ClientIP).Name
                    ObjectId = $Data.ObjectId
                    UserId = $Data.UserId
                    AzureActiveDirectoryEventType = $Data.AzureActiveDirectoryEventType
                    ExtendedProperties = ($Data.ExtendedProperties | ConvertTo-Json -Compress | Out-String).Trim()
                    ModifiedProperties = (($Data.ModifiedProperties | ConvertTo-Json -Compress) -replace "\\r\\n" | Out-String).Trim()
                    Actor = ($Data.Actor | ConvertTo-Json -Compress | Out-String).Trim()
                    ActorContextId = $Data.ActorContextId
                    ActorIpAddress = $Data.ActorIpAddress
                    ActorIPAddressLocation = (Get-GeoJSIp -ip $Data.ActorIpAddress).Name
                    InterSystemsId = $Data.InterSystemsId
                    IntraSystemId = $Data.IntraSystemId
                    SupportTicketId = $Data.SupportTicketId
                    Target = ($Data.Target | ConvertTo-Json -Compress | Out-String).Trim()
                    TargetContextId = $Data.TargetContextId
                    ApplicationId = $Data.ApplicationId
                }
                $DataObj = New-Object -TypeName PSObject -Property $DataProps
                $DataArr += $DataObj           
            }
        } elseif ($WorkloadType -eq "EXO"){
            ForEach ($Data in $UALInput){
                $DataProps = [ordered]@{
                    CreationTime = $Data.CreationTime
                    Id = $Data.Id
                    Operation = $Data.Operation
                    OrganizationId = $Data.OrganizationId
                    RecordType = $Data.RecordType
                    ResultStatus = $Data.ResultStatus
                    UserKey = $Data.UserKey
                    UserType = $Data.UserType
                    Version = $Data.Version
                    Workload = $Data.Workload
                    UserId = $Data.UserId
                    AppId = $Data.AppId
                    ClientAppId = $Data.ClientAppId
                    ClientIPAddress = $Data.ClientIPAddress
                    ClientIPLocation = (Get-GeoJSIp -ip $Data.ClientIPAddress).Name
                    ClientInfoString = $Data.ClientInfoString
                    ExternalAccess = $Data.ExternalAccess
                    InternalLogonType = $Data.InternalLogonType
                    LogonType = $Data.LogonType
                    LogonUserSid = $Data.LogonUserSid
                    MailboxGuid = $Data.MailboxGuid
                    MailboxOwnerSid = $Data.MailboxOwnerSid
                    MailboxOwnerUPN = $Data.MailboxOwnerUPN
                    OperationProperties = ($Data.OperationProperties | ConvertTo-Json -Compress | Out-String).Trim()
                    OrganizationName = $Data.OrganizationName
                    OriginatingServer = $Data.OriginatingServer
                    Folders = ((($Data.Folders | ConvertTo-Json -Compress).replace("\u003c","")).replace("\u003e","")  | Out-String).Trim()
                    OperationCount = $Data.OperationCount
                }
                $DataObj = New-Object -TypeName PSObject -Property $DataProps
                $DataArr += $DataObj           
            }
        } elseif ($WorkloadType -eq "EXO2"){
            ForEach ($Data in $UALInput){
                $DataProps = [ordered]@{
                    CreationTime = $Data.CreationTime
                    Id = $Data.Id
                    Operation = $Data.Operation
                    OrganizationId = $Data.OrganizationId
                    RecordType = $Data.RecordType
                    ResultStatus = $Data.ResultStatus
                    UserKey = $Data.UserKey
                    UserType = $Data.UserType
                    Version = $Data.Version
                    Workload = $Data.Workload
                    ClientIP = $Data.ClientIP
                    ClientIPLocation = (Get-GeoJSIp -ip $Data.ClientIP).Name
                    UserId = $Data.UserId
                    ClientIPAddress = $Data.ClientIPAddress
                    ClientInfoString = $Data.ClientInfoString
                    ExternalAccess = $Data.ExternalAccess
                    InternalLogonType = $Data.InternalLogonType
                    LogonType = $Data.LogonType
                    LogonUserSid = $Data.LogonUserSid
                    MailboxGuid = $Data.MailboxGuid
                    MailboxOwnerSid = $Data.MailboxOwnerSid
                    MailboxOwnerUPN = $Data.MailboxOwnerUPN
                    OrganizationName = $Data.OrganizationName
                    OriginatingServer = $Data.OriginatingServer
                }
                $DataObj = New-Object -TypeName PSObject -Property $DataProps
                $DataArr += $DataObj           
            }
        } elseif ($WorkloadType -eq "SharePoint"){
            ForEach ($Data in $UALInput){
                $DataProps = [ordered]@{
                    CreationTime = $Data.CreationTime
                    Id = $Data.Id
                    Operation = $Data.Operation
                    OrganizationId = $Data.OrganizationId
                    RecordType = $Data.RecordType
                    UserKey = $Data.UserKey
                    UserType = $Data.UserType
                    Version = $Data.Version
                    Workload = $Data.Workload
                    ClientIP = $Data.ClientIP
                    ClientIPLocation = (Get-GeoJSIp -ip $Data.ClientIP).Name
                    ObjectId = $Data.ObjectId
                    UserId = $Data.UserId
                    ApplicationId = $Data.ApplicationId
                    CorrelationId = $Data.CorrelationId
                    EventSource = $Data.EventSource
                    ItemType = $Data.ItemType
                    ListId = $Data.ListId
                    ListItemUniqueId = $Data.ListItemUniqueId
                    Site = $Data.Site
                    UserAgent = $Data.UserAgent
                    WebId = $Data.WebId
                    HighPriorityMediaProcessing = $Data.HighPriorityMediaProcessing
                    SourceFileExtension = $Data.SourceFileExtension
                    SiteUrl = $Data.SiteUrl
                    SourceFileName = $Data.SourceFileName
                    SourceRelativeUrl = $Data.SourceRelativeUrl
                }
                $DataObj = New-Object -TypeName PSObject -Property $DataProps
                $DataArr += $DataObj
            }
        }
        elseif ($WorkloadType -eq "AzureApp"){
            ForEach ($Data in $UALInput){
                $DataProps = [ordered]@{
                    CreationTime = $Data.CreationTime
                    Id = $Data.Id
                    Operation = $Data.Operation
                    OrganizationId = $Data.OrganizationId
                    RecordType = $Data.RecordType
                    UserKey = $Data.UserKey
                    UserType = $Data.UserType
                    Version = $Data.Version
                    Workload = $Data.Workload
                    ClientIP = $Data.ClientIP
                    ClientIPLocation = (Get-GeoJSIp -ip $Data.ClientIP).Name
                    ObjectId = $Data.ObjectId
                    UserId = $Data.UserId
                    ApplicationId = $Data.ApplicationId
                    ApplicationDisplayName = (Get-AzureADApplication -all:$true | Where-Object {$_.AppId -match "$($data.ObjectId)"}).DisplayName
                    ServicePrincipalDisplayName = (Get-AzureADServicePrincipal -all:$true | Where-Object {$_.AppId -match "$($data.ObjectId)"}).DisplayName
                    CorrelationId = $Data.CorrelationId
                    EventSource = $Data.EventSource
                    UserAgent = $Data.UserAgent
                }
                $DataObj = New-Object -TypeName PSObject -Property $DataProps
                $DataArr += $DataObj
            }
        }
        elseif ($WorkloadType -eq "InboxRule"){
            ForEach ($Data in $UALInput){
                $DataProps = [ordered]@{
                    CreationTime = $Data.CreationTime
                    Id = $Data.Id
                    Operation = $Data.Operation
                    OrganizationId = $Data.OrganizationId
                    RecordType = $Data.RecordType
                    UserKey = $Data.UserKey
                    UserType = $Data.UserType
                    Version = $Data.Version
                    Workload = $Data.Workload
                    ClientIP = $Data.ClientIP
                    ClientIPLocation = (Get-GeoJSIp -ip $Data.ClientIP).Name
                    ObjectId = $Data.ObjectId
                    UserId = $Data.UserId
                    RuleName = ($data.Parameters | Where-Object {$_.Name -like "Name"}).Value 
                    RuleForce = ($data.Parameters | Where-Object {$_.Name -like "Force"}).Value 
                    RuleFrom = ($data.Parameters | Where-Object {$_.Name -like "From"}).Value 
                    RuleSubjectContainsWords = ($data.Parameters | Where-Object {$_.Name -like "SubjectContainsWords"}).Value 
                    RuleMoveToFolder = ($data.Parameters | Where-Object {$_.Name -like "MoveToFolder"}).Value 
                    RuleStopProcessing = ($data.Parameters | Where-Object {$_.Name -like "StopProcessingRules"}).Value 
                    RuleAlwaysDeleteOutlookRulesBlob = ($data.Parameters | Where-Object {$_.Name -like "AlwaysDeleteOutlookRulesBlob"}).Value 
                    
                }
                $DataObj = New-Object -TypeName PSObject -Property $DataProps
                $DataArr += $DataObj
            }
        }
        If ($AppendType -eq "Append"){
            $DataArr | Export-csv $ExportDir\$CsvName.csv -NoTypeInformation -Append -Delimiter $Delimiter -Encoding utf8
        } Else {
            $DataArr | Export-csv $ExportDir\$CsvName.csv -NoTypeInformation -Delimiter $Delimiter -Encoding utf8
        }
        
        Remove-Variable UALInput -ErrorAction SilentlyContinue
        Remove-Variable Data -ErrorAction SilentlyContinue
        Remove-Variable DataObj -ErrorAction SilentlyContinue
        Remove-Variable DataProps -ErrorAction SilentlyContinue
        Remove-Variable DataArr -ErrorAction SilentlyContinue
}

# Geoip lookup
Function Get-GeoJSIp {
    Param(
        [Parameter(Mandatory=$true)]
        [AllowEmptyString()]
        [string]$ip
    )
    try{
        # Remove any "ports" from IP
        $cleanIP = ($ip | Select-String -Pattern "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}").Matches.Value
        if($null -eq $cleanIP){
            # No IP
            $data = "no ip"
            return $data
        }
        else{
        $uri = "https://get.geojs.io/v1/ip/country/" + "$cleanIP" + ".json"
        $data = Invoke-RestMethod -Uri $uri
        return $data
        }
    }
    catch{
        throw $_.Exception.Message
    }
}

Function Export-AzureAppPermissions {
    Get-AzureADServicePrincipal | ForEach-Object {

        # Build a hash table of the service principal's app roles. The 0-Guid is
        # used in an app role assignment to indicate that the principal is assigned
        # to the default app role (or rather, no app role).
        $appRoles = @{ "$([Guid]::Empty.ToString())" = "(default)" }
        $_.AppRoles | ForEach-Object { $appRoles[$_.Id] = $_.DisplayName }
      
        # Get the app role assignments for this app, and add a field for the app role name
        Get-AzureADServiceAppRoleAssignment -ObjectId ($_.ObjectId) | ForEach-Object {
          $_ | Add-Member "AppRoleDisplayName" $appRoles[$_.Id] -Passthru
        }
      } | Export-csv $ExportDir\app_role_assignments.csv -NoTypeInformation -Delimiter $Delimiter -Encoding UTF8
    
}

# Function to collect Azure Sign in logs
Function Get-AzSigninLogs{
    Param(
    [string]$upn
    )
    # Fetches the last month's Azure Active Directory sign-in data
    $StartDate = ((Get-Date).AddDays(-30)).ToString("yyyy-MM-dd")
    $TodayDate = (Get-Date -Format("yyyy-MM-dd"))
    Write-Host "Fetching data from Azure Active Directory..."
     
    if(!$upn){
    $Records = Get-AzureADAuditSignInLogs -Filter "createdDateTime gt $StartDate" -all:$True
    $csvName = "AzureSigninLog-ALL-$StartDate-TO-$TodayDate.csv"
    }
    else{
    $Records = Get-AzureADAuditSignInLogs -Filter "createdDateTime gt $StartDate" -all:$True | Where-Object {$_.UserprincipalName -match "$upn"} 
    $csvName = $upn + "-" + "AzureSigninLog-$StartDate-TO-$TodayDate.csv"
    }
     
    $Report = [System.Collections.Generic.List[Object]]::new() 
    ForEach ($Rec in $Records) {
        Switch ($Rec.Status.ErrorCode) {
          "0" {$Status = "Success"}
          default {$Status = $Rec.Status.FailureReason}
        }
        $ReportLine = [PSCustomObject] @{
               TimeStamp   = Get-Date($Rec.CreatedDateTime) -format g
               User        = $Rec.UserPrincipalName
               Name        = $Rec.UserDisplayName
               IPAddress   = $Rec.IpAddress
               ClientApp   = $Rec.ClientAppUsed
               DeviceOperatingsystem      = $Rec.DeviceDetail.OperatingSystem
               DeviceBrowser = $Rec.DeviceDetail.Browser
               City        = $Rec.Location.City
               State       = $Rec.Location.State
               CountryCode = $Rec.Location.CountryOrRegion
               Appname     = $Rec.AppDisplayName
               Resource    = $Rec.ResourceDisplayName
               Status      = $Status
               Correlation = $Rec.CorrelationId
               Interactive = $Rec.IsInteractive
               ConditionalAccessStatus = $Rec.ConditionalAccessStatus
                }
          $Report.Add($ReportLine) } 
    Write-Host $Report.Count "sign-in audit records processed."
    $Report | Export-Csv $ExportDir\$csvName -NoTypeInformation -Encoding UTF8 
     
    }


# Call function to import PSmodules
Import-PSModules -ExportDir $ExportDir

# Connect 
Write-Host "You will be prompted 3 times for sign in..." -ForegroundColor Green
# Connect to Exchange online
Connect-ExchangeOnline -ErrorAction Stop 6>$null
# Connect to  MSOnline
Connect-MsolService -ErrorAction Stop 6>$null
# Connect to  AzureAD 
Connect-AzureAD -ErrorAction Stop 6>$null

# Export Unified audit log for Sharepoint
Write-Host "Exporting Unfied Audit log for Sharepoint..." 
$QDSPData = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -RecordType SharePoint -ResultSize 5000  | Select-Object -ExpandProperty AuditData | Convertfrom-Json
If ($null -ne $QDSPData){
    Export-UALData -ExportDir $ExportDir -UALInput $QDSPData -CsvName "QD-Unified-Auditlog-Sharepoint-Activity" -WorkloadType "SharePoint" -AppendType "Append" -Delimiter $Delimiter
} Else{
    Write-Verbose "No data returned for Sharepoint"
}

# Export unified audit log for Exchange
Write-Host "Exporting Unified Audit log for Exchange activity.."
$PSMailboxData = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -ResultSize 5000 -RecordType 1 | Select-Object -ExpandProperty AuditData | Convertfrom-Json
If ($null -ne $PSMailboxData){
    Export-UALData -ExportDir $ExportDir -UALInput $PSMailboxData -CsvName "QD-Unified-Auditlog-Exchange-Activity" -WorkloadType "EXO2" -Delimiter $Delimiter
} Else{
    Write-Verbose "No data returned for Exchange"
}

# Export unified audit log for Onedrive
Write-Host "Exporting Unified Audit log for Onedrive activity.."
$UALOnedrive = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -ResultSize 5000 -RecordType 6 | Select-Object -ExpandProperty AuditData | Convertfrom-Json
If ($null -ne $PSMailboxData){
    Export-UALData -ExportDir $ExportDir -UALInput $UALOnedrive -CsvName "QD-Unified-Auditlog-Onedrive-Activity" -WorkloadType "Sharepoint" -Delimiter $Delimiter
} Else{
    Write-Verbose "No data returned for Onedrive activity"
}


# Export unified audit log for New-InboxRule
Write-Host "Exporting Unified Audit log for New-InboxRule..."
$MailboxRules = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -ResultSize 5000 -Operations "New-InboxRule" | Select-Object -ExpandProperty AuditData | Convertfrom-Json
If ($null -ne $MailboxRules){
    Export-UALData -ExportDir $ExportDir -UALInput $MailboxRules -CsvName "QD-Unified-Auditlog-New-InboxRule" -WorkloadType "EXO2" -Delimiter $Delimiter
} Else{
    Write-Verbose "No data returned for New-InboxRule"
}

#Searches for any OAuth or application consents
Write-Verbose "Searching for 'Add OAuth2PermissionGrant' and 'Consent to application' in the UAL."
$ConsentData = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -RecordType AzureActiveDirectory -Operations "Add OAuth2PermissionGrant","Consent to application" -ResultSize 5000 | Select-Object -ExpandProperty AuditData | Convertfrom-Json
If ($null -ne $ConsentData){    
    Export-UALData -ExportDir $ExportDir -UALInput $ConsentData -CsvName "QD-Unified-Auditlog-Consent_Operations_Export" -WorkloadType "AzureApp" -Delimiter $Delimiter
} Else{
    Write-Verbose "No 'Add app role assignment to service principal', 'Add app role assignment grant to user', and 'Add app role assignment to group' data returned and no CSV will be produced."
}  

# Call function to collect Azure sign in logs
# This only goes back 30 days! (7 days if azure basic/free)
Write-Host "Collection Azure Sign in logs, this might take a while..."
Get-AzSigninLogs

# Export Azure Application permissions 
Export-AzureAppPermissions

# Scriptet loggar ut från Exchangeonline och AzureAD
Write-Host "Disconnecting from ExchangeOnline"
Disconnect-ExchangeOnline -Confirm:$false
Write-Host "Disconnecting from AzureAD"
Disconnect-AzureAD -Confirm:$false