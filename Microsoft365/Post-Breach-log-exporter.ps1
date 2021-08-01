<#
.SYNOPSIS
  Log export script for common things to look at after a potential breach
.DESCRIPTION
  Exports unified audit logs and Azure sign in logs.
  Code built upon CISA Sparrow script https://github.com/cisagov/Sparrow
.PARAMETER <Parameter_Name>

.INPUTS
  None
.OUTPUTS
  CSV files to C:\Users\%USERNAME%\Desktop\ExportDir 
.NOTES
  Version:        1.2.3
  Author:         Christian Tamm
  Creation Date:  2021-02-26
  Purpose/Change: Initial script development
  
  1.1
  Added geoIP resolver using geojs.io 
  1.2
  Added UTF-8 Encoding in Export-UALData function
  1.2.1 
  Added parsing of inboxrules 
  1.2.3
  Added export av eDiscovery events
  
.EXAMPLE
  <Example goes here. Repeat this attribute for more than one example>
#>

# Global variables
[cmdletbinding()]Param(
    [Parameter()]
    [string] $ExportDir = (Join-Path ([Environment]::GetFolderPath("Desktop")) 'ExportDir'),
    #[string] $ExportDir = "C:\Temp",
    [Parameter()]
    [string] $Delimiter = "," # Change this delimiter for localization support of CSV import into Excel
)

# Checks if Azure and Exchange modules are present. Also creates $ExportDir
Function Import-PSModules {

    [cmdletbinding()]Param(
        [Parameter(Mandatory = $true)]
        [string] $ExportDir
    )

    $ModuleArray = @("ExchangeOnlineManagement", "AzureADPreview", "MSOnline")

    ForEach ($ReqModule in $ModuleArray) {
        If ($null -eq (Get-Module $ReqModule -ListAvailable -ErrorAction SilentlyContinue)) {
            Write-Verbose "Required module, $ReqModule, is not installed on the system."
            Write-Verbose "Installing $ReqModule from default repository"
            Install-Module -Name $ReqModule -Force
            Write-Verbose "Importing $ReqModule"
            Import-Module -Name $ReqModule
        }
        ElseIf ($null -eq (Get-Module $ReqModule -ErrorAction SilentlyContinue)) {
            Write-Verbose "Importing $ReqModule"
            Import-Module -Name $ReqModule
        }
    }

    #If you want to change the default export directory, please change the $ExportDir value.
    #Otherwise, the default export is the user's home directory, Desktop folder, and ExportDir folder.
    If (!(Test-Path $ExportDir)) {
        New-Item -Path $ExportDir -ItemType "Directory" -Force
    }
}

# Function to transform Unified Audit log based on workload to somewhat readable format
# Also calls Get-GeoJSIp function to get IP address location
Function Export-UALData {
    Param(
        [Parameter(ValueFromPipeline = $True)]
        [Object[]]$UALInput,
        [Parameter(Mandatory = $true)]
        [String]$CsvName,
        [Parameter(Mandatory = $true)]
        [String]$WorkloadType,
        [Parameter()]
        [String]$AppendType,
        [Parameter(Mandatory = $true)]
        [string] $ExportDir,
        [Parameter(Mandatory = $true)]
        [string] $Delimiter
    )

    If ($UALInput.Count -eq 5000) {
        Write-Host 'Warning: Result set may have been truncated; narrow start/end date.'
    }

    $DataArr = @()
    If ($WorkloadType -eq "AAD") {
        ForEach ($Data in $UALInput) {
            $DataProps = [ordered]@{
                CreationTime                  = $Data.CreationTime
                Id                            = $Data.Id
                Operation                     = $Data.Operation
                Organization                  = $Data.Organization
                RecordType                    = $Data.RecordType
                ResultStatus                  = $Data.ResultStatus
                LogonError                    = $Data.LogonError
                UserKey                       = $Data.UserKey
                UserType                      = $Data.UserType
                Version                       = $Data.Version
                Workload                      = $Data.Workload
                ClientIP                      = $Data.ClientIP
                ClientIPLocation              = (Get-GeoJSIp -ip $Data.ClientIP).Name
                ObjectId                      = $Data.ObjectId
                UserId                        = $Data.UserId
                AzureActiveDirectoryEventType = $Data.AzureActiveDirectoryEventType
                ExtendedProperties            = ($Data.ExtendedProperties | ConvertTo-Json -Compress | Out-String).Trim()
                ModifiedProperties            = (($Data.ModifiedProperties | ConvertTo-Json -Compress) -replace "\\r\\n" | Out-String).Trim()
                Actor                         = ($Data.Actor | ConvertTo-Json -Compress | Out-String).Trim()
                ActorContextId                = $Data.ActorContextId
                ActorIpAddress                = $Data.ActorIpAddress
                ActorIPAddressLocation        = (Get-GeoJSIp -ip $Data.ActorIpAddress).Name
                InterSystemsId                = $Data.InterSystemsId
                IntraSystemId                 = $Data.IntraSystemId
                SupportTicketId               = $Data.SupportTicketId
                Target                        = ($Data.Target | ConvertTo-Json -Compress | Out-String).Trim()
                TargetContextId               = $Data.TargetContextId
                ApplicationId                 = $Data.ApplicationId
            }
            $DataObj = New-Object -TypeName PSObject -Property $DataProps
            $DataArr += $DataObj           
        }
        # Exchange logs
    }
    elseif ($WorkloadType -eq "EXO") {
        ForEach ($Data in $UALInput) {
            $DataProps = [ordered]@{
                CreationTime        = $Data.CreationTime
                Id                  = $Data.Id
                Operation           = $Data.Operation
                OrganizationId      = $Data.OrganizationId
                RecordType          = $Data.RecordType
                ResultStatus        = $Data.ResultStatus
                UserKey             = $Data.UserKey
                UserType            = $Data.UserType
                Version             = $Data.Version
                Workload            = $Data.Workload
                UserId              = $Data.UserId
                AppId               = $Data.AppId
                ClientAppId         = $Data.ClientAppId
                ClientIPAddress     = $Data.ClientIPAddress
                ClientIPLocation    = (Get-GeoJSIp -ip $Data.ClientIPAddress).Name
                ClientInfoString    = $Data.ClientInfoString
                ExternalAccess      = $Data.ExternalAccess
                InternalLogonType   = $Data.InternalLogonType
                LogonType           = $Data.LogonType
                LogonUserSid        = $Data.LogonUserSid
                MailboxGuid         = $Data.MailboxGuid
                MailboxOwnerSid     = $Data.MailboxOwnerSid
                MailboxOwnerUPN     = $Data.MailboxOwnerUPN
                OperationProperties = ($Data.OperationProperties | ConvertTo-Json -Compress | Out-String).Trim()
                OrganizationName    = $Data.OrganizationName
                OriginatingServer   = $Data.OriginatingServer
                Folders             = ((($Data.Folders | ConvertTo-Json -Compress).replace("\u003c", "")).replace("\u003e", "")  | Out-String).Trim()
                OperationCount      = $Data.OperationCount
            }
            $DataObj = New-Object -TypeName PSObject -Property $DataProps
            $DataArr += $DataObj           
        }
        # InboxRule Data
    }
    elseif ($WorkloadType -eq "EXO2") {
        ForEach ($Data in $UALInput) {
            $DataProps = [ordered]@{
                CreationTime      = $Data.CreationTime
                Id                = $Data.Id
                Operation         = $Data.Operation
                OrganizationId    = $Data.OrganizationId
                RecordType        = $Data.RecordType
                ResultStatus      = $Data.ResultStatus
                UserKey           = $Data.UserKey
                UserType          = $Data.UserType
                Version           = $Data.Version
                Workload          = $Data.Workload
                ClientIP          = $Data.ClientIP
                ClientIPLocation  = (Get-GeoJSIp -ip $Data.ClientIP).Name
                UserId            = $Data.UserId
                ClientIPAddress   = $Data.ClientIPAddress
                ClientInfoString  = $Data.ClientInfoString
                ExternalAccess    = $Data.ExternalAccess
                InternalLogonType = $Data.InternalLogonType
                LogonType         = $Data.LogonType
                LogonUserSid      = $Data.LogonUserSid
                MailboxGuid       = $Data.MailboxGuid
                MailboxOwnerSid   = $Data.MailboxOwnerSid
                MailboxOwnerUPN   = $Data.MailboxOwnerUPN
                OrganizationName  = $Data.OrganizationName
                OriginatingServer = $Data.OriginatingServer
            }
            $DataObj = New-Object -TypeName PSObject -Property $DataProps
            $DataArr += $DataObj           
        }
        # Sharepoint data
    }
    elseif ($WorkloadType -eq "SharePoint") {
        ForEach ($Data in $UALInput) {
            $DataProps = [ordered]@{
                CreationTime                = $Data.CreationTime
                Id                          = $Data.Id
                Operation                   = $Data.Operation
                OrganizationId              = $Data.OrganizationId
                RecordType                  = $Data.RecordType
                UserKey                     = $Data.UserKey
                UserType                    = $Data.UserType
                Version                     = $Data.Version
                Workload                    = $Data.Workload
                ClientIP                    = $Data.ClientIP
                ClientIPLocation            = (Get-GeoJSIp -ip $Data.ClientIP).Name
                ObjectId                    = $Data.ObjectId
                UserId                      = $Data.UserId
                ApplicationId               = $Data.ApplicationId
                CorrelationId               = $Data.CorrelationId
                EventSource                 = $Data.EventSource
                ItemType                    = $Data.ItemType
                ListId                      = $Data.ListId
                ListItemUniqueId            = $Data.ListItemUniqueId
                Site                        = $Data.Site
                UserAgent                   = $Data.UserAgent
                WebId                       = $Data.WebId
                HighPriorityMediaProcessing = $Data.HighPriorityMediaProcessing
                SourceFileExtension         = $Data.SourceFileExtension
                SiteUrl                     = $Data.SiteUrl
                SourceFileName              = $Data.SourceFileName
                SourceRelativeUrl           = $Data.SourceRelativeUrl
            }
            $DataObj = New-Object -TypeName PSObject -Property $DataProps
            $DataArr += $DataObj
        }
    }
    # OAuth Consent operations
    elseif ($WorkloadType -eq "AzureApp") {
        ForEach ($Data in $UALInput) {
            $DataProps = [ordered]@{
                CreationTime                = $Data.CreationTime
                Id                          = $Data.Id
                Operation                   = $Data.Operation
                OrganizationId              = $Data.OrganizationId
                RecordType                  = $Data.RecordType
                UserKey                     = $Data.UserKey
                UserType                    = $Data.UserType
                Version                     = $Data.Version
                Workload                    = $Data.Workload
                ClientIP                    = $Data.ClientIP
                ClientIPLocation            = (Get-GeoJSIp -ip $Data.ClientIP).Name
                ObjectId                    = $Data.ObjectId
                UserId                      = $Data.UserId
                ApplicationDisplayName      = (Get-AzureADApplication -all:$true | Where-Object { $_.AppId -match "$($data.ObjectId)" }).DisplayName
                ServicePrincipalDisplayName = (Get-AzureADServicePrincipal -all:$true | Where-Object { $_.AppId -match "$($data.ObjectId)" }).DisplayName

            }
            $DataObj = New-Object -TypeName PSObject -Property $DataProps
            $DataArr += $DataObj
        }
    }
    elseif ($WorkloadType -eq "SecurityComplianceCenter") {
        ForEach ($Data in $UALInput) {
            $DataProps = [ordered]@{
                CreationTime                      = $Data.CreationTime
                Id                                = $Data.Id
                Operation                         = $Data.Operation
                OrganizationId                    = $Data.OrganizationId
                RecordType                        = $Data.RecordType
                UserKey                           = $Data.UserKey
                UserType                          = $Data.UserType
                Version                           = $Data.Version
                Workload                          = $Data.Workload
                ObjectId                          = $Data.ObjectId
                UserId                            = $Data.UserId
                SecurityComplianceCenterEventType = $data.SecurityComplianceCenterEventType
                ClientApplication                 = $data.ClientApplication
                StartTime                         = $Data.StartTime 


            }
            $DataObj = New-Object -TypeName PSObject -Property $DataProps
            $DataArr += $DataObj
        }
    }
    elseif ($WorkloadType -eq "InboxRule") {
        ForEach ($Data in $UALInput) {
            $DataProps = [ordered]@{
                CreationTime                     = $Data.CreationTime
                Id                               = $Data.Id
                Operation                        = $Data.Operation
                OrganizationId                   = $Data.OrganizationId
                RecordType                       = $Data.RecordType
                UserKey                          = $Data.UserKey
                UserType                         = $Data.UserType
                Version                          = $Data.Version
                Workload                         = $Data.Workload
                ClientIP                         = $Data.ClientIP
                ClientIPLocation                 = (Get-GeoJSIp -ip $Data.ClientIP).Name
                ObjectId                         = $Data.ObjectId
                UserId                           = $Data.UserId
                RuleName                         = ($data.Parameters | Where-Object { $_.Name -like "Name" }).Value 
                RuleForce                        = ($data.Parameters | Where-Object { $_.Name -like "Force" }).Value 
                RuleFrom                         = ($data.Parameters | Where-Object { $_.Name -like "From" }).Value 
                RuleSubjectContainsWords         = ($data.Parameters | Where-Object { $_.Name -like "SubjectContainsWords" }).Value 
                RuleMoveToFolder                 = ($data.Parameters | Where-Object { $_.Name -like "MoveToFolder" }).Value 
                RuleStopProcessing               = ($data.Parameters | Where-Object { $_.Name -like "StopProcessingRules" }).Value 
                RuleAlwaysDeleteOutlookRulesBlob = ($data.Parameters | Where-Object { $_.Name -like "AlwaysDeleteOutlookRulesBlob" }).Value 
                    
            }
            $DataObj = New-Object -TypeName PSObject -Property $DataProps
            $DataArr += $DataObj
        }
    }
    If ($AppendType -eq "Append") {
        $DataArr | Export-csv $ExportDir\$CsvName.csv -NoTypeInformation -Append -Delimiter $Delimiter -Encoding utf8
    }
    Else {
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
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$ip
    )
    try {
        # Remove any "ports" from IP
        $cleanIP = ($ip | Select-String -Pattern "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}").Matches.Value
        if ($null -eq $cleanIP) {
            # No IP
            $data = "no ip"
            return $data
        }
        else {
            $uri = "https://get.geojs.io/v1/ip/country/" + "$cleanIP" + ".json"
            $data = Invoke-RestMethod -Uri $uri
            return $data
        }
    }
    catch {
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
    } | Export-csv $ExportDir\Azure-app_role_assignments.csv -NoTypeInformation -Delimiter $Delimiter -Encoding UTF8
    
}

# Function to collect Azure Sign in logs
Function Get-AzSigninLogs {
    # Fetches the last month's Azure Active Directory sign-in data
    $StartDate = ((Get-Date).AddDays(-364)).ToString("yyyy-MM-dd")
    $TodayDate = (Get-Date -Format("yyyy-MM-dd"))
    Write-Host "Fetching data from Azure Active Directory..."
    $Records = Get-AzureADAuditSignInLogs -Filter "createdDateTime gt $StartDate" -all:$True
    $csvName = "AzureSigninLog-$StartDate-TO-$TodayDate.csv"
    $Report = [System.Collections.Generic.List[Object]]::new() 
    ForEach ($Rec in $Records) {
        Switch ($Rec.Status.ErrorCode) {
            "0" { $Status = "Success" }
            default { $Status = $Rec.Status.FailureReason }
        }
        $ReportLine = [PSCustomObject] @{
            TimeStamp               = Get-Date($Rec.CreatedDateTime) -format g
            User                    = $Rec.UserPrincipalName
            Name                    = $Rec.UserDisplayName
            IPAddress               = $Rec.IpAddress
            ClientApp               = $Rec.ClientAppUsed
            DeviceOperatingsystem   = $Rec.DeviceDetail.OperatingSystem
            DeviceBrowser           = $Rec.DeviceDetail.Browser
            City                    = $Rec.Location.City
            State                   = $Rec.Location.State
            CountryCode             = $Rec.Location.CountryOrRegion
            Appname                 = $Rec.AppDisplayName
            Resource                = $Rec.ResourceDisplayName
            Status                  = $Status
            Correlation             = $Rec.CorrelationId
            Interactive             = $Rec.IsInteractive
            ConditionalAccessStatus = $Rec.ConditionalAccessStatus
        }
        $Report.Add($ReportLine) 
    } 
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

# Specify how many days back we should try to get data
$daysToRetrieve = 5

# We loop through 365 days in increments of 2 days to mitigate any limit in the search result (5000 posts)  
[int]$dayCounter = "-1"
$i = 1
while ($i -le $daysToRetrieve) {
    $StartDate = [DateTime]::UtcNow.AddDays($dayCounter)
    $EndDate = [DateTime]::UtcNow.AddDays($dayCounter + 1)

    Write-Host -ForegroundColor Green "Exporting data between $($StartDate.ToString('yyyy-MM-dd')) and $($EndDate.ToString('yyyy-MM-dd'))"
    # Kör kod
    # Export Unified audit log for Sharepoint
    Write-Host "Exporting Unfied Audit log for Sharepoint..."
    $SPData = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -RecordType SharePoint -ResultSize 5000  | Select-Object -ExpandProperty AuditData | Convertfrom-Json
    If ($null -ne $SPData) {
        Export-UALData -ExportDir $ExportDir -UALInput $SPData -CsvName "Unified-Auditlog-Sharepoint-Activity" -WorkloadType "SharePoint" -AppendType "Append" -Delimiter $Delimiter
    }
    Else {
        Write-Host "No data returned for Sharepoint" -ForegroundColor Yellow
    }

    # Export unified audit log for ExchangeAdmin
    Write-Host "Exporting Unified Audit log for ExchangeAdmin activity..."
    $PSMailboxData = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -ResultSize 5000 -RecordType 1 | Select-Object -ExpandProperty AuditData | Convertfrom-Json
    If ($null -ne $PSMailboxData) {
        Export-UALData -ExportDir $ExportDir -UALInput $PSMailboxData -CsvName "Unified-Auditlog-Exchange-Activity" -WorkloadType "EXO2" -AppendType "Append" -Delimiter $Delimiter
    }
    Else {
        Write-Host "No data returned for ExchangeAdmin" -ForegroundColor Yellow
    }

    # Export unified audit log for ExchangeItem
    Write-Host "Exporting Unified Audit log for ExchangeItem activity..."
    $PSMailboxData = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -ResultSize 5000 -RecordType 2 | Select-Object -ExpandProperty AuditData | Convertfrom-Json
    If ($null -ne $PSMailboxData) {
        Export-UALData -ExportDir $ExportDir -UALInput $PSMailboxData -CsvName "Unified-Auditlog-Exchange-Activity" -WorkloadType "EXO2" -AppendType "Append" -Delimiter $Delimiter
    }
    Else {
        Write-Host "No data returned for ExchangeItem" -ForegroundColor Yellow
    }

    # Export unified audit log for Exchange
    Write-Host "Exporting Unified Audit log for ExchangeItemGroup activity..."
    $PSMailboxData = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -ResultSize 5000 -RecordType 3 | Select-Object -ExpandProperty AuditData | Convertfrom-Json
    If ($null -ne $PSMailboxData) {
        Export-UALData -ExportDir $ExportDir -UALInput $PSMailboxData -CsvName "Unified-Auditlog-Exchange-Activity" -WorkloadType "EXO2" -AppendType "Append" -Delimiter $Delimiter
    }
    Else {
        Write-Host "No data returned for ExchangeItemGroup" -ForegroundColor Yellow
    }

    # Export unified audit log for Exchange
    Write-Host "Exporting Unified Audit log for MailSubmission activity..."
    $PSMailboxData = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -ResultSize 5000 -RecordType 29 | Select-Object -ExpandProperty AuditData | Convertfrom-Json
    If ($null -ne $PSMailboxData) {
        Export-UALData -ExportDir $ExportDir -UALInput $PSMailboxData -CsvName "Unified-Auditlog-Exchange-Activity" -WorkloadType "EXO2" -AppendType "Append" -Delimiter $Delimiter
    }
    Else {
        Write-Host "No data returned for MailSubmission" -ForegroundColor Yellow
    }


    # Export unified audit log for Onedrive
    Write-Host "Exporting Unified Audit log for Onedrive activity..."
    $UALOnedrive = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -ResultSize 5000 -RecordType 6 | Select-Object -ExpandProperty AuditData | Convertfrom-Json
    If ($null -ne $UALOnedrive) {
        Export-UALData -ExportDir $ExportDir -UALInput $UALOnedrive -CsvName "Unified-Auditlog-Onedrive-Activity" -WorkloadType "Sharepoint" -AppendType "Append" -Delimiter $Delimiter
    }
    Else {
        Write-Host "No data returned for Onedrive activity" -ForegroundColor Yellow
    }


    # Export unified audit log for New-InboxRule
    Write-Host "Exporting Unified Audit log for New-InboxRule..."
    $MailboxRules = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -ResultSize 5000 -Operations "New-InboxRule" -RecordType 1 | Select-Object -ExpandProperty AuditData | Convertfrom-Json
    If ($null -ne $MailboxRules) {
        Export-UALData -ExportDir $ExportDir -UALInput $MailboxRules -CsvName "Unified-Auditlog-New-InboxRule" -WorkloadType "EXO2" -AppendType "Append" -Delimiter $Delimiter
    }
    Else {
        Write-Host "No data returned for New-InboxRule" -ForegroundColor Yellow
    }

    # Export unified audit log for Security and Compliance data (including ediscovery events)
    Write-Host "Exporting Unified Audit log for New-InboxRule..."
    $securityCompliance = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -ResultSize 5000 -Operations Get-ComplianceCase, New-ComplianceCase, CaseAdminUpdated, ViewedSearchExported, SearchExportDownloaded, Set-RoleGroup, Update-RoleGroupMember | Select-Object -ExpandProperty AuditData | Convertfrom-Json
    If ($null -ne $securityCompliance) {
        Export-UALData -ExportDir $ExportDir -UALInput $securityCompliance -CsvName "Unified-Auditlog-eDiscovery" -WorkloadType "SecurityComplianceCenter" -AppendType "Append" -Delimiter $Delimiter
    }
    Else {
        Write-Host "No data returned for SecurityComplianceCenter" -ForegroundColor Yellow
    }

    #Searches for any OAuth or application consents
    Write-Verbose "Searching for 'Add OAuth2PermissionGrant' and 'Consent to application' in the UAL..."
    $ConsentData = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -RecordType AzureActiveDirectory -Operations "Add OAuth2PermissionGrant", "Consent to application" -ResultSize 5000 | Select-Object -ExpandProperty AuditData | Convertfrom-Json
    If ($null -ne $ConsentData) {    
        Export-UALData -ExportDir $ExportDir -UALInput $ConsentData -CsvName "Unified-Auditlog-Consent_Operations_Export" -WorkloadType "AzureApp" -AppendType "Append" -Delimiter $Delimiter
    }
    Else {
        Write-Host "No 'Add app role assignment to service principal', 'Add app role assignment grant to user', and 'Add app role assignment to group' data returned and no CSV will be produced." -ForegroundColor Yellow
    }  

    # Kod klart, addera 1. 
    $dayCounter = $dayCounter - 1
    $i++ 
}



# Call function to collect Azure sign in logs
# This only goes back 30 days! (7 days if azure basic/free)
Write-Host "Collection Azure Sign in logs, this might take a while..."
Get-AzSigninLogs

# Export Azure Application permissions 
Export-AzureAppPermissions


<#
# Scriptet loggar ut från Exchangeonline och AzureAD
Write-Host "Disconnecting from ExchangeOnline"
Disconnect-ExchangeOnline -Confirm:$false
Write-Host "Disconnecting from AzureAD"
Disconnect-AzureAD -Confirm:$false

#>