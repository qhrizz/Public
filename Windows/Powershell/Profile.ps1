# This is my Powershell profile hosted at Github
Write-Host "Loading powershell profile from qhrizz's Github" -Foregroundcolor Green
Write-Host "Provided as is..."
Write-Host '¯\_(ツ)_/¯'
Write-Host "---------------------"

Write-Host "Available functions are (list again with Get-Functions)" 
# Hashtable to populate available functions
$availableFunctions = @{
"Invoke-Hello" = "Mock function to test if the profile was loaded"
"Invoke-M365Profile" = "Load functions to install and connect to M365"
"WhatsMyIP" = "Check current WAN address using Amazon"
"gimme" = "List last used commands"
"Install-M365Modules" = "Installs require modules"
"Connect-M365" = "Connect to M365 with modern authentication"
"Set-MailboxPermission" = "Add mailboxpermissions for a user on a mailbox"
"Delete-MailboxPermission" = "Remove mailboxpermissions for a user on a mailbox"
"Get-MboxPermissions " = "List mailboxpermissions in a more sanitized way"
"Get-GeoJSIp" = "Get country for IP address"
} 
$availableFunctions.GetEnumerator() | Sort-Object -Property name 

# List available functions again
Function Get-Functions {
    $availableFunctions.GetEnumerator() | Sort-Object -Property name 
}


# Set oh-my-posh theme
Import-Module posh-git
Import-Module oh-my-posh
Set-PoshPrompt -Theme slimfat

<#
Generic functions
#>

# Mock function to test if the profile has loaded
Function Invoke-Hello {
    Write-Host "Hello $ENV:USERNAME"
    Write-Host "Todays date: $(Get-Date -Format ("yyyy-MM-dd"))"
    Write-Host "The time is $(Get-Date -Format ("HH:mm:ss"))"
    }
# Get current WAN address
Function WhatsMyIP{
    Invoke-WebRequest -Uri http://checkip.amazonaws.com/ | Select-String "[0-9]{0,3}.[0-9]{0,3}.[0-9]{0,3}.[0-9]{0,3}" | ForEach-Object {$_ -replace ("\n","")}
    }
# Show history of commands
Function gimme {
    (Get-History).CommandLine | Out-GridView
}
# Function to install the modules - This will trigger a administrative powershell prompt

<#
Microsoft 365 related functions
#>
Function Install-M365Modules {
    # Request administrative privileges
    ## Install Azure AD v2 Module (Also a replacement for the old MSOL module) and ExchangeOnlineManagement Module
    if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -Command `"Install-Module -Name AzureAD;Install-Module -Name ExchangeOnlineManagement;"` -Verb RunAs }
    Write-Host "Complete. You may now close this window"
}
# Function to begin the authentication process against AzureAD and Exchange online
Function Connect-M365 {
    Import-Module AzureAD
    Import-Module ExchangeOnlineManagement
    Write-Host "You will be prompted two times for credentials..." -ForegroundColor Yellow
    # Connect to AzureAD
    try {
        Connect-AzureAD -ErrorAction Stop 6>$null
        Write-Host "Successfully connected to Exchange Online"
    }
    catch {
        throw $_.Exception.Message
        }
     
    # Connect to ExchangeOnline
    try {
            Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop 6>$null
            Write-Host "Successfully connected to Exchange Online"
        }
        catch {
            throw $_.Exception.Message
            }
}
Function Set-MailboxPermission {
    #Funktion f�r att l�gga p� mailboxbeh�righeter. Input $user = anv�ndaren och $mailbox = delade mailboxen.
    param(
        [string]$User,
        [string]$Mailbox
        )
    Write-Host "Adding permissions for user $User on mailbox $Mailbox"
    Add-MailboxPermission -Identity $Mailbox -User $User -AccessRights Fullaccess -InheritanceType all -AutoMapping:$true
    Write-Host "Adding sendAs permission for user $User on mailbox $Mailbox"
    Add-RecipientPermission -Identity $Mailbox -AccessRights SendAs -Trustee $User -Confirm:$false
        }
# Remove mailbox permission (Unapproved verb as to not collide with the existing Remove-MailboxPermissions)
Function Delete-MailboxPermission {
param(
    [string]$User,
    [string]$Mailbox
    )
Write-Host "Removing permissions for user $User on mailbox $Mailbox"
Remove-MailboxPermission -Identity $Mailbox -User $User -Accessrights Fullaccess -Confirm:$false
}
# List mailbox permissions
Function Get-MboxPermissions {
    param(
        [string]$Mailbox
        )

Get-MailboxPermission -Identity $Mailbox | Select-Object User,Accessrights

}
# Geoip function
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
Write-Host "---------------------"
Write-Host "Profile loaded!" -ForegroundColor Green 