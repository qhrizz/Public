# This is my Powershell profile hosted at Github
$introText = @"
■ Loading Powershell profile from Github
■ Provided as is...(っ▀¯▀)つ 
"@
Write-Host $introText -ForegroundColor Green # Print introtext and Stunna Shades ASCII Art :) 
Write-Host "Available functions are (list again with Get-Functions)"  -ForegroundColor Yellow
# Hashtable to populate available functions
$availableFunctions = @{
"Invoke-Hello" = "Mock function to test if the profile was loaded"
"WhatsMyIP" = "Check current WAN address using Amazon"
"gimme" = "List last used commands"
"Install-M365Modules" = "Installs require modules"
"Connect-M365" = "Connect to M365 with modern authentication"
"Set-MboxPermission" = "Add mailboxpermissions for a user on a mailbox"
"Remove-MboxPermission" = "Remove mailboxpermissions for a user on a mailbox"
"Get-MboxPermissions " = "List mailboxpermissions in a more sanitized way"
"Get-GeoJSIp" = "Get country for IP address"
"Install-Chocolatey" = "Install Chocolatey"
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
Generic functions. A mix of everything and nothing
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
    ## Install Azure AD v2 Preview Module (Also a replacement for the old MSOL module) and ExchangeOnlineManagement Module
    if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -Command `"Uninstall-Module -Name AzureAD;Install-Module -Name AzureADPreview -Scope AllUsers -v;Install-Module -Name ExchangeOnlineManagement -Scope AllUsers -v;pause"` -Verb RunAs }
}
# Function to begin the authentication process against AzureAD and Exchange online
Function Connect-M365 {
    Import-Module AzureADPreview -UseWindowsPowerShell
    Import-Module ExchangeOnlineManagement
    Write-Host "You will be prompted two times for credentials..." -ForegroundColor Yellow
    # Connect to AzureAD
    try {
        Connect-AzureAD -ErrorAction Stop 6>$null
        Write-Host "Successfully connected to AzureAD Online"
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
# Function to add mailboxpermissions for a user on a mailbox. 
Function Set-MboxPermission {
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
Function Remove-MboxPermission {
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

Function Install-Chocolatey {
    Write-Host "Installing Chocolatey. Requires elevation! "
    if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -Command `"Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))"` -Verb RunAs }
    $text = @"
Things you can install:
choco install firefox -y
choco install googlechrome -y
choco install 7zip.install -y
choco install notepadplusplus.install -y
choco install git.install -y
choco install vscode -y
choco install putty -y
choco install powershell-core -y
choco install microsoft-windows-terminal -y
"@
Write-Host $text -ForegroundColor Green
}

# Set Autocomplete menu 
Set-PSReadlineKeyHandler -Key Tab -Function MenuComplete 

Write-Host "---------------------"
$endText = @"
Profile loaded!
ヽ(°◇° )ノ 
"@

Write-Host $endText -ForegroundColor Green