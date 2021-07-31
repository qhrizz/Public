# This is my M365 Profile
Write-Host "Loading Microsoft 365 profile from qhrizz's Github" -Foregroundcolor Green
Write-Host "Provided as is..."
Write-Host "---------------------"

Write-Host "Available functions are: " 
# Hashtable to populate available functions
$availableFunctions = @{
"Install-M365Modules" = "Installs require modules"
"Connect-M365" = "Connect to M365 with modern authentication"
"Set-MailboxPermission" = "Add mailboxpermissions for a user on a mailbox"
"Delete-MailboxPermission" = "Remove mailboxpermissions for a user on a mailbox"
"Get-MboxPermissions " = "List mailboxpermissions in a more sanitized way"
}
$availableFunctions

# List available functions again
Function Get-Functions {
    $availableFunctions
}

# Function to install the modules - This will trigger a administrative powershell prompt
Function Install-M365Modules {
    # Request administrative privileges
    ## Install Azure AD v2 Module (Also a replacement for the old MSOL module) and ExchangeOnlineManagement Module
    if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -Command `"Install-Module -Name AzureAD;Install-Module -Name ExchangeOnlineManagement;"` -Verb RunAs }
    Write-Host "Complete. You may now close this window"
}

# Function to begin the authentication process against AzureAD and Exchange online
Function Connect-M365 {
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