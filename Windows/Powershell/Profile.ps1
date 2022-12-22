# This is my Powershell profile hosted at Github
$introText = @"
■ Loading Powershell profile from Github
■ Provided as is...(っ▀¯▀)つ 
"@
Write-Host $introText -ForegroundColor Green # Print introtext and Stunna Shades ASCII Art :) 
Write-Host "Available functions are (list again with Get-Functions)"  -ForegroundColor Yellow
# Hashtable to populate available functions
$availableFunctions = @{
    "Invoke-Hello"          = "Mock function to test if the profile was loaded"
    "WhatsMyIP"             = "Check current WAN address using Amazon"
    "gimme"                 = "List last used commands"
    "Install-M365Modules"   = "Installs require modules"
    "Connect-M365"          = "Connect to M365 with modern authentication"
    "Add-MboxPermission"    = "Add mailboxpermissions for a user on a mailbox"
    "Remove-MboxPermission" = "Remove mailboxpermissions for a user on a mailbox"
    "Get-MboxPermissions "  = "List mailboxpermissions in a more sanitized way"
    "Get-GeoJSIp"           = "Get country for IP address"
    "Install-Chocolatey"    = "Install Chocolatey"
    "Stop-WSL"              = "Stop a WSL instance"
    "Start-WSL"             = "Start a WSL instance"
    "Get-WSLRunning"        = "List running WSL instances"
    "ConvertTo-Base64"      = "Encode text to base64"
    "ConvertFrom-Base64"    = "Decode text from base64"
    "Start-IntuneSync"      = "Trigger manual Intune Sync"
    "New-IsoFile"           = "Add files to an ISO"
} 
$availableFunctions.GetEnumerator() | Sort-Object -Property name 

# List available functions again
Function Get-Functions {
    $availableFunctions.GetEnumerator() | Sort-Object -Property name 
}

 
# Set oh-my-posh theme
#Import-Module posh-git
#Import-Module oh-my-posh
#Set-PoshPrompt -Theme slimfat
oh-my-posh init pwsh --config "$env:POSH_THEMES_PATH\slimfat.omp.json" | Invoke-Expression

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
Function WhatsMyIP {
    Invoke-WebRequest -Uri http://checkip.amazonaws.com/ | Select-String "[0-9]{0,3}.[0-9]{0,3}.[0-9]{0,3}.[0-9]{0,3}" | ForEach-Object { $_ -replace ("\n", "") }
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
    if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        try {
            Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -Command `"Uninstall-Module -Name AzureAD;Install-Module -Name AzureADPreview -Scope AllUsers -v;Install-Module -Name ExchangeOnlineManagement -Scope AllUsers -v;pause"` -Verb RunAs 
        }
        catch {
            throw $_.Exception.Message
        }
        
    }
    else {
        try {
            Uninstall-Module -Name AzureAD; Install-Module -Name AzureADPreview -Scope AllUsers -v; Install-Module -Name ExchangeOnlineManagement -Scope AllUsers -v
        }
        catch {
            throw $_.Exception.Message
        }
    }
}
# Function to begin the authentication process against AzureAD and Exchange online
Function Connect-M365 {
    Write-Host "You will be prompted two times for credentials..." -ForegroundColor Yellow
    # Connect to AzureAD and ExchangeOnline
    try {
        # Handle if the script runs in Powershell 7, this requires -UseWindowsPowershell
        if ($PSVersionTable.psversion.Major -eq "7") {
            Write-Host "Detected PS7/Core - Using '-UseWindowsPowerShell'" -ForegroundColor Yellow
            Import-Module AzureADPreview -UseWindowsPowerShell
        }
        # Probably < Powershell 7, import normally. 
        else {
            Import-Module AzureADPreview
        }
        Import-Module ExchangeOnlineManagement
        Connect-AzureAD -ErrorAction Stop 6>$null
        Write-Host "Successfully connected to AzureAD Online"
        Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop 6>$null
        Write-Host "Successfully connected to Exchange Online"
    }
    catch {
        throw $_.Exception.Message
    }
}
# Function to add mailboxpermissions for a user on a mailbox. 
Function Add-MboxPermission {
    param(
        [string]$User,
        [string]$Mailbox
    )
    Write-Host "Adding permissions for user $User on mailbox $Mailbox"
    Add-MailboxPermission -Identity $Mailbox -User $User -AccessRights Fullaccess -InheritanceType all -AutoMapping:$true
    Write-Host "Adding sendAs permission for user $User on mailbox $Mailbox"
    Add-RecipientPermission -Identity $Mailbox -AccessRights SendAs -Trustee $User -Confirm:$false
}
# Remove mailbox permission
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
    (Get-MailboxPermission -Identity $Mailbox).User | Select-String "@"
}
# Geoip function
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

Function Install-Chocolatey {
    Write-Host "Installing Chocolatey. Requires elevation! "
    try {
        if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { 
            Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -Command `"Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))"` -Verb RunAs 
        }
        else {
            Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
        }
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
    catch {
        throw $_.Exception.Message
    }
}
# Stop WSL instance
# Functions to manage WSL instances
Function Stop-WSL {
    param(
        [string]$instance
    )
    wsl --terminate $instance
}
# Start a WSL instance
Function Start-WSL {
    param(
        [string]$instance
    )
    wsl -d $instance
}
# List all running instances
Function Get-WSLRunning {
    wsl --list --running --quiet
}
# List all instances
Function Get-WSLInstances {
    wsl -l -v
}

Function ConvertTo-Base64 {
    Param(
        [string]$text
    )
    # Convert to Bytes
    $Bytes = [System.Text.Encoding]::Unicode.GetBytes($text)
    # Convert to Base64
    [Convert]::ToBase64String($Bytes)
}

Function ConvertFrom-Base64 {
    Param(
        [string]$encodedtext
    )
    # Revert from Base64 to Text
    [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($EncodedText))
}

# Function to trigger Intune sync from a client manually. This simply triggers the scheduled task that is installed when enrolling. 
Function Start-IntuneSync {
    Write-Host "Triggering Intune Sync via Scheduled Task"
    
    try {
        if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { 
            Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -Command `"Get-ScheduledTask | Where-Object {$_.TaskName -eq 'PushLaunch'} | Start-ScheduledTask -Verbose"` -Verb RunAs 
        }
        else {
            Get-ScheduledTask | Where-Object { $_.TaskName -eq 'PushLaunch' } | Start-ScheduledTask -Verbose
        }
    }
    catch {
        throw $_.Exception.Message
    }
}

# Function to create an ISO file from an input
# Get-Item C:\Path\To\File.exe | New-IsoFile -Path C:\temp\myexe.iso
# Get-ChildItem C:\Path\ | New-IsoFile -Path C:\temp\myiso.iso 
Function New-IsoFile {  

    [CmdletBinding(DefaultParameterSetName = 'Source')]Param( 
        [parameter(Position = 1, Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = 'Source')]$Source,  
        [parameter(Position = 2)][string]$Path = "$env:temp\$((Get-Date).ToString('yyyyMMdd-HHmmss.ffff')).iso",  
        [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })][string]$BootFile = $null, 
        [ValidateSet('CDR', 'CDRW', 'DVDRAM', 'DVDPLUSR', 'DVDPLUSRW', 'DVDPLUSR_DUALLAYER', 'DVDDASHR', 'DVDDASHRW', 'DVDDASHR_DUALLAYER', 'DISK', 'DVDPLUSRW_DUALLAYER', 'BDR', 'BDRE')][string] $Media = 'DVDPLUSRW_DUALLAYER', 
        [string]$Title = (Get-Date).ToString("yyyyMMdd-HHmmss.ffff"),  
        [switch]$Force, 
        [parameter(ParameterSetName = 'Clipboard')][switch]$FromClipboard 
    ) 
  
    Begin {  
    ($cp = new-object System.CodeDom.Compiler.CompilerParameters).CompilerOptions = '/unsafe' 
        if (!('ISOFile' -as [type])) {  
            Add-Type -CompilerParameters $cp -TypeDefinition @'
public class ISOFile  
{ 
  public unsafe static void Create(string Path, object Stream, int BlockSize, int TotalBlocks)  
  {  
    int bytes = 0;  
    byte[] buf = new byte[BlockSize];  
    var ptr = (System.IntPtr)(&bytes);  
    var o = System.IO.File.OpenWrite(Path);  
    var i = Stream as System.Runtime.InteropServices.ComTypes.IStream;  
   
    if (o != null) { 
      while (TotalBlocks-- > 0) {  
        i.Read(buf, BlockSize, ptr); o.Write(buf, 0, bytes);  
      }  
      o.Flush(); o.Close();  
    } 
  } 
}  
'@  
        } 
   
        if ($BootFile) { 
            if ('BDR', 'BDRE' -contains $Media) { 
                Write-Warning "Bootable image doesn't seem to work with media type $Media" 
            } 
      ($Stream = New-Object -ComObject ADODB.Stream -Property @{Type = 1 }).Open()  # adFileTypeBinary 
            $Stream.LoadFromFile((Get-Item -LiteralPath $BootFile).Fullname) 
      ($Boot = New-Object -ComObject IMAPI2FS.BootOptions).AssignBootImage($Stream) 
        } 
  
        $MediaType = @('UNKNOWN', 'CDROM', 'CDR', 'CDRW', 'DVDROM', 'DVDRAM', 'DVDPLUSR', 'DVDPLUSRW', 'DVDPLUSR_DUALLAYER', 'DVDDASHR', 'DVDDASHRW', 'DVDDASHR_DUALLAYER', 'DISK', 'DVDPLUSRW_DUALLAYER', 'HDDVDROM', 'HDDVDR', 'HDDVDRAM', 'BDROM', 'BDR', 'BDRE') 
  
        Write-Verbose -Message "Selected media type is $Media with value $($MediaType.IndexOf($Media))"
    ($Image = New-Object -com IMAPI2FS.MsftFileSystemImage -Property @{VolumeName = $Title }).ChooseImageDefaultsForMediaType($MediaType.IndexOf($Media)) 
   
        if (!($Target = New-Item -Path $Path -ItemType File -Force:$Force -ErrorAction SilentlyContinue)) {
            Write-Error -Message "Cannot create file $Path. Use -Force parameter to overwrite if the target file already exists."; break 
        } 
    }  
  
    Process { 
        if ($FromClipboard) { 
            if ($PSVersionTable.PSVersion.Major -lt 5) { 
                Write-Error -Message 'The -FromClipboard parameter is only supported on PowerShell v5 or higher'; break 
            } 
            $Source = Get-Clipboard -Format FileDropList 
        } 
  
        foreach ($item in $Source) { 
            if ($item -isnot [System.IO.FileInfo] -and $item -isnot [System.IO.DirectoryInfo]) { 
                $item = Get-Item -LiteralPath $item
            } 
  
            if ($item) { 
                Write-Verbose -Message "Adding item to the target image: $($item.FullName)"
                try { 
                    $Image.Root.AddTree($item.FullName, $true) 
                } 
                catch {
                    Write-Error -Message ($_.Exception.Message.Trim() + ' Try a different media type.')
                } 
            } 
        } 
    } 
  
    End {  
        if ($Boot) {
            $Image.BootImageOptions = $Boot 
        }  
        $Result = $Image.CreateResultImage()  
        [ISOFile]::Create($Target.FullName, $Result.ImageStream, $Result.BlockSize, $Result.TotalBlocks) 
        Write-Verbose -Message "Target image ($($Target.FullName)) has been created"
        $Target
    } 
} 
  
# Set Autocomplete menu 
Set-PSReadlineKeyHandler -Key Tab -Function MenuComplete 

Write-Host "---------------------"
$endText = @"
Profile loaded!
ヽ(°◇° )ノ 
"@

Write-Host $endText -ForegroundColor Green
# This is my Powershell profile hosted at Github
$introText = @"
■ Loading Powershell profile from Github
■ Provided as is...(っ▀¯▀)つ 
"@
Write-Host $introText -ForegroundColor Green # Print introtext and Stunna Shades ASCII Art :) 
Write-Host "Available functions are (list again with Get-Functions)"  -ForegroundColor Yellow
# Hashtable to populate available functions
$availableFunctions = @{
    "Invoke-Hello"          = "Mock function to test if the profile was loaded"
    "WhatsMyIP"             = "Check current WAN address using Amazon"
    "gimme"                 = "List last used commands"
    "Install-M365Modules"   = "Installs require modules"
    "Connect-M365"          = "Connect to M365 with modern authentication"
    "Add-MboxPermission"    = "Add mailboxpermissions for a user on a mailbox"
    "Remove-MboxPermission" = "Remove mailboxpermissions for a user on a mailbox"
    "Get-MboxPermissions "  = "List mailboxpermissions in a more sanitized way"
    "Get-GeoJSIp"           = "Get country for IP address"
    "Install-Chocolatey"    = "Install Chocolatey"
    "Stop-WSL"              = "Stop a WSL instance"
    "Start-WSL"             = "Start a WSL instance"
    "Get-WSLRunning"        = "List running WSL instances"
    "ConvertTo-Base64"      = "Encode text to base64"
    "ConvertFrom-Base64"    = "Decode text from base64"
    "Start-IntuneSync"      = "Trigger manual Intune Sync"
    "New-IsoFile"           = "Add files to an ISO"
    "New-SWRandomPassword"  = "Create a random password `nNew-SWRandomPassword -MinPasswordLength 15 -MaxPasswordLength 20 -Count 1"
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
Function WhatsMyIP {
    Invoke-WebRequest -Uri http://checkip.amazonaws.com/ | Select-String "[0-9]{0,3}.[0-9]{0,3}.[0-9]{0,3}.[0-9]{0,3}" | ForEach-Object { $_ -replace ("\n", "") }
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
    if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        try {
            Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -Command `"Uninstall-Module -Name AzureAD;Install-Module -Name AzureADPreview -Scope AllUsers -v;Install-Module -Name ExchangeOnlineManagement -Scope AllUsers -v;pause"` -Verb RunAs 
        }
        catch {
            throw $_.Exception.Message
        }
        
    }
    else {
        try {
            Uninstall-Module -Name AzureAD; Install-Module -Name AzureADPreview -Scope AllUsers -v; Install-Module -Name ExchangeOnlineManagement -Scope AllUsers -v
        }
        catch {
            throw $_.Exception.Message
        }
    }
}
# Function to begin the authentication process against AzureAD and Exchange online
Function Connect-M365 {
    Write-Host "You will be prompted two times for credentials..." -ForegroundColor Yellow
    # Connect to AzureAD and ExchangeOnline
    try {
        # Handle if the script runs in Powershell 7, this requires -UseWindowsPowershell
        if ($PSVersionTable.psversion.Major -eq "7") {
            Write-Host "Detected PS7/Core - Using '-UseWindowsPowerShell'" -ForegroundColor Yellow
            Import-Module AzureADPreview -UseWindowsPowerShell
        }
        # Probably < Powershell 7, import normally. 
        else {
            Import-Module AzureADPreview
        }
        Import-Module ExchangeOnlineManagement
        Connect-AzureAD -ErrorAction Stop 6>$null
        Write-Host "Successfully connected to AzureAD Online"
        Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop 6>$null
        Write-Host "Successfully connected to Exchange Online"
    }
    catch {
        throw $_.Exception.Message
    }
}
# Function to add mailboxpermissions for a user on a mailbox. 
Function Add-MboxPermission {
    param(
        [string]$User,
        [string]$Mailbox
    )
    Write-Host "Adding permissions for user $User on mailbox $Mailbox"
    Add-MailboxPermission -Identity $Mailbox -User $User -AccessRights Fullaccess -InheritanceType all -AutoMapping:$true
    Write-Host "Adding sendAs permission for user $User on mailbox $Mailbox"
    Add-RecipientPermission -Identity $Mailbox -AccessRights SendAs -Trustee $User -Confirm:$false
}
# Remove mailbox permission
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
    (Get-MailboxPermission -Identity $Mailbox).User | Select-String "@"
}
# Geoip function
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

Function Install-Chocolatey {
    Write-Host "Installing Chocolatey. Requires elevation! "
    try {
        if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { 
            Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -Command `"Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))"` -Verb RunAs 
        }
        else {
            Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
        }
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
    catch {
        throw $_.Exception.Message
    }
}
# Stop WSL instance
# Functions to manage WSL instances
Function Stop-WSL {
    param(
        [string]$instance
    )
    wsl --terminate $instance
}
# Start a WSL instance
Function Start-WSL {
    param(
        [string]$instance
    )
    wsl -d $instance
}
# List all running instances
Function Get-WSLRunning {
    wsl --list --running --quiet
}
# List all instances
Function Get-WSLInstances {
    wsl -l -v
}

Function ConvertTo-Base64 {
    Param(
        [string]$text
    )
    # Convert to Bytes
    $Bytes = [System.Text.Encoding]::Unicode.GetBytes($text)
    # Convert to Base64
    [Convert]::ToBase64String($Bytes)
}

Function ConvertFrom-Base64 {
    Param(
        [string]$encodedtext
    )
    # Revert from Base64 to Text
    [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($EncodedText))
}

# Function to trigger Intune sync from a client manually. This simply triggers the scheduled task that is installed when enrolling. 
Function Start-IntuneSync {
    Write-Host "Triggering Intune Sync via Scheduled Task"
    
    try {
        if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { 
            Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -Command `"Get-ScheduledTask | Where-Object {$_.TaskName -eq 'PushLaunch'} | Start-ScheduledTask -Verbose"` -Verb RunAs 
        }
        else {
            Get-ScheduledTask | Where-Object { $_.TaskName -eq 'PushLaunch' } | Start-ScheduledTask -Verbose
        }
    }
    catch {
        throw $_.Exception.Message
    }
}

# Function to create an ISO file from an input
# Get-Item C:\Path\To\File.exe | New-IsoFile -Path C:\temp\myexe.iso
# Get-ChildItem C:\Path\ | New-IsoFile -Path C:\temp\myiso.iso 
Function New-IsoFile {  

    [CmdletBinding(DefaultParameterSetName = 'Source')]Param( 
        [parameter(Position = 1, Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = 'Source')]$Source,  
        [parameter(Position = 2)][string]$Path = "$env:temp\$((Get-Date).ToString('yyyyMMdd-HHmmss.ffff')).iso",  
        [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })][string]$BootFile = $null, 
        [ValidateSet('CDR', 'CDRW', 'DVDRAM', 'DVDPLUSR', 'DVDPLUSRW', 'DVDPLUSR_DUALLAYER', 'DVDDASHR', 'DVDDASHRW', 'DVDDASHR_DUALLAYER', 'DISK', 'DVDPLUSRW_DUALLAYER', 'BDR', 'BDRE')][string] $Media = 'DVDPLUSRW_DUALLAYER', 
        [string]$Title = (Get-Date).ToString("yyyyMMdd-HHmmss.ffff"),  
        [switch]$Force, 
        [parameter(ParameterSetName = 'Clipboard')][switch]$FromClipboard 
    ) 
  
    Begin {  
    ($cp = new-object System.CodeDom.Compiler.CompilerParameters).CompilerOptions = '/unsafe' 
        if (!('ISOFile' -as [type])) {  
            Add-Type -CompilerParameters $cp -TypeDefinition @'
public class ISOFile  
{ 
  public unsafe static void Create(string Path, object Stream, int BlockSize, int TotalBlocks)  
  {  
    int bytes = 0;  
    byte[] buf = new byte[BlockSize];  
    var ptr = (System.IntPtr)(&bytes);  
    var o = System.IO.File.OpenWrite(Path);  
    var i = Stream as System.Runtime.InteropServices.ComTypes.IStream;  
   
    if (o != null) { 
      while (TotalBlocks-- > 0) {  
        i.Read(buf, BlockSize, ptr); o.Write(buf, 0, bytes);  
      }  
      o.Flush(); o.Close();  
    } 
  } 
}  
'@  
        } 
   
        if ($BootFile) { 
            if ('BDR', 'BDRE' -contains $Media) { 
                Write-Warning "Bootable image doesn't seem to work with media type $Media" 
            } 
      ($Stream = New-Object -ComObject ADODB.Stream -Property @{Type = 1 }).Open()  # adFileTypeBinary 
            $Stream.LoadFromFile((Get-Item -LiteralPath $BootFile).Fullname) 
      ($Boot = New-Object -ComObject IMAPI2FS.BootOptions).AssignBootImage($Stream) 
        } 
  
        $MediaType = @('UNKNOWN', 'CDROM', 'CDR', 'CDRW', 'DVDROM', 'DVDRAM', 'DVDPLUSR', 'DVDPLUSRW', 'DVDPLUSR_DUALLAYER', 'DVDDASHR', 'DVDDASHRW', 'DVDDASHR_DUALLAYER', 'DISK', 'DVDPLUSRW_DUALLAYER', 'HDDVDROM', 'HDDVDR', 'HDDVDRAM', 'BDROM', 'BDR', 'BDRE') 
  
        Write-Verbose -Message "Selected media type is $Media with value $($MediaType.IndexOf($Media))"
    ($Image = New-Object -com IMAPI2FS.MsftFileSystemImage -Property @{VolumeName = $Title }).ChooseImageDefaultsForMediaType($MediaType.IndexOf($Media)) 
   
        if (!($Target = New-Item -Path $Path -ItemType File -Force:$Force -ErrorAction SilentlyContinue)) {
            Write-Error -Message "Cannot create file $Path. Use -Force parameter to overwrite if the target file already exists."; break 
        } 
    }  
  
    Process { 
        if ($FromClipboard) { 
            if ($PSVersionTable.PSVersion.Major -lt 5) { 
                Write-Error -Message 'The -FromClipboard parameter is only supported on PowerShell v5 or higher'; break 
            } 
            $Source = Get-Clipboard -Format FileDropList 
        } 
  
        foreach ($item in $Source) { 
            if ($item -isnot [System.IO.FileInfo] -and $item -isnot [System.IO.DirectoryInfo]) { 
                $item = Get-Item -LiteralPath $item
            } 
  
            if ($item) { 
                Write-Verbose -Message "Adding item to the target image: $($item.FullName)"
                try { 
                    $Image.Root.AddTree($item.FullName, $true) 
                } 
                catch {
                    Write-Error -Message ($_.Exception.Message.Trim() + ' Try a different media type.')
                } 
            } 
        } 
    } 
  
    End {  
        if ($Boot) {
            $Image.BootImageOptions = $Boot 
        }  
        $Result = $Image.CreateResultImage()  
        [ISOFile]::Create($Target.FullName, $Result.ImageStream, $Result.BlockSize, $Result.TotalBlocks) 
        Write-Verbose -Message "Target image ($($Target.FullName)) has been created"
        $Target
    } 
} 

function New-SWRandomPassword {
    <#
    .Synopsis
       Generates one or more complex passwords designed to fulfill the requirements for Active Directory
    .DESCRIPTION
       Generates one or more complex passwords designed to fulfill the requirements for Active Directory
    .EXAMPLE
       New-SWRandomPassword
       C&3SX6Kn

       Will generate one password with a length between 8  and 12 chars.
    .EXAMPLE
       New-SWRandomPassword -MinPasswordLength 8 -MaxPasswordLength 12 -Count 4
       7d&5cnaB
       !Bh776T"Fw
       9"C"RxKcY
       %mtM7#9LQ9h

       Will generate four passwords, each with a length of between 8 and 12 chars.
    .EXAMPLE
       New-SWRandomPassword -InputStrings abc, ABC, 123 -PasswordLength 4
       3ABa

       Generates a password with a length of 4 containing atleast one char from each InputString
    .EXAMPLE
       New-SWRandomPassword -InputStrings abc, ABC, 123 -PasswordLength 4 -FirstChar abcdefghijkmnpqrstuvwxyzABCEFGHJKLMNPQRSTUVWXYZ
       3ABa

       Generates a password with a length of 4 containing atleast one char from each InputString that will start with a letter from 
       the string specified with the parameter FirstChar
    .OUTPUTS
       [String]
    .NOTES
       Written by Simon Wåhlin, blog.simonw.se
       I take no responsibility for any issues caused by this script.
    .FUNCTIONALITY
       Generates random passwords
    .LINK
       http://blog.simonw.se/powershell-generating-random-password-for-active-directory/
   
    #>
    [CmdletBinding(DefaultParameterSetName='FixedLength',ConfirmImpact='None')]
    [OutputType([String])]
    Param
    (
        # Specifies minimum password length
        [Parameter(Mandatory=$false,
                   ParameterSetName='RandomLength')]
        [ValidateScript({$_ -gt 0})]
        [Alias('Min')] 
        [int]$MinPasswordLength = 8,
        
        # Specifies maximum password length
        [Parameter(Mandatory=$false,
                   ParameterSetName='RandomLength')]
        [ValidateScript({
                if($_ -ge $MinPasswordLength){$true}
                else{Throw 'Max value cannot be lesser than min value.'}})]
        [Alias('Max')]
        [int]$MaxPasswordLength = 12,

        # Specifies a fixed password length
        [Parameter(Mandatory=$false,
                   ParameterSetName='FixedLength')]
        [ValidateRange(1,2147483647)]
        [int]$PasswordLength = 8,
        
        # Specifies an array of strings containing charactergroups from which the password will be generated.
        # At least one char from each group (string) will be used.
        [String[]]$InputStrings = @('abcdefghijkmnpqrstuvwxyz', 'ABCEFGHJKLMNPQRSTUVWXYZ', '23456789', '!#%&'),

        # Specifies a string containing a character group from which the first character in the password will be generated.
        # Useful for systems which requires first char in password to be alphabetic.
        [String] $FirstChar,
        
        # Specifies number of passwords to generate.
        [ValidateRange(1,2147483647)]
        [int]$Count = 1
    )
    Begin {
        Function Get-Seed{
            # Generate a seed for randomization
            $RandomBytes = New-Object -TypeName 'System.Byte[]' 4
            $Random = New-Object -TypeName 'System.Security.Cryptography.RNGCryptoServiceProvider'
            $Random.GetBytes($RandomBytes)
            [BitConverter]::ToUInt32($RandomBytes, 0)
        }
    }
    Process {
        For($iteration = 1;$iteration -le $Count; $iteration++){
            $Password = @{}
            # Create char arrays containing groups of possible chars
            [char[][]]$CharGroups = $InputStrings

            # Create char array containing all chars
            $AllChars = $CharGroups | ForEach-Object {[Char[]]$_}

            # Set password length
            if($PSCmdlet.ParameterSetName -eq 'RandomLength')
            {
                if($MinPasswordLength -eq $MaxPasswordLength) {
                    # If password length is set, use set length
                    $PasswordLength = $MinPasswordLength
                }
                else {
                    # Otherwise randomize password length
                    $PasswordLength = ((Get-Seed) % ($MaxPasswordLength + 1 - $MinPasswordLength)) + $MinPasswordLength
                }
            }

            # If FirstChar is defined, randomize first char in password from that string.
            if($PSBoundParameters.ContainsKey('FirstChar')){
                $Password.Add(0,$FirstChar[((Get-Seed) % $FirstChar.Length)])
            }
            # Randomize one char from each group
            Foreach($Group in $CharGroups) {
                if($Password.Count -lt $PasswordLength) {
                    $Index = Get-Seed
                    While ($Password.ContainsKey($Index)){
                        $Index = Get-Seed                        
                    }
                    $Password.Add($Index,$Group[((Get-Seed) % $Group.Count)])
                }
            }

            # Fill out with chars from $AllChars
            for($i=$Password.Count;$i -lt $PasswordLength;$i++) {
                $Index = Get-Seed
                While ($Password.ContainsKey($Index)){
                    $Index = Get-Seed                        
                }
                $Password.Add($Index,$AllChars[((Get-Seed) % $AllChars.Count)])
            }
            Write-Output -InputObject $(-join ($Password.GetEnumerator() | Sort-Object -Property Name | Select-Object -ExpandProperty Value))
        }
    }
}


# Set Autocomplete menu 
Set-PSReadlineKeyHandler -Key Tab -Function MenuComplete 

Write-Host "---------------------"
$endText = @"
Profile loaded!
ヽ(°◇° )ノ 
"@

Write-Host $endText -ForegroundColor Green
