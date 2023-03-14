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
    "ConvertTo-Base64"      = "Encode text to base64"
    "ConvertFrom-Base64"    = "Decode text from base64"
    "Start-IntuneSync"      = "Trigger manual Intune Sync"
    "New-IsoFile"           = "Add files to an ISO"
    "New-Password"  = "Create a memorable password"
    "cOnVeRtTo-sPoNgEbOb" = "Spongebob meme text"
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
  
Function New-Password {
    <#
    .SYNOPSIS
        "Memorable" password generator for quick passwords
        Logic from https://thesysadminchannel.com/simple-random-password-generator-using-powershell but modified to use 1Passwords wordlist and adding upper character words 
     
    .NOTES
        Name: New-Password
        Author: Christian Tamm
        Version: 1.2
        DateCreated: 2022-12-30

        1.1: added clearing from clipboard (also doesnt show the password in console.)
        1.2 added clearClipboard switch
    .LINK
        https://thesysadminchannel.com/simple-random-password-generator-using-powershell 
     
    .EXAMPLE
        New-Password
        New-Password -WordCount 5
        New-Password -setClipboard -clearClipboard
    #>
    
    param(
        [Parameter(
            Mandatory = $false
        )]
        [ValidateRange(2, 20)]
        [int]   $WordCount = 3,
        [switch]$setClipBoard,
        [switch]$clearClipboard
    )
     
     
    BEGIN {
        $SpecialCharacters = @((33, 35) + (36..38) + (40..42) + (60..62) + (64))
        $Numbers = @(1..1000)
    }
     
    PROCESS {
        try {
            # Fetch wordlist from 1Password
            $Site = Invoke-WebRequest -Uri 'https://1password.com/txt/agwordlist.txt'
            $FullList = $Site.Content.Trim().split("`n")
            
            # Create a specific array depending on how many characters each word has                     
            [System.Collections.ArrayList]$3LtrWord = @()
            [System.Collections.ArrayList]$4LtrWord = @()
            [System.Collections.ArrayList]$5LtrWord = @()
            [System.Collections.ArrayList]$6LtrWord = @()
            [System.Collections.ArrayList]$7LtrWord = @()
            [System.Collections.ArrayList]$8LtrWord = @()
            [System.Collections.ArrayList]$9LtrWord = @()
     
            # Add words to their respective list depending on length
            foreach ($Word in $FullList) {
                switch ($word.Length) {
                    3 { $3LtrWord.Add($Word) | Out-Null }
                    4 { $4LtrWord.Add($Word) | Out-Null }
                    5 { $5LtrWord.Add($Word) | Out-Null }
                    6 { $6LtrWord.Add($Word) | Out-Null }
                    7 { $7LtrWord.Add($Word) | Out-Null }
                    8 { $8LtrWord.Add($Word) | Out-Null }
                    9 { $9LtrWord.Add($Word) | Out-Null }
                }
            }
     
            # Minimum 14 character password if we remove spaces and special characters
            if ($WordCount -le 3) {
                $WordList = $7LtrWord + $8LtrWord + $9LtrWord
            }
     
            if ($WordCount -eq 4) {
                $WordList = $4LtrWord + $5LtrWord + $6LtrWord + $7LtrWord
            }
     
            if ($WordCount -eq 5) {
                $WordList = $4LtrWord + $5LtrWord + $6LtrWord
            }
                 
            if ($WordCount -ge 6) {
                $WordList = $3LtrWord + $4LtrWord + $5LtrWord
            }

            # Get which words from the wordlist to use
            [System.Collections.ArrayList]$passwordArray = @()
            $i = 0
            # While the counter is less than the wordCount specified, do
            while ($i -lt $WordCount) {           
                # Grab one random word from the list
                $passPhrase = ($WordList | Get-Random -Count 1)

                # Add word to the array
                $passwordArray.Add($passPhrase) | Out-Null
                $i++ | Out-Null
            } 
            # Create a new array and add logic to append number and specialcharacter
            [System.Collections.ArrayList]$passwordArrayModify = @()
            # remove 1 from wordcount to prevent it from blocking the last word from having numbers and special character added
            $SpecialCharacterAndNumber = $WordCount - 1            
            $nrToUpper = Get-Random -Minimum 0 -Maximum ($WordCount - 1)                 
            $i = 0
            foreach ($word in $passwordArray) {
                if ($i -eq $nrToUpper) {
                    $word = $word.ToUpper()
                    $passwordArrayModify.Add($word) | Out-Null
                    $i++ | Out-Null
                }
                elseif ($i -match $SpecialCharacterAndNumber) {
                    $word = $word + ([char]($SpecialCharacters | Get-Random -Count 1)) + ($Numbers | Get-Random -Count 1)
                    $passwordArrayModify.Add($word) | Out-Null
                    $i++ | Out-Null
                }
                else {
                    $passwordArrayModify.Add($word) | Out-Null
                    $i++ | Out-Null
                }
            }
            # print the new password
            $newPassword = $passwordArrayModify -join "-"
            if($setClipBoard -eq $true -and $clearClipboard -eq $true ){
                Set-Clipboard -Value $newPassword
                for ($i = 30; $i -ge 0; $i-- ) {
                    Write-Progress -Activity "Clearing clipboard in..." -Status "$i seconds"
                    Start-Sleep -Seconds 1
                }
                $null | Set-Clipboard
            }
            elseif($setClipBoard -eq $true) {
                Set-Clipboard -Value $newPassword
            }
            else{
                Write-Host $newPassword -ForegroundColor Green
            }
        }
        catch {
            Write-Error $_.Exception.Message
        }
    }
     
    END {}
     
}


# Set Autocomplete menu 
Set-PSReadlineKeyHandler -Key Tab -Function MenuComplete 

Write-Host "---------------------"
$endText = @"
Profile loaded!
ヽ(°◇° )ノ 
"@

Write-Host $endText -ForegroundColor Green


# Function taken from https://www.reddit.com/r/PowerShell/comments/71lpdc/powershell_challenge_write_pester_tests_for_the/
Function cOnVeRtTo-sPoNgEbOb
{
    [CmdletBinding()]
    [Alias()]
    [OutputType([string])]
    Param
    (
        [Parameter(Position=0)]
        $String,
        [switch]$setClipBoard
    )

    if($Null -eq $String) 
    {
        $String = ''
    }
    if($String.gettype().Name -ne 'String')
    {
        Write-Error 'You must provide a string to convert to Spongebob case.'
    }
    $SpongeString = ''
    $Case = 'Lower'

    $String.GetEnumerator() | ForEach-Object {
        [string]$Char = $_
        Switch($Case) {
        'Lower' { $SpongeString += $Char.ToLower()
                  $Case = 'Upper'}
        'Upper' { $SpongeString += $Char.ToUpper()
                  $Case = 'Lower'}
        }  
    }
    #Output
    if($setClipBoard){
        $SpongeString | Set-Clipboard
    }
    else{
    $SpongeString 
    }
    
}