# This is my Powershell profile hosted at Github
$introText = @"
Loading Powershell profile from Github
"@
Write-Host $introText -ForegroundColor Green 

# Hashtable to populate available functions
$availableFunctions = @{
    "Invoke-Hello"          = "Mock function to test if the profile was loaded"
    "WhatsMyIP"             = "Check current WAN address using Amazon"
    "Start-IntuneSync"      = "Trigger manual Intune Sync"
    "New-Password"  = "Create a memorable password"
    "cOnVeRtTo-sPoNgEbOb" = "Spongebob meme text"
} 
$availableFunctions.GetEnumerator() | Sort-Object -Property name 

# List available functions again
Function Get-Functions {
    $availableFunctions.GetEnumerator() | Sort-Object -Property name 
}

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
            # $Site = Invoke-WebRequest -Uri 'https://1password.com/txt/agwordlist.txt'
            $Site = Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/qhrizz/Public/master/agwordlist.txt'
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

# Set Autocomplete menu 
Set-PSReadlineKeyHandler -Key Tab -Function MenuComplete 

Write-Host $endText -ForegroundColor Green


