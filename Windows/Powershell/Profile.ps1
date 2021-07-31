# This is my Powershell profile
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
}
$availableFunctions

# List available functions again
Function Get-Functions {
    $availableFunctions
}


# Set oh-my-posh theme
Import-Module posh-git
Import-Module oh-my-posh
Set-PoshPrompt -Theme slimfat

# Mock function to test if the profile has loaded
Function Invoke-Hello {
    Write-Host "Hello $ENV:USERNAME"
    Write-Host "Todays date: $(Get-Date -Format ("yyyy-MM-dd"))"
    Write-Host "The time is $(Get-Date -Format ("HH:mm:ss"))"
    }
    
# Function to load Microsoft 365 profile
Function Invoke-M365Profile {
    Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/qhrizz/Public/master/Windows/Powershell/M365Profile.ps1'))
}
# Get current WAN address
Function WhatsMyIP{
    Invoke-WebRequest -Uri http://checkip.amazonaws.com/ | Select-String "[0-9]{0,3}.[0-9]{0,3}.[0-9]{0,3}.[0-9]{0,3}" | ForEach-Object {$_ -replace ("\n","")}
    }
# Show history of commands
Function gimme {
    (Get-History).CommandLine | Out-GridView
}
Write-Host "Profile loaded"
