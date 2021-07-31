# This is my Powershell profile
Write-Host "Loading powershell profile from qhrizz's Github" -Foregroundcolor Green
Write-Host "Provided as is..."
Write-Host '¯\_(ツ)_/¯'
Write-Host "---------------------"


# Set oh-my-posh theme
Import-Module posh-git
Import-Module oh-my-posh
Set-PoshPrompt -Theme slimfat

<<<<<<< HEAD
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
=======

# Test function 
Function Invoke-Hello {
Write-Host "Hello $ENV:USERNAME"
Write-Host "Todays date is $date"
}


Write-Host "Profile loaded" -Foregroundcolor Green
>>>>>>> d724d9733710623d7b079c34c6d75ae5371f566b
