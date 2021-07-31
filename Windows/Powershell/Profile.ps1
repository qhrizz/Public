# This is my Powershell profile
Write-Host "Loading powershell profile from qhrizz's Github Gist" -Foregroundcolor Green
Write-Host "Provided as is..."
Write-Host '¯\_(ツ)_/¯'
Write-Host "---------------------"


# Set oh-my-posh theme
Import-Module posh-git
Import-Module oh-my-posh
Set-PoshPrompt -Theme slimfat


# Test function 
Function Invoke-Hello {
Write-Host "Hello $ENV:USERNAME"
Write-Host "Todays date is $date"
}


Write-Host "Profile loaded" -Foregroundcolor Green
