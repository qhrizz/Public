# This is my Powershell profile
Write-Host "Loading powershell profile from qhrizz's Github Gist" -Foregroundcolor Green
Write-Host "Provided as is..."
Write-Host "¯\_(ツ)_/¯"
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


Write-Host "Profile loaded"

Invoke-Webrequest -Uri "https://gist.githubusercontent.com/qhrizz/541f8a067fe8ec3869986949fccaa5d1/raw/ce187450ba5c69b91860d3f77ca9c96aa40dd59b/gistfile1.txt" -UseBasicParsing -OutFile C:\Temp\ps-profile.ps1 | Invoke-Expression C:\temp\ps-profile.ps1
