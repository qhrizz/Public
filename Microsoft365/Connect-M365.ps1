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