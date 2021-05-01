# Script to connect to Azure, Exchangeonline and O365

Function Connect-M365{
    Param (
        [Switch]$BasicAuth
    );
    # Check for the Azure AD,Exchange Online Management Modules and MSOnline, and install if not already available
    if (-not (Get-Module -Name ExchangeOnlineManagement)) {
        try {
            Write-Host "Installing ExchangeOnlineManagement module";
            Install-Module -Name ExchangeOnlineManagement -Force
        } catch {
            Write-Host -ForegroundColor Yellow "[!] Unable to install module ExchangeOnlineManagement. Please be sure to launch an elevated PowerShell prompt."
        }
    }
    else{
        Write-Host "Module ExchangeOnlineManagement already installed" -ForegroundColor Green
    }
    if (-not (Get-Module -Name AzureAD)) {
        try {
            Write-Host "Installing AzureAD Preview module (for the latest cmdlets)";
            Install-Module -Name AzureADPreview -Force
        } catch {
            Write-Host -ForegroundColor Yellow "[!] Unable to install module AzureAD. Please be sure to launch an elevated PowerShell prompt."
        }
    }
    else{
        Write-Host "Module AzureAD Preview already installed" -ForegroundColor Green
    }
    if (-not (Get-Module -Name MSOnline)) {
        try {
            Write-Host "Installing MSOnline module";
            Install-Module -Name MSOnline -Force
        } catch {
            Write-Host -ForegroundColor Yellow "[!] Unable to install module MSOnline. Please be sure to launch an elevated PowerShell prompt."
        }
    }
    else{
        Write-Host "Module MSOnline already installed" -ForegroundColor Green
    }
    
    #...................................
    # Authentication
    #...................................
    
    # Create a login credential variable
    if ($BasicAuth -and (-not $loginCreds)) {
        $Global:loginCreds = Get-Credential
    } elseif (-not $BasicAuth) {
        Write-Host -ForegroundColor Yellow "NOTE: Using default authentication. This method will prompt you for login credentials 3 times.";
        Start-Sleep -Seconds 5
    };
    
    Write-Host "Beginning authentication";
    Write-Host "Authenticating to Exchange Online";
    # Connect to Exchange Online
    try {
        if ($BasicAuth) {
            Connect-ExchangeOnline -Credential $loginCreds -ShowBanner:$false -ErrorAction Stop 6>$null
        } else {
            Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop 6>$null
        };
        Write-Host "Successfully connected to Exchange Online"
    } catch {
        if($_.Exception.Message -match "you have exceeded the maximum number of connections allowed"){
            try {
                Disconnect-ExchangeOnline -Confirm:$false 6>$null;
                Write-Host "Disconnected from previous Exchange Online session(s)"
            } catch {
                throw $_.Exception.Message
            };
            try {
                if ($BasicAuth) {
                    Connect-ExchangeOnline -Credential $loginCreds -ShowBanner:$false -ErrorAction Stop 6>$null
                } else {
                    Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop 6>$null
                };
                Write-Host "Successfully connected to Exchange Online"
            } catch {
                throw $_.Exception.Message
            }
        } else {
            throw $_.Exception.Message
        }
    };
    
    # Connect to Azure AD
    Write-Host "Authenticating to Azure AD";
    try {
        if ($BasicAuth) {
            $ConnectAZD = Connect-AzureAD -Credential $loginCreds -ErrorAction Stop 6>$null
        } else {
            $ConnectAZD = Connect-AzureAD -ErrorAction Stop 6>$null
        };
        Write-Host "Successfully connected to Azure AD"
    } catch {
        if($_.Exception.Message -match "you have exceeded the maximum number of connections allowed"){
            try {
                Disconnect-AzureAD | Out-Null;
                Write-Host "Disconnected from previous Azure AD session(s)"
            } catch {
                Write-Error $_.Exception.Message
            };
            try {
                if ($BasicAuth) {
                    $ConnectAZD = Connect-AzureAD -Credential $loginCreds -ErrorAction Stop 6>$null
                } else {
                    $ConnectAZD = Connect-AzureAD -ErrorAction Stop 6>$null
                };
                Write-Host "Successfully connected to Azure AD"
            } catch {
                throw $_.Exception.Message
            }
        } else {
            throw $_.Exception.Message
        }
    };

    # Connect to MSOnline
    Write-Host "Authenticating to MSOL";
    # Module is more "simple" and does not have disconnect functions. Therefore simply use it. 
    Connect-MsolService
}
