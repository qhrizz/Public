# Install Chocolatey and a few basic applications

# Install Chocolatey. 
# Can be installed via GPO Script
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

# Install Firefox
choco install firefox -y 

# Install Chrome 
choco install googlechrome -y 

# Install 7zip
choco install 7zip.install -y 

# Install Notepad++
choco install notepadplusplus.install -y 

# Install Git
choco install git.install -y 

# Install VS Studio Code
choco install vscode -y 

# Install Putty
choco install putty -y 

# Install Youtube-DL
choco install youtube-dl -y 

# Install FFMPEG
choco install ffmpeg -y 

# Install ShareX
choco install sharex -y 

# Install Powershell Core
choco install powershell-core -y 

# Install Spotify
choco install spotfiy -y

# Install Steam
choco install steam -y 

