# Download the Microsoft repository GPG keys
wget -q https://packages.microsoft.com/config/ubuntu/18.04/packages-microsoft-prod.deb

# Register the Microsoft repository GPG keys
dpkg -i packages-microsoft-prod.deb

# Enable the "universe" repositories
add-apt-repository universe

apt-get update

# Install PowerShell
apt-get install -y powershell
