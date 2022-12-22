#!/bin/bash

# Update
tdnf update 

# Install sudo
tdnf install sudo -y

# Install open-iscsi
tdnf install open-iscsi -y 

# Install cloud-init
tdnf install cloud-init -y 

# Clean out unique IDs
rm -rf /var/lib/cloud/instances

# Prevent duplicate DHCP addresses
truncate -s 0 /etc/machine-id
rm /var/lib/dbus/machine-id