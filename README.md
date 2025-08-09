
# Proxmox SDN Sync Daemon

This project provides a Python daemon to synchronize network configurations (VRFs/Zones and VLANs/Vnets) from a Proxmox VE cluster to other network controllers. It is designed to run as a systemd service directly on a Proxmox host. The primary goal is to use Proxmox as the single source of truth for network definitions, and have those definitions automatically pushed to other systems.

# Supported Sync Targets:

* Pensando PSM: Pushes Proxmox Zones as Virtual Routers and Vnets as Networks.
* Aruba Fabric Composer (AFC): Pushes Proxmox Zones as VRFs and Vnets as VLANs.

# Disclaimer

This is an automation tool that makes changes to your network infrastructure. Use it at your own risk.

* It is strongly recommended to test this daemon in a non-production lab environment before deploying it in a live environment.
* The authors of this script are not responsible for any outages, misconfigurations, or data loss that may occur as a result of using this software.
* Always ensure you have backups of your Proxmox, PSM, and AFC configurations before running this tool.
* This software is provided "as is", without warranty of any kind.

# Prerequisites

1. Before running the installer, ensure you have the following:
Administrative Access: Root or sudo access to the Proxmox host where you will run the daemon. This is required for the installer to create the necessary user, role, and API token within Proxmox.
2. Python 3 & Pip: Python 3 should be installed by default on Proxmox. The installer will ensure the requests library is installed via apt.
3. API Credentials for Target Systems:
* Pensando PSM: A user and password with permissions to create/delete Virtual Routers and Networks.
* Aruba AFC: A user and password with permissions to create/delete VRFs and VLANs.

# Installation

To install the daemon, clone this repository or download the files to your Proxmox host. Then, make the installer executable and run it.

```
# Example: Clone from GitHub

git clone https://github.com/farsonic/proxmox-sync
cd proxmox-sync-daemon

# Make the installer executable
chmod +x install.sh

# Run the installer with sudo
bash ./install.sh
```

The installer will guide you through the following steps:
*  Install necessary software dependencies.*
*  Automatically create a dedicated, low-privilege Proxmox user (sync-daemon@pve) and an API token.
*  Prompt you for API credentials for your target systems (PSM, AFC).
*  Create a secure environment file for passwords and a config.json for other settings.
*  Create a systemd service to run the script as a daemon.
*  Start and enable the service.

# Automated Proxmox Credential Creation

The installer automates the creation of a secure, read-only user for the daemon. It creates:
* User: sync-daemon@pve with the built-in PVEAuditor role.
* API Token: A dedicated token for this user with privilege separation disabled to ensure it inherits the correct permissions.

This ensures the daemon runs with the minimum permissions required.

# Managing the Daemon

Once installed, you can manage the daemon using standard systemctl commands.

* Check the status of the service:
```systemctl status proxmox-sync-daemon```


* View the logs in real-time:
```journalctl -u proxmox-sync-daemon -f```


* Stop the service:
```systemctl stop proxmox-sync-daemon```


* Start the service:
```systemctl start proxmox-sync-daemon```


* Restart the service (e.g., after changing the config):
```systemctl restart proxmox-sync-daemon```


# Uninstallation

To completely remove the daemon from your system, run the uninstall.sh script.
```
# Make the uninstaller executable
chmod +x uninstall.sh

# Run the uninstaller with sudo
sudo ./uninstall.sh
```

The script will stop the service and remove all related files. It will also prompt you if you wish to remove the sync-daemon@pve user and its API token from Proxmox.

# Configuration

The main configuration is stored in ```/opt/proxmox-sync-daemon/config.json``` Passwords and secrets are stored separately in ```/opt/proxmox-sync-daemon/.env``` If you need to change any settings after installation, you can edit these files and then restart the service.


