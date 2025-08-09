#!/bin/bash

# This script uninstalls the Proxmox Sync Daemon.
# It must be run with sudo or as root.

# --- Configuration ---
INSTALL_DIR="/opt/proxmox-sync-daemon"
SERVICE_NAME="proxmox-sync-daemon"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
PVE_USER="sync-daemon@pve"
PVE_ROLE="SDNSync"

# --- Helper Functions ---
function print_info() {
    echo -e "\e[34m[INFO]\e[0m $1"
}

function print_success() {
    echo -e "\e[32m[SUCCESS]\e[0m $1"
}

function print_error() {
    echo -e "\e[31m[ERROR]\e[0m $1" >&2
    exit 1
}

function check_root() {
    if [[ "$EUID" -ne 0 ]]; then
        print_error "This script must be run as root. Please use sudo."
    fi
}

# --- Main Script ---
check_root

print_info "Starting Proxmox Sync Daemon uninstallation..."

# --- Step 1: Stop and Disable the Service ---
print_info "Stopping and disabling the systemd service..."
if systemctl is-active --quiet "$SERVICE_NAME"; then
    systemctl stop "$SERVICE_NAME" || print_error "Failed to stop the service."
fi
if systemctl is-enabled --quiet "$SERVICE_NAME"; then
    systemctl disable "$SERVICE_NAME" || print_error "Failed to disable the service."
fi
print_success "Service stopped and disabled."

# --- Step 2: Remove Systemd and Installation Files ---
if [ -f "$SERVICE_FILE" ]; then
    print_info "Removing systemd service file..."
    rm "$SERVICE_FILE" || print_error "Failed to remove service file."
    systemctl daemon-reload
    print_success "Service file removed."
else
    print_info "Service file not found, skipping."
fi

if [ -d "$INSTALL_DIR" ]; then
    print_info "Removing installation directory: ${INSTALL_DIR}..."
    rm -rf "$INSTALL_DIR" || print_error "Failed to remove installation directory."
    print_success "Installation directory removed."
else
    print_info "Installation directory not found, skipping."
fi

# --- Step 3: Optionally Remove Proxmox Credentials ---
read -p "Do you want to remove the Proxmox user (${PVE_USER}) and role (${PVE_ROLE})? [y/N]: " REMOVE_CREDS
if [[ "$REMOVE_CREDS" =~ ^[yY](es)?$ ]]; then
    print_info "Removing Proxmox user and role..."
    
    # The token is part of the user, so it gets deleted with the user
    if pveum user delete "$PVE_USER" &>/dev/null; then
        print_success "User '${PVE_USER}' removed."
    else
        print_info "User '${PVE_USER}' not found or could not be removed."
    fi

    if pveum role delete "$PVE_ROLE" &>/dev/null; then
        print_success "Role '${PVE_ROLE}' removed."
    else
        print_info "Role '${PVE_ROLE}' not found or could not be removed."
    fi
else
    print_info "Skipping removal of Proxmox user and role."
fi

print_success "Uninstallation complete!"
