#!/bin/bash

# This script installs the Proxmox Sync Daemon.
# It must be run with sudo or as root.

# --- Configuration ---
INSTALL_DIR="/opt/proxmox-sync-daemon"
SCRIPT_NAME="sync_daemon.py"
CONFIG_NAME="config.json"
ENV_FILE=".env"
SERVICE_NAME="proxmox-sync-daemon"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

# --- Helper Functions ---
function print_info() {
    echo -e "\e[34m[INFO]\e[0m $1"
}

function print_success() {
    echo -e "\e[32m[SUCCESS]\e[0m $1"
}

function print_warning() {
    echo -e "\e[33m[WARNING]\e[0m $1"
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

function create_proxmox_credentials() {
    local user_name="sync-daemon@pve"
    local token_name="daemon-token"
    local role_name="PVEAuditor" # Use the built-in read-only role

    print_info "Attempting to create Proxmox credentials automatically..."

    # Create a dedicated user
    local random_pw=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 20)
    if ! pveum user add "$user_name" --password "$random_pw" &>/dev/null; then
        print_warning "User '${user_name}' may already exist. Proceeding."
    else
        print_success "Created user '${user_name}'."
    fi

    # Apply the built-in PVEAuditor role to the user at the root path.
    pveum acl modify / -user "$user_name" -role "$role_name" || print_error "Failed to set ACL for user '${user_name}'."
    print_success "Applied role '${role_name}' to user '${user_name}'."

    # First, try to remove an existing token to prevent errors on re-installation.
    pveum user token delete "$user_name" "$token_name" &>/dev/null
    print_info "Ensuring no old token exists..."

    # Create the token with Privilege Separation DISABLED
    print_info "Creating new API token with privilege separation disabled..."
    local token_output
    token_output=$(pveum user token add "$user_name" "$token_name" --privsep 0 -o json) || print_error "Failed to create API token."

    PVE_API_USER_READ="$user_name"
    PVE_TOKEN_NAME_READ="$token_name"
    PVE_TOKEN_SECRET_READ=$(echo "$token_output" | python3 -c "import sys, json; print(json.load(sys.stdin).get('value'))")

    if [ -z "$PVE_TOKEN_SECRET_READ" ] || [ "$PVE_TOKEN_SECRET_READ" == "None" ]; then
        print_error "Could not extract token secret. Please check Proxmox permissions."
    fi

    print_success "Successfully created and captured API token credentials."
}

# --- Main Script ---
check_root

print_info "Starting Proxmox Sync Daemon installation..."

# --- Step 1: Install Dependencies ---
print_info "Updating package lists and installing dependencies..."
apt-get update >/dev/null || print_error "Failed to update package lists."
apt-get install -y python3-requests >/dev/null || print_error "Failed to install the 'python3-requests' package."

# --- Step 2: Gather Configuration from User ---
print_info "Gathering configuration details..."

# Proxmox Details
read -p "Create a dedicated Proxmox API user and token automatically? (Recommended) [Y/n]: " AUTO_PVE
if [[ "$AUTO_PVE" =~ ^[nN](o)?$ ]]; then
    print_info "Manual Proxmox credential entry selected."
    read -p "Enter Proxmox read-only API User (e.g., sync-reader@pve): " PVE_API_USER_READ
    read -p "Enter Proxmox read-only Token Name: " PVE_TOKEN_NAME_READ
    read -sp "Enter Proxmox read-only Token Secret: " PVE_TOKEN_SECRET_READ; echo
else
    create_proxmox_credentials
fi

# Target Configuration
read -p "Configure Pensando PSM as a target? [Y/n]: " CONFIGURE_PSM
CONFIGURE_PSM=${CONFIGURE_PSM:-Y}
read -p "Configure Aruba Fabric Composer (AFC) as a target? [y/N]: " CONFIGURE_AFC
CONFIGURE_AFC=${CONFIGURE_AFC:-N}

if [[ ! "$CONFIGURE_PSM" =~ ^[yY](es)?$ ]] && [[ ! "$CONFIGURE_AFC" =~ ^[yY](es)?$ ]]; then
    print_error "You must configure at least one target (PSM or AFC). Aborting."
fi

PSM_HOST=""
PSM_USER=""
PSM_PASSWORD=""
if [[ "$CONFIGURE_PSM" =~ ^[yY](es)?$ ]]; then
    print_info "--- PSM Configuration ---"
    read -p "Enter PSM host (IP or FQDN): " PSM_HOST
    read -p "Enter PSM Username: " PSM_USER
    read -sp "Enter PSM Password: " PSM_PASSWORD; echo
fi

AFC_HOST=""
AFC_USER=""
AFC_PASSWORD=""
AFC_FABRIC_NAMES=""
if [[ "$CONFIGURE_AFC" =~ ^[yY](es)?$ ]]; then
    print_info "--- AFC Configuration ---"
    read -p "Enter AFC host (IP or FQDN): " AFC_HOST
    read -p "Enter AFC Username: " AFC_USER
    read -sp "Enter AFC Password: " AFC_PASSWORD; echo
    read -p "Enter AFC Fabric Names (comma-separated, e.g., DC1,DC2): " AFC_FABRIC_NAMES
fi

# --- Determine Sync Targets based on user selection ---
VRF_TARGET="NONE"
VLAN_TARGET="NONE"
if [[ "$CONFIGURE_AFC" =~ ^[yY](es)?$ ]]; then
    # If AFC is available, it becomes the primary for VRFs, and VLANs sync to both
    VRF_TARGET="AFC"
    VLAN_TARGET="BOTH"
elif [[ "$CONFIGURE_PSM" =~ ^[yY](es)?$ ]]; then
    # If only PSM is available, it is the target for both
    VRF_TARGET="PSM"
    VLAN_TARGET="PSM"
fi

# Daemon Settings
read -p "Enter Sync Poll Interval in seconds [15]: " POLL_INTERVAL
POLL_INTERVAL=${POLL_INTERVAL:-15}

read -p "Only sync VNETs with the 'orchestration' flag set? (Recommended) [Y/n]: " SYNC_ORCHESTRATED_INPUT
SYNC_ORCHESTRATED=$([[ "$SYNC_ORCHESTRATED_INPUT" =~ ^[nN](o)?$ ]] && echo "false" || echo "true")

read -p "Enable Dry Run Mode (no changes will be made)? [y/N]: " DRY_RUN_INPUT
DRY_RUN=$([[ "$DRY_RUN_INPUT" =~ ^[yY](es)?$ ]] && echo "true" || echo "false")

# --- Step 3: Create Installation Directory and Config Files ---
print_info "Creating installation directory at ${INSTALL_DIR}..."
mkdir -p "$INSTALL_DIR" || print_error "Failed to create directory ${INSTALL_DIR}."

# Create the secure environment file for passwords
print_info "Generating secure environment file for passwords..."
cat > "${INSTALL_DIR}/${ENV_FILE}" << EOF
PVE_TOKEN_SECRET_READ=${PVE_TOKEN_SECRET_READ}
PSM_PASSWORD=${PSM_PASSWORD}
AFC_PASSWORD=${AFC_PASSWORD}
EOF
chmod 600 "${INSTALL_DIR}/${ENV_FILE}" || print_error "Failed to set permissions on .env file."

# Create the main config file without passwords
print_info "Generating ${CONFIG_NAME}..."
FABRIC_JSON_ARRAY=$(echo "$AFC_FABRIC_NAMES" | tr ',' '\n' | sed 's/.*/"&"/' | paste -sd, -)

cat > "${INSTALL_DIR}/${CONFIG_NAME}" << EOF
{
  "Proxmox": {
    "host": "127.0.0.1",
    "api_user_read": "${PVE_API_USER_READ}",
    "token_name_read": "${PVE_TOKEN_NAME_READ}"
  },
  "PSM": {
    "host": "${PSM_HOST}",
    "user": "${PSM_USER}"
  },
  "AFC": {
    "host": "${AFC_HOST}",
    "user": "${AFC_USER}",
    "fabric_names": [${FABRIC_JSON_ARRAY}]
  },
  "Daemon": {
    "master_of_record": "Proxmox",
    "vrf_sync_target": "${VRF_TARGET}",
    "vlan_sync_target": "${VLAN_TARGET}",
    "poll_interval_seconds": ${POLL_INTERVAL},
    "request_timeout": 10,
    "dry_run": ${DRY_RUN},
    "sync_orchestrated_vnets_only": ${SYNC_ORCHESTRATED},
    "reserved_zone_names": [
      "default",
      "mgmt"
    ]
  }
}
EOF

# --- Step 4: Copy Script and Set Permissions ---
print_info "Copying daemon script..."
cp "$SCRIPT_NAME" "${INSTALL_DIR}/${SCRIPT_NAME}" || print_error "Failed to copy ${SCRIPT_NAME}."
chmod 755 "${INSTALL_DIR}/${SCRIPT_NAME}"

# --- Step 5: Create and Enable Systemd Service ---
print_info "Creating systemd service file at ${SERVICE_FILE}..."

cat > "$SERVICE_FILE" << EOF
[Unit]
Description=Proxmox SDN Sync Daemon
After=network-online.target

[Service]
# Load passwords securely from the environment file
EnvironmentFile=${INSTALL_DIR}/${ENV_FILE}
ExecStart=/usr/bin/python3 -u /opt/proxmox-sync-daemon/sync_daemon.py
WorkingDirectory=${INSTALL_DIR}
Restart=on-failure
RestartSec=5
User=root
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

print_info "Reloading systemd, enabling and starting the service..."
systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
systemctl start "$SERVICE_NAME"

# --- Final Step: Display Status ---
print_success "Installation complete!"
print_info "To check the status of the service, run:"
echo "systemctl status ${SERVICE_NAME}"
print_info "To view live logs, run:"
echo "journalctl -u ${SERVICE_NAME} -f"
