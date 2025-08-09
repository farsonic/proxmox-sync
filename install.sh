#!/bin/bash

# This script installs the Proxmox Sync Daemon.
# It must be run with sudo or as root.

# --- Configuration ---
INSTALL_DIR="/opt/proxmox-sync-daemon"
SCRIPT_NAME="sync_daemon.py"
CONFIG_NAME="config.json"
SERVICE_NAME="proxmox-sync-daemon"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
REQUIREMENTS_FILE="requirements.txt"

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
    local role_name="SDNSync"
    local user_name="sync-daemon@pve"
    local token_name="daemon-token"

    print_info "Attempting to create Proxmox credentials automatically..."

    # Create a dedicated role with minimal permissions
    if ! pveum role add "$role_name" -privs "Sys.Audit SDN.Audit" &>/dev/null; then
        print_warning "Role '${role_name}' may already exist. Proceeding."
    else
        print_success "Created role '${role_name}'."
    fi

    # Create a dedicated user
    # Generate a random password as it won't be used directly
    local random_pw=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 20)
    if ! pveum user add "$user_name" --password "$random_pw" &>/dev/null; then
        print_warning "User '${user_name}' may already exist. Proceeding."
    else
        print_success "Created user '${user_name}'."
    fi

    # Apply the role to the user at the root level
    pveum acl set / -user "$user_name" -role "$role_name" || print_error "Failed to set ACL for user '${user_name}'."
    print_success "Applied role '${role_name}' to user '${user_name}'."

    # Create the API token and capture its secret value
    print_info "Creating API token..."
    local token_output
    token_output=$(pveum user token add "$user_name" "$token_name" -o json) || print_error "Failed to create API token."
    
    PVE_API_USER_READ="$user_name"
    PVE_TOKEN_NAME_READ="$token_name"
    # Use python to parse the JSON output safely
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
apt-get install -y python3-pip >/dev/null || print_error "Failed to install python3-pip."

if [ -f "$REQUIREMENTS_FILE" ]; then
    pip3 install -r "$REQUIREMENTS_FILE" || print_error "Failed to install Python packages from requirements.txt."
else
    print_error "$REQUIREMENTS_FILE not found. Please make sure it's in the same directory."
fi

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

# PSM Details
read -p "Enter PSM host (IP or FQDN): " PSM_HOST
read -p "Enter PSM Username: " PSM_USER
read -sp "Enter PSM Password: " PSM_PASSWORD; echo

# AFC Details
read -p "Enter AFC host (IP or FQDN): " AFC_HOST
read -p "Enter AFC Username: " AFC_USER
read -sp "Enter AFC Password: " AFC_PASSWORD; echo
read -p "Enter AFC Fabric Names (comma-separated, e.g., DC1,DC2): " AFC_FABRIC_NAMES

# Daemon Settings
read -p "Enter Sync Poll Interval in seconds [15]: " POLL_INTERVAL
POLL_INTERVAL=${POLL_INTERVAL:-15}
read -p "Enable Dry Run Mode (no changes will be made)? [y/N]: " DRY_RUN_INPUT
DRY_RUN=$([[ "$DRY_RUN_INPUT" =~ ^[yY](es)?$ ]] && echo "true" || echo "false")

# --- Step 3: Create Installation Directory and Config File ---
print_info "Creating installation directory at ${INSTALL_DIR}..."
mkdir -p "$INSTALL_DIR" || print_error "Failed to create directory ${INSTALL_DIR}."

print_info "Generating ${CONFIG_NAME}..."
# Convert comma-separated fabric names to a JSON array
FABRIC_JSON_ARRAY=$(echo "$AFC_FABRIC_NAMES" | tr ',' '\n' | sed 's/.*/"&"/' | paste -sd, -)

cat > "${INSTALL_DIR}/${CONFIG_NAME}" << EOF
{
  "Proxmox": {
    "host": "127.0.0.1",
    "api_user_read": "${PVE_API_USER_READ}",
    "token_name_read": "${PVE_TOKEN_NAME_READ}",
    "token_secret_read": "${PVE_TOKEN_SECRET_READ}"
  },
  "PSM": {
    "host": "${PSM_HOST}",
    "user": "${PSM_USER}",
    "password": "${PSM_PASSWORD}"
  },
  "AFC": {
    "host": "${AFC_HOST}",
    "user": "${AFC_USER}",
    "password": "${AFC_PASSWORD}",
    "fabric_names": [${FABRIC_JSON_ARRAY}]
  },
  "Daemon": {
    "master_of_record": "Proxmox",
    "vrf_sync_target": "BOTH",
    "vlan_sync_target": "BOTH",
    "poll_interval_seconds": ${POLL_INTERVAL},
    "request_timeout": 10,
    "dry_run": ${DRY_RUN},
    "reserved_zone_names": [
      "default",
      "sdn"
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
ExecStart=/usr/bin/python3 ${INSTALL_DIR}/${SCRIPT_NAME}
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
