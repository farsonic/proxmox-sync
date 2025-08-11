#!/usr/bin/env python3
import requests
import json
import warnings
import time
import sys
import urllib3
import os # Import the os module to access environment variables

# Suppress InsecureRequestWarning: Unverified HTTPS request is being made
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# --- Configuration Loader ---

def load_config():
    """Loads settings from the config.json file."""
    try:
        with open('config.json', 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        print("[FATAL ERROR] config.json not found. Please create it.")
        sys.exit(1)
    except json.JSONDecodeError:
        print("[FATAL ERROR] config.json is not valid JSON. Please check its format.")
        sys.exit(1)

# Load config globally so all functions can access it
config = load_config()

# --- AFC API Functions ---

def get_afc_token(session):
    afc_config = config['AFC']
    # Read password from environment variable
    afc_password = os.environ.get('AFC_PASSWORD')
    if not afc_password:
        print("[ERROR] AFC_PASSWORD environment variable not set.")
        return None

    req_timeout = config['Daemon']['request_timeout']
    auth_url = f"https://{afc_config['host']}/api/v1/auth/token"
    auth_headers = {'X-Auth-Username': afc_config['user'], 'X-Auth-Password': afc_password}
    try:
        response = session.post(auth_url, headers=auth_headers, verify=False, timeout=req_timeout)
        response.raise_for_status()
        return response.json().get('result')
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] AFC Authentication failed: {e}")
        return None

def lookup_fabric_uuids(session, token):
    afc_config = config['AFC']
    req_timeout = config['Daemon']['request_timeout']
    fabrics_url = f"https://{afc_config['host']}/api/v1/fabrics"
    headers = {'Authorization': f'Bearer {token}', 'Accept': 'application/json;version=1.0'}
    print("--> Looking up AFC Fabric UUIDs...")
    try:
        response = session.get(fabrics_url, headers=headers, verify=False, timeout=req_timeout)
        response.raise_for_status()
        all_fabrics = response.json().get('result', [])
        name_to_uuid = {fabric['name']: fabric['uuid'] for fabric in all_fabrics}
        found_uuids = {}
        for name in afc_config['fabric_names']:
            if name in name_to_uuid:
                found_uuids[name] = name_to_uuid[name]
                print(f"    Found '{name}' -> {name_to_uuid[name][:8]}...")
            else:
                print(f"    [ERROR] Fabric with name '{name}' not found in AFC.")
        return found_uuids
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Could not look up AFC Fabrics: {e}")
        return {}

def get_afc_vrfs(session, token, fabric_uuid):
    req_timeout = config['Daemon']['request_timeout']
    vrfs_url = f"https://{config['AFC']['host']}/api/v1/vrfs"
    headers = {'Authorization': f'Bearer {token}', 'Accept': 'application/json;version=1.0'}
    params = {'fabrics': fabric_uuid, 'fields': 'uuid,name'}
    try:
        response = session.get(vrfs_url, headers=headers, params=params, verify=False, timeout=req_timeout)
        response.raise_for_status()
        vrfs_data = response.json().get('result', [])
        return {vrf['name']: {'uuid': vrf.get('uuid')} for vrf in vrfs_data if vrf.get('name')}
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Could not get AFC VRFs for fabric {fabric_uuid[:8]}: {e}")
        return None

def create_afc_vrf(session, token, vrf_name, fabric_uuid, fabric_name):
    req_timeout = config['Daemon']['request_timeout']
    create_url = f"https://{config['AFC']['host']}/api/v1/vrfs"
    headers = {'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'}
    payload = {"name": vrf_name, "description": f"Created by Sync Script", "fabric_uuid": fabric_uuid}
    print(f"  [+] AFC: Creating VRF '{vrf_name}' on Fabric '{fabric_name}'...")
    if config['Daemon']['dry_run']: return True
    try:
        response = session.post(create_url, headers=headers, json=payload, verify=False, timeout=req_timeout)
        response.raise_for_status()
        print(f"      SUCCESS: VRF created.")
        return True
    except requests.exceptions.HTTPError as e:
        print(f"      [ERROR] Failed to create AFC VRF '{vrf_name}': {e.response.text}")
        return False

def delete_afc_vrf(session, token, vrf_uuid, vrf_name, fabric_name):
    req_timeout = config['Daemon']['request_timeout']
    delete_url = f"https://{config['AFC']['host']}/api/v1/vrfs/{vrf_uuid}"
    headers = {'Authorization': f'Bearer {token}'}
    print(f"  [-] AFC: Deleting VRF '{vrf_name}' from Fabric '{fabric_name}'...")
    if config['Daemon']['dry_run']: return True
    try:
        response = session.delete(delete_url, headers=headers, verify=False, timeout=req_timeout)
        response.raise_for_status()
        print(f"      SUCCESS: VRF deleted.")
        return True
    except requests.exceptions.HTTPError as e:
        print(f"      [ERROR] Failed to delete AFC VRF '{vrf_name}': {e.response.text}")
        return False

def get_afc_vlans(session, token, fabric_uuid):
    req_timeout = config['Daemon']['request_timeout']
    vlans_url = f"https://{config['AFC']['host']}/api/v1/fabrics/{fabric_uuid}/vlans"
    headers = {'Authorization': f'Bearer {token}', 'Accept': 'application/json;version=1.0'}
    params = {'fields': 'uuid,vlan_id,vlan_name,vlan_names'}
    try:
        response = session.get(vlans_url, headers=headers, params=params, verify=False, timeout=req_timeout)
        response.raise_for_status()
        vlans_data = response.json().get('result', [])
        afc_vlans = {}
        for vlan in vlans_data:
            vlan_id_raw = vlan.get('vlan_id')
            if vlan_id_raw is None or vlan_id_raw == 1: continue
            vlan_name = vlan.get('vlan_name') or (vlan.get('vlan_names')[0] if vlan.get('vlan_names') else f"vlan_{vlan_id_raw}")
            afc_vlans[int(vlan_id_raw)] = {'uuid': vlan.get('uuid'), 'name': vlan_name}
        return afc_vlans
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Could not get AFC VLANs for fabric {fabric_uuid[:8]}: {e}")
        return None

def create_afc_vlan(session, token, fabric_uuid, fabric_name, vlan_id, vlan_name):
    req_timeout = config['Daemon']['request_timeout']
    create_url = f"https://{config['AFC']['host']}/api/v1/fabrics/{fabric_uuid}/vlans"
    headers = {'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'}
    payload = {"vlans": [{"vlan_id": str(vlan_id), "vlan_name": vlan_name, "strict_firewall_bypass_enabled": False}], "vlan_scope": {"fabric_scope": "exclude_spine"}}
    print(f"  [+] AFC: Creating VLAN {vlan_id} ('{vlan_name}') on Fabric '{fabric_name}'...")
    if config['Daemon']['dry_run']: return True
    try:
        response = session.post(create_url, headers=headers, json=payload, verify=False, timeout=req_timeout)
        response.raise_for_status()
        print(f"      SUCCESS: VLAN created.")
        time.sleep(1) # Small delay to allow AFC to process the change
        return True
    except requests.exceptions.HTTPError as e:
        print(f"      [ERROR] Failed to create AFC VLAN '{vlan_name}': {e.response.text}")
        return False

def delete_afc_vlan(session, token, fabric_uuid, fabric_name, vlan_uuid, vlan_name):
    req_timeout = config['Daemon']['request_timeout']
    delete_url = f"https://{config['AFC']['host']}/api/v1/fabrics/{fabric_uuid}/vlans/{vlan_uuid}"
    headers = {'Authorization': f'Bearer {token}'}
    print(f"  [-] AFC: Deleting VLAN '{vlan_name}' from Fabric '{fabric_name}'...")
    if config['Daemon']['dry_run']: return True
    try:
        response = session.delete(delete_url, headers=headers, verify=False, timeout=req_timeout)
        response.raise_for_status()
        print(f"      SUCCESS: VLAN deleted.")
        return True
    except requests.exceptions.HTTPError as e:
        print(f"      [ERROR] Failed to delete AFC VLAN '{vlan_name}': {e.response.text}")
        return False

# --- PSM API Functions ---

def login_to_psm(session):
    psm_config = config['PSM']
    # Read password from environment variable
    psm_password = os.environ.get('PSM_PASSWORD')
    if not psm_password:
        print("[ERROR] PSM_PASSWORD environment variable not set.")
        return False

    req_timeout = config['Daemon']['request_timeout']
    url = f"https://{psm_config['host']}/v1/login"
    credentials = {"username": psm_config['user'], "password": psm_password, "tenant": "default"}
    headers = {"Content-Type": "application/json"}
    print("--> Attempting to log into PSM...")
    try:
        response = session.post(url, headers=headers, json=credentials, verify=False, timeout=req_timeout)
        response.raise_for_status()
        if 'Set-Cookie' in response.headers:
            print("    SUCCESS: Logged into PSM and session cookie received.")
            return True
        else:
            print("    [ERROR] PSM Login successful, but no session cookie was returned.")
            return False
    except requests.exceptions.RequestException as e:
        print(f"    [ERROR] PSM Login failed: {e}")
        return False

def get_psm_vrfs(session):
    req_timeout = config['Daemon']['request_timeout']
    url = f"https://{config['PSM']['host']}/configs/network/v1/tenant/default/virtualrouters"
    headers = {"Accept": "application/json"}
    print("--> Getting Virtual Routers from PSM...")
    try:
        response = session.get(url, headers=headers, verify=False, timeout=req_timeout)
        response.raise_for_status()
        vrfs_data = response.json().get('items') or []
        return {vrf.get('meta', {}).get('name') for vrf in vrfs_data if vrf.get('meta', {}).get('name')}
    except requests.exceptions.RequestException as e:
        print(f"    [ERROR] Could not get PSM Virtual Routers: {e}")
        return None

def create_psm_vrf(session, vrf_name):
    req_timeout = config['Daemon']['request_timeout']
    url = f"https://{config['PSM']['host']}/configs/network/v1/tenant/default/virtualrouters"
    headers = {"Content-Type": "application/json"}
    payload = {"meta": {"name": vrf_name, "tenant": "default"}, "spec": {"type": "unknown"}}
    print(f"  [+] PSM: Creating Virtual Router '{vrf_name}'...")
    if config['Daemon']['dry_run']: return True
    try:
        response = session.post(url, headers=headers, json=payload, verify=False, timeout=req_timeout)
        response.raise_for_status()
        print(f"      SUCCESS: Virtual Router created.")
        return True
    except requests.exceptions.HTTPError as e:
        print(f"      [ERROR] Failed to create PSM Virtual Router '{vrf_name}': {e.response.text}")
        return False

def delete_psm_vrf(session, vrf_name):
    req_timeout = config['Daemon']['request_timeout']
    url = f"https://{config['PSM']['host']}/configs/network/v1/tenant/default/virtualrouters/{vrf_name}"
    print(f"  [-] PSM: Deleting Virtual Router '{vrf_name}'...")
    if config['Daemon']['dry_run']: return True
    try:
        response = session.delete(url, verify=False, timeout=req_timeout)
        response.raise_for_status()
        print(f"      SUCCESS: Virtual Router deleted.")
        return True
    except requests.exceptions.HTTPError as e:
        print(f"      [ERROR] Failed to delete PSM Virtual Router '{vrf_name}': {e.response.text}")
        return False

def get_psm_vlans(session):
    req_timeout = config['Daemon']['request_timeout']
    url = f"https://{config['PSM']['host']}/configs/network/v1/networks"
    headers = {"Accept": "application/json"}
    print("--> Getting Networks from PSM...")
    try:
        response = session.get(url, headers=headers, verify=False, timeout=req_timeout)
        response.raise_for_status()
        networks_data = response.json().get('items') or []
        psm_vlans = {}
        for network in networks_data:
            vlan_id = network.get('spec', {}).get('vlan-id')
            name = network.get('meta', {}).get('name')
            if vlan_id and name:
                psm_vlans[vlan_id] = {'name': name}
        return psm_vlans
    except requests.exceptions.RequestException as e:
        print(f"    [ERROR] Could not get PSM Networks: {e}")
        return None

def create_psm_vlan(session, vlan_id, vlan_name, vrf_name):
    req_timeout = config['Daemon']['request_timeout']
    url = f"https://{config['PSM']['host']}/configs/network/v1/networks"
    headers = {"Content-Type": "application/json"}
    payload = {
        "kind": "Network",
        "meta": {"name": vlan_name},
        "spec": { "type": "bridged", "vlan-id": vlan_id, "virtual-router": vrf_name }
    }
    print(f"  [+] PSM: Creating Network '{vlan_name}' (VLAN {vlan_id}) in VRF '{vrf_name}'...")
    if config['Daemon']['dry_run']: return True
    try:
        response = session.post(url, headers=headers, json=payload, verify=False, timeout=req_timeout)
        response.raise_for_status()
        print(f"      SUCCESS: Network created.")
        return True
    except requests.exceptions.HTTPError as e:
        print(f"      [ERROR] Failed to create PSM Network '{vlan_name}': {e.response.text}")
        return False

def delete_psm_vlan(session, vlan_name):
    req_timeout = config['Daemon']['request_timeout']
    url = f"https://{config['PSM']['host']}/configs/network/v1/networks/{vlan_name}"
    print(f"  [-] PSM: Deleting Network '{vlan_name}'...")
    if config['Daemon']['dry_run']: return True
    try:
        response = session.delete(url, verify=False, timeout=req_timeout)
        response.raise_for_status()
        print(f"      SUCCESS: Network deleted.")
        return True
    except requests.exceptions.HTTPError as e:
        print(f"      [ERROR] Failed to delete PSM Network '{vlan_name}': {e.response.text}")
        return False

# --- Proxmox API Functions ---

def get_proxmox_state():
    """Gets Proxmox SDN state using a read-only API token."""
    prox_config = config['Proxmox']
    # Read token secret from environment variable
    pve_token_secret = os.environ.get('PVE_TOKEN_SECRET_READ')
    if not pve_token_secret:
        print("[ERROR] PVE_TOKEN_SECRET_READ environment variable not set.")
        return None, None

    req_timeout = config['Daemon']['request_timeout']
    zones_url = f"https://{prox_config['host']}:8006/api2/json/cluster/sdn/zones"
    vnets_url = f"https://{prox_config['host']}:8006/api2/json/cluster/sdn/vnets"
    headers = {'Authorization': f"PVEAPIToken={prox_config['api_user_read']}!{prox_config['token_name_read']}={pve_token_secret}"}
    try:
        print("--> Getting Proxmox SDN state...")
        zones_response = requests.get(zones_url, headers=headers, verify=False, timeout=req_timeout)
        print(f"    Proxmox zones response status: {zones_response.status_code}")
        zones_response.raise_for_status()
        zones_data = zones_response.json().get('data', [])
        print(f"    Found {len(zones_data)} zones in Proxmox.")
        proxmox_zones = {z['zone'] for z in zones_data if z.get('zone')}

        vnets_response = requests.get(vnets_url, headers=headers, verify=False, timeout=req_timeout)
        print(f"    Proxmox vnets response status: {vnets_response.status_code}")
        vnets_response.raise_for_status()
        vnets_data = vnets_response.json().get('data', [])
        print(f"    Found {len(vnets_data)} vnets in Proxmox.")
        proxmox_vnets = {}
        for v in vnets_data:
            if v.get('tag'):
                proxmox_vnets[int(v['tag'])] = {
                    'vnet': v.get('vnet'),
                    'zone': v.get('zone'),
                    'isolate': int(v.get('isolate-ports', 0)),
                    'orchestration': int(v.get('orchestration', 0))
                }
        return proxmox_zones, proxmox_vnets
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Could not get Proxmox config: {e}")
        return None, None

# --- Main Daemon and Sync Logic ---

def main():
    MASTER_OF_RECORD = config['Daemon']['master_of_record']
    POLL_INTERVAL_SECONDS = config['Daemon']['poll_interval_seconds']
    RESERVED_ZONE_NAMES = set(config['Daemon']['reserved_zone_names'])
    SYNC_ORCHESTRATED_ONLY = config['Daemon'].get('sync_orchestrated_vnets_only', False)

    vrf_sync_target = config['Daemon'].get('vrf_sync_target', 'NONE').upper()
    vlan_sync_target = config['Daemon'].get('vlan_sync_target', 'NONE').upper()
    VRF_SYNC_TARGETS = ['AFC', 'PSM'] if vrf_sync_target == 'BOTH' else [vrf_sync_target]
    VLAN_SYNC_TARGETS = ['AFC', 'PSM'] if vlan_sync_target == 'BOTH' else [vlan_sync_target]

    # Check if targets are actually configured before trying to use them
    psm_configured = 'PSM' in config and config['PSM'].get('host')
    afc_configured = 'AFC' in config and config['AFC'].get('host')

    print(f"--- Starting Sync Daemon ---")
    print(f"--- MASTER OF RECORD: {MASTER_OF_RECORD} ---")
    print(f"--- VRF SYNC TARGET(S): {VRF_SYNC_TARGETS} ---")
    print(f"--- VLAN SYNC TARGET(S): {VLAN_SYNC_TARGETS} ---")
    if config['Daemon']['dry_run']: print("--- RUNNING IN DRY-RUN MODE ---")

    afc_session = requests.Session()
    psm_session = requests.Session()
    psm_logged_in = False

    try:
        while True:
            print("\n" + "="*50)
            print(f"Starting sync cycle at {time.ctime()}...")

            # --- Step 1: Authenticate and Get State ---
            afc_token = None
            if afc_configured and ('AFC' in VRF_SYNC_TARGETS or 'AFC' in VLAN_SYNC_TARGETS):
                afc_token = get_afc_token(afc_session)
                if not afc_token:
                    print("[SKIP] AFC authentication failed. Skipping cycle.")
                    time.sleep(POLL_INTERVAL_SECONDS)
                    continue

            if psm_configured and ('PSM' in VRF_SYNC_TARGETS or 'PSM' in VLAN_SYNC_TARGETS) and not psm_logged_in:
                psm_logged_in = login_to_psm(psm_session)
                if not psm_logged_in:
                    print("[SKIP] PSM authentication failed. Skipping cycle.")
                    time.sleep(POLL_INTERVAL_SECONDS)
                    continue

            fabric_uuids_map = {}
            if afc_token:
                 fabric_uuids_map = lookup_fabric_uuids(afc_session, afc_token)

            if MASTER_OF_RECORD == 'Proxmox':
                desired_zones, desired_vnets = get_proxmox_state()
                if desired_zones is None:
                    print("[SKIP] Could not get state from Proxmox. Skipping cycle.")
                    time.sleep(POLL_INTERVAL_SECONDS)
                    continue

                if SYNC_ORCHESTRATED_ONLY:
                    print("[INFO] Filtering for VNETs with 'orchestration=1' flag enabled...")

                    filtered_vnets = {
                        tag: details for tag, details in desired_vnets.items()
                        if details.get('orchestration') == 1
                    }

                    print(f"       Found {len(desired_vnets)} total VNETs, "
                          f"{len(filtered_vnets)} selected for sync.")

                    # Overwrite the original variable so the rest of the script
                    # only sees the filtered list.
                    desired_vnets = filtered_vnets

            else:
                print(f"[FATAL] MASTER_OF_RECORD '{MASTER_OF_RECORD}' not implemented.")
                sys.exit(1)

            # --- Step 2: Reconcile DELETIONS ---
            print("\n[INFO] Reconciling DELETIONS...")

            if psm_configured and 'PSM' in VLAN_SYNC_TARGETS:
                current_psm_vlans = get_psm_vlans(psm_session)
                if current_psm_vlans is not None:
                    psm_desired_vlan_ids = {tag for tag, details in desired_vnets.items() if details.get('isolate') == 1}
                    vlans_to_delete = set(current_psm_vlans.keys()) - psm_desired_vlan_ids
                    for vlan_id in sorted(list(vlans_to_delete)):
                        delete_psm_vlan(psm_session, current_psm_vlans[vlan_id]['name'])

            if afc_token and 'AFC' in VLAN_SYNC_TARGETS:
                for fabric_name, fabric_uuid in fabric_uuids_map.items():
                    current_afc_vlans = get_afc_vlans(afc_session, afc_token, fabric_uuid)
                    if current_afc_vlans is not None:
                        vlans_to_delete = set(current_afc_vlans.keys()) - set(desired_vnets.keys())
                        for vlan_id in sorted(list(vlans_to_delete)):
                            details = current_afc_vlans[vlan_id]
                            delete_afc_vlan(afc_session, afc_token, fabric_uuid, fabric_name, details['uuid'], details['name'])

            if psm_configured and 'PSM' in VRF_SYNC_TARGETS:
                current_psm_vrfs = get_psm_vrfs(psm_session)
                if current_psm_vrfs is not None:
                    vrfs_to_delete = current_psm_vrfs - desired_zones
                    for name in sorted(list(vrfs_to_delete)):
                        if name in RESERVED_ZONE_NAMES: continue
                        delete_psm_vrf(psm_session, name)

            if afc_token and 'AFC' in VRF_SYNC_TARGETS:
                for fabric_name, fabric_uuid in fabric_uuids_map.items():
                    current_afc_vrfs = get_afc_vrfs(afc_session, afc_token, fabric_uuid)
                    if current_afc_vrfs is not None:
                        vrfs_to_delete = set(current_afc_vrfs.keys()) - desired_zones
                        for name in sorted(list(vrfs_to_delete)):
                            if name in RESERVED_ZONE_NAMES: continue
                            delete_afc_vrf(afc_session, afc_token, current_afc_vrfs[name]['uuid'], name, fabric_name)

            # --- Step 3: Reconcile CREATIONS ---
            print("\n[INFO] Reconciling CREATIONS...")

            if psm_configured and 'PSM' in VRF_SYNC_TARGETS:
                current_psm_vrfs = get_psm_vrfs(psm_session)
                if current_psm_vrfs is not None:
                    vrfs_to_create = desired_zones - current_psm_vrfs
                    for name in sorted(list(vrfs_to_create)):
                        if name in RESERVED_ZONE_NAMES: continue
                        create_psm_vrf(psm_session, name)

            if afc_token and 'AFC' in VRF_SYNC_TARGETS:
                for fabric_name, fabric_uuid in fabric_uuids_map.items():
                    current_afc_vrfs = get_afc_vrfs(afc_session, afc_token, fabric_uuid)
                    if current_afc_vrfs is not None:
                        vrfs_to_create = desired_zones - set(current_afc_vrfs.keys())
                        for name in sorted(list(vrfs_to_create)):
                            if name in RESERVED_ZONE_NAMES: continue
                            create_afc_vrf(afc_session, afc_token, name, fabric_uuid, fabric_name)

            if psm_configured and 'PSM' in VLAN_SYNC_TARGETS:
                current_psm_vlans = get_psm_vlans(psm_session)
                if current_psm_vlans is not None:
                    psm_desired_vlan_ids = {tag for tag, details in desired_vnets.items() if details.get('isolate') == 1}
                    vlans_to_create = psm_desired_vlan_ids - set(current_psm_vlans.keys())
                    for vlan_id in sorted(list(vlans_to_create)):
                        details = desired_vnets[vlan_id]
                        create_psm_vlan(psm_session, vlan_id, details['vnet'], details['zone'])

            if afc_token and 'AFC' in VLAN_SYNC_TARGETS:
                for fabric_name, fabric_uuid in fabric_uuids_map.items():
                    current_afc_vlans = get_afc_vlans(afc_session, afc_token, fabric_uuid)
                    if current_afc_vlans is not None:
                        vlans_to_create = set(desired_vnets.keys()) - set(current_afc_vlans.keys())
                        for vlan_id in sorted(list(vlans_to_create)):
                            details = desired_vnets[vlan_id]
                            create_afc_vlan(afc_session, afc_token, fabric_uuid, fabric_name, vlan_id, details['vnet'])

            print("\n" + "="*50)
            print(f"Sync cycle finished. Waiting for {POLL_INTERVAL_SECONDS} seconds.")
            time.sleep(POLL_INTERVAL_SECONDS)

    except KeyboardInterrupt:
        print("\n--- Stopping Sync Daemon ---")
    finally:
        afc_session.close()
        psm_session.close()
        print("--- Sessions closed. Exiting. ---")

if __name__ == "__main__":
    main()
