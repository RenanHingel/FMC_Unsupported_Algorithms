## Changelog
### 1.0.3
# Expect pagination 
# Expect and handle ikev1+ikev2
# Improve debug logging
###

import requests
import urllib3
import json
import getpass
from requests.auth import HTTPBasicAuth
import datetime
urllib3.disable_warnings()

version = "1.0.3"

# FMC information
address = input("Enter the FMC IP address: ")
username = input("Enter your username: ")
password = getpass.getpass(prompt="Enter your password: ")
base_url = "https://" + address


# Declaring variables to refer as date, log and entries list
todays_date = datetime.datetime.now()
logfile = f"output_{todays_date.day}{todays_date.month}{todays_date.year}{todays_date.hour}{todays_date.minute}.txt"
debug_logfile = f"debug_{todays_date.day}{todays_date.month}{todays_date.year}{todays_date.hour}{todays_date.minute}.txt"

log = open(logfile,"a")
debug_log = open(debug_logfile,"a")


def log_and_print(input_string):
    print(input_string)
    log.write(input_string + '\n')

def log_debug(uri,data):
    debug_log.write(f"URI={uri}\n {str(data)} \n")

def api_call_get(api_url):
    try:
        response = requests.get(api_url, headers=headers, verify=False)  # Since it's an example, we'll disable SSL verification.
        response.raise_for_status()  # Check if the request was successful (status code 200-299).
        log_debug(api_url,response.json())
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error during API request: {e}")
        return None

def extract_policy_details(ike_settings_data,type):
    policies = []

    if isinstance(ike_settings_data, dict):
        ike_settings_data = [ike_settings_data]
    if (type == "v1"):
        for ike_setting in ike_settings_data:
            ikev1_settings = ike_setting.get('ikeV1Settings')
            if ikev1_settings:
                policies.extend(ikev1_settings.get('policies', []))
    if (type == "v2"):
        for ike_setting in ike_settings_data:
            ikev2_settings = ike_setting.get('ikeV2Settings')
            if ikev2_settings:
                policies.extend(ikev2_settings.get('policies', []))

    return policies

# Start of FMC access token token generation
log_and_print(f"==========================================================")
log_and_print(f"FMC Unsupported Algorithms - Version {version}")
log_and_print(f"Please refer to the following link for details, lookup for Removal and deprecation of weak ciphers")
log_and_print(f"https://www.cisco.com/c/en/us/td/docs/security/secure-firewall/management-center/device-config/720/management-center-device-config-72/vpn-s2s.html")
log_and_print(f"----------------------------------------------------------")
log_and_print(f"Connecting to FMC {base_url}")

token_uri = "/api/fmc_platform/v1/auth/generatetoken"
response = requests.request("POST", base_url + token_uri, verify=False, auth=HTTPBasicAuth(username, password))
accesstoken = response.headers["X-auth-access-token"]
refreshtoken = response.headers["X-auth-refresh-token"]
DOMAIN_UUID = response.headers["DOMAIN_UUID"]
log_and_print(f"Connection status code: {response.status_code}")

# Define headers for all subsequent API calls
headers = { 'Content-Type': 'application/json', 'x-auth-access-token': accesstoken }


# First API call - Obtain list of VPN S2S
ftds2svpns_uri = base_url + "/api/fmc_config/v1/domain/" + DOMAIN_UUID + "/policy/ftds2svpns?limit=1000"
vpn_s2s_data = api_call_get(ftds2svpns_uri)

vpncount = vpn_s2s_data["paging"]["count"]

# Print to console and save the to log file
log_and_print(f"----------------------------------------------------------")
log_and_print(f"Collecting VPN site to site report.")
log_and_print(f"Found {vpncount} site to site configurations.")
log_and_print(f"Report timestamp: {todays_date.day}/{todays_date.month}/{todays_date.year} {todays_date.hour}:{todays_date.minute}")
log_and_print(f"Collected VPN information written to: {logfile}")
log_and_print(f"Collected DEBUG written to: {debug_logfile}")
log_and_print(f"----------------------------------------------------------")


if vpn_s2s_data:
    ftds2svpn_entries = []
    
    # Now loop inside the first API response to obtain name and ID of each VPN S2S
    for item in vpn_s2s_data["items"]:
        ftds2svpns_name = item["name"]
        ftds2svpns_id = item["id"]
        log_and_print(f"|--- VPN Name: {ftds2svpns_name}")
        
        # Second API call - Get details of each VPN S2S
        ftds2svpns_details_uri = base_url + "/api/fmc_config/v1/domain/" + DOMAIN_UUID + f"/policy/ftds2svpns/{ftds2svpns_id}"
        vpn_details_data = api_call_get(ftds2svpns_details_uri)

        # From this response we need the IKE Settings ID only
        isikev1 = str(vpn_details_data["ikeV1Enabled"])
        isikev2 = str(vpn_details_data["ikeV2Enabled"])
        log_and_print(f"|    |--- IKE Modes:")
        log_and_print(f"|    |   |--- ikeV1Enabled: {isikev1}")
        log_and_print(f"|    |   |--- ikeV2Enabled: {isikev2}")

        # Nested loop to find IKEv1 IPsec proposal details
        if (isikev1 == "True") :
            try:
                for proposal in vpn_details_data["ipsecSettings"]["ikeV1IpsecProposal"]:
                    proposal_info = proposal["name"]
                    proposal_id = proposal["id"]

                    ipsec_lifetime = vpn_details_data["ipsecSettings"]["lifetimeSeconds"]
                    ipsec_size = vpn_details_data["ipsecSettings"]["lifetimeKilobytes"]
                    pfs_enabled = vpn_details_data["ipsecSettings"]["perfectForwardSecrecy"]["enabled"]
                    agressive_mode = vpn_details_data["advancedSettings"]["advancedIkeSetting"]["enableAggressiveMode"]

                    log_and_print(f"|    |--- IKEv1 IPsec Proposal:")
                    log_and_print(f"|    |   |--- Name: {proposal_info}")
                    log_and_print(f"|    |   |   |--- IPsec Lifetime: {ipsec_lifetime}")
                    log_and_print(f"|    |   |   |--- IPsec Size: {ipsec_size}")
                    log_and_print(f"|    |   |   |--- PFS Enabled: {pfs_enabled}")
                    log_and_print(f"|    |   |   |--- Agressive Mode: {agressive_mode}")

                ike_settings_id = vpn_details_data['ikeSettings']['id']
                # Third API call - Get details of the IKE Settings used in this VPN S2S
                ike_settings_uri = base_url + "/api/fmc_config/v1/domain/" + DOMAIN_UUID + f"/policy/ftds2svpns/{ftds2svpns_id}/ikesettings/{ike_settings_id}"
                ike_settings_data = api_call_get(ike_settings_uri)
            except:
                log_and_print(f"|    |--- IKEv1 IPsec Proposal: NONE")

        # Since each VPN S2S can have more than one IKE Settings, we loop inside this result to obtain the data needed for the last API call
            if ike_settings_data:
                policy_details = extract_policy_details([ike_settings_data],"v1")
                for policy in policy_details:

                        # We only need the name and ID of each IKE Settings ID
                        ikepolicy_name = policy["name"]
                        ikepolicy_id = policy["id"]
                        log_and_print(f"|    |--- IKEv1 Policy Name: {ikepolicy_name}")
                    
                        # Fourth API call - Get details of the IKE Policy
                        ike_details_uri = base_url + "/api/fmc_config/v1/domain/" + DOMAIN_UUID + f"/object/ikev1policies/{ikepolicy_id}"
                        ike_details_data = api_call_get(ike_details_uri)
                        
                        # Extract required information
                        encryption_algorithms = ike_details_data.get("encryption", [])
                        integrity_algorithms = ike_details_data.get("hash", [])
                        diffie_hellman_groups = ike_details_data.get("diffieHellmanGroup", [])
                        
                        # Print the extracted information
                        log_and_print(f"|    |   |--- Encryption Algorithms:: {encryption_algorithms}")
                        log_and_print(f"|    |   |--- Integrity Algorithms:: {integrity_algorithms}")
                        log_and_print(f"|    |   |--- Diffie Hellman Groups:: {diffie_hellman_groups}")
                        
                        # Check if the policy needs review
                        if (diffie_hellman_groups == 5):
                            log_and_print(f"*** Review required for {ikepolicy_name}. IKEv1 Diffie-Hellman groups: {diffie_hellman_groups} is DEPRECATED and will not supported in the future. ***")
                log_and_print("----------------------------------------------------------")


        # Nested loop to find IKEv2 IPsec proposal details
        if (isikev2 == "True") :
            try:
                for proposal in vpn_details_data["ipsecSettings"]["ikeV2IpsecProposal"]:
                    proposal_info = proposal["name"]
                    proposal_id = proposal["id"]

                    ipsec_lifetime = vpn_details_data["ipsecSettings"]["lifetimeSeconds"]
                    ipsec_size = vpn_details_data["ipsecSettings"]["lifetimeKilobytes"]
                    pfs_enabled = vpn_details_data["ipsecSettings"]["perfectForwardSecrecy"]["enabled"]
                    agressive_mode = vpn_details_data["advancedSettings"]["advancedIkeSetting"]["enableAggressiveMode"]

                    log_and_print(f"|    |--- IKEv2 IPsec Proposal:")
                    log_and_print(f"|    |   |--- Name: {proposal_info}")
                    log_and_print(f"|    |   |   |--- IPsec Lifetime: {ipsec_lifetime}")
                    log_and_print(f"|    |   |   |--- IPsec Size: {ipsec_size}")
                    log_and_print(f"|    |   |   |--- PFS Enabled: {pfs_enabled}")
                    log_and_print(f"|    |   |   |--- Agressive Mode: {agressive_mode}")

                ike_settings_id = vpn_details_data['ikeSettings']['id']
                # Third API call - Get details of the IKE Settings used in this VPN S2S
                ike_settings_uri = base_url + "/api/fmc_config/v1/domain/" + DOMAIN_UUID + f"/policy/ftds2svpns/{ftds2svpns_id}/ikesettings/{ike_settings_id}"
                ike_settings_data = api_call_get(ike_settings_uri)
            except:
                log_and_print(f"|    |--- IKEv2 IPsec Proposal: NONE")

        # Since each VPN S2S can have more than one IKE Settings, we loop inside this result to obtain the data needed for the last API call
            if ike_settings_data:
                policy_details = extract_policy_details([ike_settings_data],"v2")
                for policy in policy_details:

                        # We only need the name and ID of each IKE Settings ID
                        ikepolicy_name = policy["name"]
                        ikepolicy_id = policy["id"]
                        log_and_print(f"|    |--- IKEv2 Policy Name: {ikepolicy_name}")
                    
                        # Fourth API call - Get details of the IKE Policy
                        ike_details_uri = base_url + "/api/fmc_config/v1/domain/" + DOMAIN_UUID + f"/object/ikev2policies/{ikepolicy_id}"
                        ike_details_data = api_call_get(ike_details_uri)
                        
                        # Extract required information
                        encryption_algorithms = ike_details_data.get("encryptionAlgorithms", [])
                        integrity_algorithms = ike_details_data.get("integrityAlgorithms", [])
                        diffie_hellman_groups = ike_details_data.get("diffieHellmanGroups", [])
                        
                        # Print the extracted information
                        log_and_print(f"|    |   |--- Encryption Algorithms:: {', '.join(map(str, encryption_algorithms))}")
                        log_and_print(f"|    |   |--- Integrity Algorithms:: {', '.join(map(str, integrity_algorithms))}")
                        log_and_print(f"|    |   |--- Diffie Hellman Groups:: {', '.join(map(str, diffie_hellman_groups))}")
                        
                        # Check if the policy needs review
                        review_groups = [group for group in diffie_hellman_groups if group in [2, 5, 24]]
                        if review_groups:
                            log_and_print(f"*** Review required for {ikepolicy_name}. Found in Diffie-Hellman groups: {', '.join(map(str, review_groups))} ***")
                log_and_print("----------------------------------------------------------")
log_and_print(f"==========================================================")
