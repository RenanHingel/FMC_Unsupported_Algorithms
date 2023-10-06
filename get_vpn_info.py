########################################################
# FMC_Unsupported_Algorithms
#
# Changelog for current version 1.0.4:
# + Fixed IKE policy parsing
# + Added one second delay to prevent rate limiting issues
#
# For full version control, please refer to https://github.com/RenanHingel/fmc_unsupported_algorithms
########################################################

import time
import requests
import urllib3
import json
import getpass
from requests.auth import HTTPBasicAuth
import datetime
import csv
urllib3.disable_warnings()

version = "1.0.4"

def api_call_get(api_url):
    try:
        response = requests.get(api_url, headers=headers, verify=False)  # Since it's an example, we'll disable SSL verification.
        response.raise_for_status()  # Check if the request was successful (status code 200-299).
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error during API request: {e}")
        return None
    
def extract_policy_details(ike_settings_data):
    policy_details = []
    for item in ike_settings_data:
        policies = item['ikeV2Settings']['policy']
        name = policies['name']
        policy_id = policies['id']
        policy_details.append({'name': name, 'id': policy_id})
    return policy_details

def log_and_print(input_string):
    print(input_string)
    log.write(input_string + '\n')

# FMC information
address = input("Enter the FMC IP address: ")
username = input("Enter your username: ")
password = getpass.getpass(prompt="Enter your password: ")
base_url = "https://" + address

# Declaring variables
vpn_data_list = []
todays_date = datetime.datetime.now()
logfile = f"output_{todays_date.day}{todays_date.month}{todays_date.year}{todays_date.hour}{todays_date.minute}.txt"
log = open(logfile,"a")

log_and_print(f"==========================================================")
log_and_print(f"FMC Unsupported Algorithms - Version {version}")
log_and_print(f"This script aims to leverage Cisco FMC API to look for DH group 2, 5 and 24 on IKEv2 VPN configurations.\n")
log_and_print(f"According to Cisco's history for Site-to-Site VPN, the following information is valid for firmware 6.7 and above: ")
log_and_print(f"- Diffie-Hellman GROUP 5 is deprecated for IKEv1 and removed for IKEv2")
log_and_print(f"- Diffie-Hellman groups 2 and 24 have been removed.")
log_and_print(f"- Encryption algorithms: 3DES, AES-GMAC, AES-GMAC-192, AES-GMAC-256 have been removed.")
log_and_print(f"Source: https://www.cisco.com/c/en/us/td/docs/security/secure-firewall/management-center/device-config/720/management-center-device-config-72/vpn-s2s.html")
log_and_print(f"----------------------------------------------------------")
log_and_print(f"Connecting to FMC {base_url}")

# Start of FMC access token token generation
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
total_vpn_count = int(vpn_s2s_data["paging"]["count"])
current_vpn_count = 0

if vpn_s2s_data:
    ftds2svpn_entries = []

    # Now loop inside the first API response to obtain name and ID of each VPN S2S
    for item in vpn_s2s_data["items"]:      
        ftds2svpns_name = item["name"]
        ftds2svpns_id = item["id"]

        # Second API call - Get details of each VPN S2S
        ftds2svpns_details_uri = base_url + "/api/fmc_config/v1/domain/" + DOMAIN_UUID + f"/policy/ftds2svpns/{ftds2svpns_id}"
        vpn_details_data = api_call_get(ftds2svpns_details_uri)

        # From this response we need the IKE Settings ID only
        isikev1 = str(vpn_details_data["ikeV1Enabled"])
        isikev2 = str(vpn_details_data["ikeV2Enabled"])

        log_and_print(f"|--- VPN Name: {ftds2svpns_name}")
        log_and_print(f"|    |--- IKE Modes:")
        log_and_print(f"|    |   |--- ikeV1Enabled: {isikev1}")
        log_and_print(f"|    |   |--- ikeV2Enabled: {isikev2}")

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

            # Since each VPN S2S can have more than one IKE Settings, we loop inside this result to obtain the data needed for the last API call
            if ike_settings_data:
                policy_details = extract_policy_details([ike_settings_data])
                for policy in policy_details:

                    # We only need the name and ID of each IKE Settings ID
                    ikepolicy_name = policy["name"]
                    ikepolicy_id = policy["id"]
                    log_and_print(f"|    |--- IKE Policy Name: {ikepolicy_name}")

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
                        vpn_data_list.append([ftds2svpns_name, ikepolicy_name, ', '.join(map(str, review_groups))])
        except:
            log_and_print(f"|    |--- IKEv2 IPsec Proposal: NONE")
        log_and_print("-------------------------------------")
        time.sleep(1)

csv_filename = f"vpn_report_{todays_date.day}{todays_date.month}{todays_date.year}{todays_date.hour}{todays_date.minute}.csv"
with open(csv_filename, 'w', newline='') as csv_file:
    csv_writer = csv.writer(csv_file)
    csv_writer.writerow(['vpn_name', 'ike_v2_policy_name', 'low_dh_group_found'])
    csv_writer.writerows(vpn_data_list)

log_and_print(f"Collected information written to: {logfile}")
log_and_print(f"Collected information written to: {csv_filename}")
log_and_print(f"==========================================================")
