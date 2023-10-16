########################################################
# FMC_Unsupported_Algorithms
#
# Changelog for current version 1.0.6:
# + Fixed faulty IKE and IPsec lists
#
# For full version control, please refer to https://github.com/RenanHingel/fmc_unsupported_algorithms
########################################################

import time
import requests
import urllib3
import getpass
from requests.auth import HTTPBasicAuth
import datetime
import csv
urllib3.disable_warnings()

version = "1.0.6"

address = input("Enter the FMC IP address: ")
username = input("Enter your username: ")
password = getpass.getpass(prompt="Enter your password: ")
base_url = "https://" + address
verbose = True

# Declaring variables
review_ike_policies = {}
vpn_data_list = []
todays_date = datetime.datetime.now()
logfile = f"output_DATE{todays_date.day}{todays_date.month}{todays_date.year}_TIME{todays_date.hour}{todays_date.minute}.txt"
log = open(logfile,"a")


def log_and_print(input_string, verbose):
    if verbose == True:
        print(input_string)
    log.write(input_string + '\n')

def api_call_get(api_url):
    try:
        response = requests.get(api_url, headers=headers, verify=False)  # Since it's an example, we'll disable SSL verification.
        response.raise_for_status()  # Check if the request was successful (status code 200-299).
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error during API request: {e}")
        return None

def review_ike_policy(policy, review, version):
    if version == 1:
        encryption_search = "encryption"
        dh_search = "diffieHellmanGroup"
    if version == 2:
        encryption_search = "encryptionAlgorithms"
        dh_search = "diffieHellmanGroups"

    invalid_algorithms = ['3DES', 'AES-GMAC', 'AES-GMAC-192', 'AES-GMAC-256', 'DES', 'NULL']
    required_groups = [2, 5, 24]

    invalid_algorithms_found = [algorithm for algorithm in invalid_algorithms if algorithm in policy[encryption_search]]
    if invalid_algorithms_found:
        review[policy['name']] = {'Encryption': invalid_algorithms_found}

    if isinstance(policy[dh_search], int):
        policy[dh_search] = [policy[dh_search]]

    dh_groups_found = [group for group in policy[dh_search] if group in required_groups]
    if dh_groups_found:
        if policy['name'] in review:
            review[policy['name']]['DH group'] = dh_groups_found
        else:
            review[policy['name']] = {'DH group': dh_groups_found}

def review_ipsec_proposals(proposal_data, version):
    review_result = {}
    invalid_algorithms = ['3DES', 'AES-GMAC', 'AES-GMAC-192', 'AES-GMAC-256', 'DES', 'NULL']

    for item in proposal_data['items']:
        proposal_name = item['name']
        invalid_algorithms_found = []

        if version == 1:
            esp_encryption = item["espEncryption"]
            if esp_encryption in invalid_algorithms:
                invalid_algorithms_found.append(esp_encryption)

        if version == 2:
            encryption_algorithms = item["encryptionAlgorithms"]
            for algorithm in encryption_algorithms:
                if algorithm in invalid_algorithms:
                    invalid_algorithms_found.append(algorithm)

        if invalid_algorithms_found:
            review_result[proposal_name] = {'Encryption': invalid_algorithms_found}
    
    return review_result


# Script header
log_and_print(f"==========================================================", True)
log_and_print(f"FMC Unsupported Algorithms - Version {version}", True)
log_and_print(f"This script aims to leverage Cisco FMC API to look for:", verbose)
log_and_print(f"- IKEv1/v2 Policy: Diffie-Hellman groups 2, 5 and 24.", verbose)
log_and_print(f"- IKEv1/v2 Policy & IPsec Proposal containing encryption algorithms '3DES', 'AES-GMAC', 'AES-GMAC-192', 'AES-GMAC-256', 'DES' and 'NULL'.", verbose)
log_and_print(f"Source: https://www.cisco.com/c/en/us/td/docs/security/secure-firewall/management-center/device-config/720/management-center-device-config-72/vpn-s2s.html", verbose)
log_and_print(f"----------------------------------------------------------", True)
log_and_print(f"Connecting to FMC {base_url}", True)

# Start of FMC access token token generation
token_uri = "/api/fmc_platform/v1/auth/generatetoken"
response = requests.request("POST", base_url + token_uri, verify=False, auth=HTTPBasicAuth(username, password))
accesstoken = response.headers["X-auth-access-token"]
refreshtoken = response.headers["X-auth-refresh-token"]
DOMAIN_UUID = response.headers["DOMAIN_UUID"]
log_and_print(f"Connection status code: {response.status_code}", True)

# Define headers for all subsequent API calls
headers = { 'Content-Type': 'application/json', 'x-auth-access-token': accesstoken }

# List of FMC API endpoints used by this script
ikev1_ipsecproposals_uri = "/api/fmc_config/v1/domain/" + DOMAIN_UUID + "/object/ikev1ipsecproposals?offset=0&limit=4&expanded=true"
ikev2_ipsecproposals_uri = "/api/fmc_config/v1/domain/" + DOMAIN_UUID + "/object/ikev2ipsecproposals?offset=0&limit=10&expanded=true"
ikev1_policies_uri = "/api/fmc_config/v1/domain/" + DOMAIN_UUID + "/object/ikev1policies?offset=0&limit=10&expanded=true"
ikev2_policies_uri = "/api/fmc_config/v1/domain/" + DOMAIN_UUID + "/object/ikev2policies?offset=0&limit=10&expanded=true"

# Get IPSEC proposals data
ikev1ipsecproposals_data = api_call_get(base_url + ikev1_ipsecproposals_uri)
ikev2ipsecproposals_data = api_call_get(base_url + ikev2_ipsecproposals_uri)

# Get IKE policies data
ikev1policies_data = api_call_get(base_url + ikev1_policies_uri)
ikev2policies_data = api_call_get(base_url + ikev2_policies_uri)

# Iterate through the items - IKEv1 and IKEv2 IKE Policy
for item in ikev1policies_data['items']:
    review_ike_policy(item, review_ike_policies, 1)
for item in ikev2policies_data['items']:
    review_ike_policy(item, review_ike_policies, 2)

# Iterate through the items - IKEv1 and IKEv2 IPSEC Proposals
ikev1_ipsec_review_result = review_ipsec_proposals(ikev1ipsecproposals_data, 1)
ikev2_ipsec_review_result = review_ipsec_proposals(ikev2ipsecproposals_data, 2)

# Now that we know which IKE policies and IPsec proposals need to be fixed, we will pull the complete VPN list for this FMC
all_vpn_uri = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/policy/ftds2svpns?limit=1000&expanded=true"
all_vpn_data = api_call_get(base_url + all_vpn_uri)

# Then, for each VPN configured, we will find it's IKE and IPsec information, then match it against the audit we did previously
for item in all_vpn_data["items"]:
        ipsec_fix_list = []
        ike_fix_list= []
        current_vpn_ipsec_list = []
        current_vpn_ike_policy_list = []

        vpn_name = item["name"]
        vpn_id = item["id"]

        isikev1 = item["ikeV1Enabled"]
        isikev2 = item["ikeV2Enabled"]

        ike_settings_id = item['ikeSettings']['id']
        ike_settings_uri = base_url + "/api/fmc_config/v1/domain/" + DOMAIN_UUID + f"/policy/ftds2svpns/{vpn_id}/ikesettings/{ike_settings_id}"
        ike_settings_data = api_call_get(ike_settings_uri)

        if isikev1 == True:
            for proposal in item["ipsecSettings"]["ikeV1IpsecProposal"]:
                proposal_name = proposal["name"]
                current_vpn_ipsec_list.append(proposal_name)
            ikev1_policies = [policy['name'] for policy in ike_settings_data['ikeV1Settings']['policies']]
            current_vpn_ike_policy_list.extend(ikev1_policies)
        
        if isikev2 == True:
            for proposal in item["ipsecSettings"]["ikeV2IpsecProposal"]:
                proposal_name = proposal["name"]
                current_vpn_ipsec_list.append(proposal_name)
            ikev2_policies = [policy['name'] for policy in ike_settings_data['ikeV2Settings']['policies']]
            current_vpn_ike_policy_list.extend(ikev2_policies)
       

        log_and_print("==========================================================", True)
        log_and_print(f"|--- VPN Name: {vpn_name}", True)
        log_and_print(f"|    |--- IPsec Proposals: {', '.join(current_vpn_ipsec_list)}", True)
        log_and_print(f"|    |--- IKE Proposals: {', '.join(current_vpn_ike_policy_list)}", True)

        for item in current_vpn_ipsec_list:
            if item in ikev1_ipsec_review_result:
                ikev1_encryption_info = ', '.join(ikev1_ipsec_review_result[item]['Encryption'])
                ike_review_info = f"Review needed - IKEv1 IPsec proposal {item} - REMOVED encryption: {ikev1_encryption_info}"
                ipsec_fix_list.append(ike_review_info)
                log_and_print(ike_review_info, True)
            if item in ikev2_ipsec_review_result:
                ikev2_encryption_info = ', '.join(ikev2_ipsec_review_result[item]['Encryption'])
                ike_review_info = f"Review needed - IKEv2 IPsec proposal {item} - REMOVED encryption: {ikev2_encryption_info}"
                ipsec_fix_list.append(ike_review_info)
                log_and_print(ike_review_info, True)

        for item in current_vpn_ike_policy_list:
            if item in review_ike_policies:
                policy_info = review_ike_policies[item]
                encryption_info = ', '.join(policy_info.get('Encryption', []))
                dh_group_info = ', '.join(str(group) for group in policy_info.get('DH group', []))

                ike_review_info = f"Review needed for {item}"
                if encryption_info:
                    ike_review_info += f" - REMOVED encryption: {encryption_info}"
                if dh_group_info:
                    ike_review_info += f" - REMOVED DH Groups: {dh_group_info}"
                ike_fix_list.append(ike_review_info)
                log_and_print(ike_review_info, True)
        vpn_data_list.append([vpn_name,', '.join(current_vpn_ike_policy_list),', '.join(ike_fix_list),', '.join(current_vpn_ipsec_list),', '.join(ipsec_fix_list)])
        time.sleep(1)
print("==========================================================")

csv_filename = f"vpn_report_DATE{todays_date.day}{todays_date.month}{todays_date.year}_TIME{todays_date.hour}_{todays_date.minute}.csv"
with open(csv_filename, 'w', newline='') as csv_file:
    csv_writer = csv.writer(csv_file)
    csv_writer.writerow(['vpn_name', 'IKE_policies','IKE_fix_list', 'IPSEC_policies','IPSEC_fix_list'])
    csv_writer.writerows(vpn_data_list)

log_and_print(f"Collected information written to: {logfile}", True)
log_and_print(f"Collected information written to: {csv_filename}", True)
log_and_print(f"==========================================================", True)
