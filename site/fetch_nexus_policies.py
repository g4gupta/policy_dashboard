import os
import json
import requests
from requests.auth import HTTPBasicAuth

# 1. Setup Configuration from Pipeline Variables
NEXUS_URL = os.getenv("NEXUS_IQ_URL")
APP_ID = os.getenv("NEXUS_APP_ID")
# Ensure you set NEXUS_USER and NEXUS_PASSWORD in your GitLab CI/CD Variables
USERNAME = os.getenv("NEXUS_USER")
PASSWORD = os.getenv("NEXUS_PASSWORD")

def fetch_policy_report():
    print(#fetch_nexus_policies.py:17)
    # Step A: Get the internal application ID from the public application ID
    app_url = f"{NEXUS_URL}/api/v2/applications?publicId={APP_ID}"
    app_response = requests.get(app_url, auth=HTTPBasicAuth(USERNAME, PASSWORD)).json()
    internal_app_id = app_response['applications'][0]['id']
    
    # Step B: Fetch the latest evaluation report for that application
    report_url = f"{NEXUS_URL}/api/v2/reports/applications/{internal_app_id}"
    reports = requests.get(report_url, auth=HTTPBasicAuth(USERNAME, PASSWORD)).json()
    
    # Grab the latest report (e.g., stage 'stage-release' or 'build')
    latest_report_path = reports[0]['reportHtmlUrl'] # Base path contains report metadata
    report_id = latest_report_path.split('/')[-1]
    
    # Step C: Get the detailed component violations
    violations_url = f"{NEXUS_URL}/api/v2/applications/{APP_ID}/reports/{report_id}/policyViolations"
    violations = requests.get(violations_url, auth=HTTPBasicAuth(USERNAME, PASSWORD)).json()
    return violations

def map_to_dashboard(violations):
    # Initialize structures for your tabs
    policy_a_libs = []
    policy_b_libs = []
    
    for violation in violations.get('violations', []):
        policy_name = violation.get('policyName')
        component = violation.get('component', {})
        
        # Extract security specifics (like CVE data if available)
        cve_id = "N/A"
        cve_link = "#"
        cve_desc = "No description available"
        
        # Look into standard constraints for vulnerability info
        for constraint in violation.get('constraints', []):
            for condition in constraint.get('conditions', []):
                value = condition.get('value', '')
                if "CVE" in value:
                    cve_id = value
                    cve_link = f"https://nvd.nist.gov/vuln/detail/{cve_id.strip()}"
                    cve_desc = constraint.get('constraintName', 'Security Vulnerability')

        # Construct the dashboard library object
        lib_entry = {
            "name": component.get('displayName', 'Unknown Component'),
            "purl": component.get('packageUrl', ''),
            "quarantine_id": violation.get('policyViolationId', 'N/A'),
            "cve": cve_id,
            "cve_link": cve_link,
            "cve_short_desc": cve_desc
        }
        
        # Route to the appropriate folder depending on the policy identity
        if policy_name == "Security-Critical":
            policy_a_libs.append(lib_entry)
        elif policy_name == "License-Banned":
            policy_b_libs.append(lib_entry)

    # Write out the JSON files to their destination directories
    with open('site/policy_a/libs.json', 'w') as f:
        json.dump(policy_a_libs, f, indent=2)
        
    with open('site/policy_b/libs.json', 'w') as f:
        json.dump(policy_b_libs, f, indent=2)
        
    print("Dashboard JSON assets written successfully.")

if __name__ == "__main__":
    try:
        data = fetch_policy_report()
        map_to_dashboard(data)
    except Exception as e:
        print(f"Error processing Nexus IQ data: {e}")
        exit(1)
