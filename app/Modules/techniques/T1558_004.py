def get_content():
    return {
        "id": "T1558.004",
        "url_id": "T1558/004",
        "title": "Steal or Forge Kerberos Tickets: AS-REP Roasting",
        "description": "Adversaries may abuse accounts with disabled Kerberos preauthentication to obtain AS-REP messages from a Domain Controller. These responses can be encrypted with weak algorithms like RC4, making them susceptible to offline password cracking and potentially revealing plaintext credentials.",
        "tags": ["as-rep roasting", "TGT", "kerberos", "rc4", "credential access", "ldap", "password cracking"],
        "tactic": "Credential Access",
        "protocol": "Kerberos",
        "os": "Windows",
        "tips": [
            "Enable auditing for Event ID 4768 to monitor AS-REQ/AS-REP activity.",
            "Detect accounts without Kerberos preauthentication via LDAP enumeration.",
            "Investigate large volumes of AS-REP responses, especially from the same host."
        ],
        "data_sources": "Windows Security, Active Directory",
        "log_sources": [
            {"type": "Windows Security", "source": "", "destination": ""},
            {"type": "Active Directory", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Event Logs", "location": "Security.evtx", "identify": "Event ID 4768 indicating AS-REQ for accounts without preauthentication"},
            {"type": "Network Connections", "location": "Traffic Capture", "identify": "AS-REP messages encrypted with RC4"}
        ],
        "destination_artifacts": [
            {"type": "Active Directory Credential Request", "location": "Domain Controller", "identify": "AS-REP responses without preauthentication"},
            {"type": "Process List", "location": "Endpoint Memory", "identify": "Tool usage such as Rubeus or ASREPRoast.py"}
        ],
        "detection_methods": [
            "Audit Event ID 4768 for accounts where pre-authentication was not required",
            "Detect AS-REP requests without prior timestamp submission",
            "Alert on LDAP enumeration of user attributes related to preauthentication"
        ],
        "apt": ["Ryuk", "UNC2165", "FIN12"],
        "spl_query": [
            "index=security EventCode=4768 PreAuthType=0x0 \n| stats count by Account_Name, Client_Address",
            "index=security EventCode=4768 \n| stats count by Account_Name, PreAuthType \n| where PreAuthType=0x0"
        ],
        "hunt_steps": [
            "Search logs for Event ID 4768 with PreAuthType 0x0",
            "Enumerate user accounts with `Do not require Kerberos preauthentication` set",
            "Check for network artifacts of AS-REP messages being harvested"
        ],
        "expected_outcomes": [
            "Identify users configured with no preauthentication",
            "Trace AS-REP responses to password cracking activity"
        ],
        "false_positive": "Some legacy applications or misconfigured service accounts may not require preauthentication. Validate the necessity before action.",
        "clearing_steps": [
            "Enable Kerberos preauthentication for vulnerable accounts",
            "Rotate passwords for accounts suspected of being harvested",
            "Audit group policies and Active Directory user settings"
        ],
        "clearing_playbook": [
            "https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-credential-theft"
        ],
        "mitre_mapping": [
            {"tactic": "Credential Access", "technique": "T1110.002", "example": "Offline cracking of AS-REP encrypted hashes"},
            {"tactic": "Persistence", "technique": "T1078", "example": "Access via valid account after cracking"}
        ],
        "watchlist": [
            "Event ID 4768 with PreAuthType 0x0",
            "Accounts queried frequently for AS-REP by tools like Rubeus"
        ],
        "enhancements": [
            "Deploy scripts to detect users with `DONT_REQ_PREAUTH` flag",
            "Enable logging on all domain controllers for Event ID 4768"
        ],
        "summary": "AS-REP Roasting is a technique that targets accounts with disabled Kerberos preauthentication, allowing adversaries to extract encrypted AS-REP responses for offline password cracking, potentially exposing user credentials.",
        "remediation": "Ensure all user accounts require Kerberos preauthentication and rotate passwords for any that were exposed or targeted.",
        "improvements": "Automate detection of accounts without preauthentication and integrate password hygiene enforcement.",
        "mitre_version": "16.1"
    }
