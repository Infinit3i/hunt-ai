def get_content():
    return {
        "id": "T1555.004",
        "url_id": "1555/004",
        "title": "Credentials from Password Stores: Windows Credential Manager",
        "description": "Adversaries may acquire credentials from the Windows Credential Manager. Credential Manager stores authentication credentials for websites, applications, and network devices that use NTLM or Kerberos. Attackers may enumerate and extract credentials using various tools and APIs.",
        "tags": ["Credential Access", "Windows Security", "Password Extraction"],
        "tactic": "Credential Access",
        "protocol": "Local File Access, OS API Calls",
        "os": ["Windows"],
        "tips": [
            "Monitor usage of 'vaultcmd.exe' for listing and extracting credentials.",
            "Detect access to the Credential Vault directory for unauthorized reads.",
            "Monitor API calls such as 'CredEnumerateA' that interact with Credential Manager."
        ],
        "data_sources": "File Access Logs, Process Execution Logs, API Call Monitoring",
        "log_sources": [
            {"type": "File", "source": "Credential Vault Storage", "destination": "File Access Logs"},
            {"type": "Process", "source": "Credential Extraction Commands", "destination": "System Logs"},
            {"type": "Command", "source": "API Calls like CredEnumerateA", "destination": "Audit Logs"}
        ],
        "source_artifacts": [
            {"type": "File", "location": "Credential Manager Storage", "identify": "Extracted Credential Data"}
        ],
        "destination_artifacts": [
            {"type": "Process", "location": "Memory", "identify": "Dumped Windows Credentials"}
        ],
        "detection_methods": [
            "Monitor process execution logs for 'vaultcmd.exe' and related credential extraction commands.",
            "Analyze system logs for unauthorized access to Windows Credential Manager storage.",
            "Detect attempts to extract plaintext credentials using known security bypass methods."
        ],
        "apt": ["Kimsuky", "APT34", "FIN12", "Waterbug", "Group123"],
        "spl_query": [
            "index=security (process_name=vaultcmd.exe OR command=*CredEnumerateA*) | table _time, process_name, user, command"
        ],
        "hunt_steps": [
            "Review process activity logs for suspicious access to Credential Manager.",
            "Analyze execution history for credential dumping tools.",
            "Monitor file access logs to detect unauthorized reads from Vault locations."
        ],
        "expected_outcomes": [
            "Detection of unauthorized attempts to extract stored credentials from Windows Credential Manager.",
            "Identification of processes attempting credential theft via API calls or file access."
        ],
        "false_positive": "Legitimate administrative tasks accessing Credential Manager for user authentication purposes.",
        "clearing_steps": [
            "Investigate unauthorized access to Credential Manager.",
            "Revoke compromised credentials and enforce password rotation.",
            "Restrict access to Credential Vault directories and APIs."
        ],
        "mitre_mapping": [
            {"tactic": "Credential Access", "technique": "Extract Credentials from Windows Credential Manager", "example": "An attacker retrieves stored credentials using 'vaultcmd.exe /listcreds'."}
        ],
        "watchlist": ["Processes accessing Credential Manager storage without proper authorization."],
        "enhancements": ["Enable logging and alerting on unauthorized Credential Manager access attempts."],
        "summary": "Attackers may extract credentials from Windows Credential Manager to gain unauthorized access. Monitoring file access and process execution can help detect this activity.",
        "remediation": "Restrict access to Credential Manager-stored credentials and enforce strong authentication measures.",
        "improvements": "Enhance monitoring for credential-related file access and system calls."
    }