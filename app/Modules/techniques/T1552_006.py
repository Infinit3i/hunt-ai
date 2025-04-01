def get_content():
    return {
        "id": "T1552.006",
        "url_id": "T1552/006",
        "title": "Unsecured Credentials: Group Policy Preferences",
        "description": "Adversaries may attempt to find unsecured credentials in Group Policy Preferences (GPP).",
        "tags": ["credentials", "gpp", "sysvol", "domain", "xml", "passwords", "infostealer"],
        "tactic": "Credential Access",
        "protocol": "",
        "os": "Windows",
        "tips": [
            "Deploy MS14-025 patch to prevent plaintext credential storage in GPP.",
            "Audit SYSVOL shares for exposed GPP XML files.",
            "Set strict permissions on SYSVOL and monitor access attempts."
        ],
        "data_sources": "Command, File",
        "log_sources": [
            {"type": "Command", "source": "", "destination": ""},
            {"type": "File", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Network Connections", "location": "\\\\<domain>\\SYSVOL", "identify": "Access to shared policy folders"},
            {"type": "File Access Times (MACB Timestamps)", "location": "\\\\<domain>\\SYSVOL\\*", "identify": "Access to GPP XML files"}
        ],
        "destination_artifacts": [
            {"type": "File", "location": "Downloaded copies of groups.xml or scheduledtasks.xml", "identify": "Decrypted password from XML content"}
        ],
        "detection_methods": [
            "Monitor access to SYSVOL for *.xml queries",
            "Detect use of GPP-specific tools like Get-GPPPassword",
            "Audit for suspicious use of PowerShell with domain policy enumeration"
        ],
        "apt": [
            "Elfin", "FIN12", "APT33"
        ],
        "spl_query": [
            'index=windows file_path="*\\SYSVOL\\*" file_name="*.xml"\n| stats count by file_name, user, host',
            'index=windows process_name="powershell.exe" command_line="*Get-GPPPassword*"\n| stats count by host, user, command_line'
        ],
        "hunt_steps": [
            "Search for domain users accessing SYSVOL and enumerating *.xml files",
            "Check for known tools like Metasploit modules or Get-GPPPassword scripts in execution logs",
            "Look for scheduled task or local admin setting changes following SYSVOL access"
        ],
        "expected_outcomes": [
            "Detection of XML file enumeration in SYSVOL",
            "Discovery of attempts to decrypt embedded passwords in GPP"
        ],
        "false_positive": "Legitimate sysadmin tasks may involve accessing GPP files. Confirm by correlating tool usage, user identity, and timing.",
        "clearing_steps": [
            "Remove legacy GPP password XML files (e.g., groups.xml, scheduledtasks.xml) from SYSVOL",
            "Apply MS14-025 to prevent future plaintext password storage",
            "Rotate any credentials exposed via GPP"
        ],
        "clearing_playbook": [
            "https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-credential-theft"
        ],
        "mitre_mapping": [
            {"tactic": "Discovery", "technique": "T1087.002", "example": "Gathering credentials via policy discovery"},
            {"tactic": "Lateral Movement", "technique": "T1021.002", "example": "Using GPP credentials for RDP or SMB login"}
        ],
        "watchlist": [
            "groups.xml", "scheduledtasks.xml", "Get-GPPPassword", "gpprefdecrypt.py", "Metasploit GPP module"
        ],
        "enhancements": [
            "Deploy decoy GPP XML files with Everyone:Deny permissions and alert on Access Denied attempts",
            "Integrate detection logic into SIEM for any SYSVOL *.xml enumeration"
        ],
        "summary": "Adversaries may retrieve plaintext passwords stored in Group Policy Preferences XML files within SYSVOL shares.",
        "remediation": "Patch domain controllers with MS14-025, remove legacy GPP credential files, and monitor SYSVOL for sensitive content.",
        "improvements": "Proactively search for GPP XML files with embedded credentials and automate alerts for their creation or access.",
        "mitre_version": "16.1"
    }
