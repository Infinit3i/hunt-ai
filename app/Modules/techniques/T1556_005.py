def get_content():
    return {
        "id": "T1556.005",
        "url_id": "T1556/005",
        "title": "Modify Authentication Process: Reversible Encryption",
        "description": "Adversaries may abuse Active Directory properties to enable reversible password encryption, allowing them to retrieve plaintext credentials for accounts. This is possible if the AllowReversiblePasswordEncryption setting is enabled, which is generally disabled by default. By exploiting this feature and acquiring related keys and parameters, an attacker can decrypt user passwords.",
        "tags": ["Active Directory", "Reversible Encryption", "Credential Theft", "PowerShell Abuse"],
        "tactic": "Credential Access, Defense Evasion, Persistence",
        "protocol": "",
        "os": "Windows",
        "tips": [
            "Audit Group Policies and Fine-Grained Password Policies (FGPP) for reversible encryption settings.",
            "Alert on PowerShell usage of Set-ADUser with -AllowReversiblePasswordEncryption set to true.",
            "Regularly scan for accounts with reversible encryption enabled.",
            "Restrict unnecessary use of legacy authentication systems."
        ],
        "data_sources": "Active Directory: Active Directory Object Modification, Command: Command Execution, Script: Script Execution, User Account: User Account Metadata",
        "log_sources": [
            {"type": "Active Directory", "source": "", "destination": ""},
            {"type": "Command", "source": "", "destination": ""},
            {"type": "Script", "source": "", "destination": ""},
            {"type": "User Account", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Registry", "location": "GPO: Computer Configuration > Windows Settings > Security Settings > Account Policies > Password Policy", "identify": "Store passwords using reversible encryption = Enabled"},
            {"type": "PowerShell Log", "location": "PowerShell Transcription", "identify": "Set-ADUser -AllowReversiblePasswordEncryption $true"}
        ],
        "destination_artifacts": [],
        "detection_methods": [
            "Monitor Active Directory attribute changes",
            "Analyze Group Policy configuration for password settings",
            "Audit use of Set-ADUser and related PowerShell commands",
            "Detect plaintext password storage in AD userParameters"
        ],
        "apt": [],
        "spl_query": [
            'index=win_ad_logs EventCode=5136 OR CommandLine=\"*AllowReversiblePasswordEncryption $true*\"| stats count by ObjectDN, AttributeLDAPDisplayName, OperationType'
        ],
        "hunt_steps": [
            "Search for Set-ADUser commands that set reversible encryption.",
            "Audit FGPPs for unusual configurations.",
            "Inspect userParameters for G$RADIUSCHAP and G$RADIUSCHAPKEY entries."
        ],
        "expected_outcomes": [
            "Identification of accounts with reversible encryption enabled",
            "Detection of password decryption potential via harvested parameters"
        ],
        "false_positive": "Some legacy systems may intentionally use this setting. Verify with IT before treating as malicious.",
        "clearing_steps": [
            "Set-ADUser -AllowReversiblePasswordEncryption $false",
            "Remove FGPPs that enable reversible encryption",
            "Re-enforce GPOs to disable the setting globally"
        ],
        "clearing_playbook": [
            "https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-phishing"
        ],
        "mitre_mapping": [
            {"tactic": "Credential Access", "technique": "T1003", "example": "Decrypting stored credentials with reversible encryption."}
        ],
        "watchlist": [
            "Use of Set-ADUser with -AllowReversiblePasswordEncryption",
            "Unexpected changes to Password Policy GPO",
            "Presence of decrypted passwords in AD exports"
        ],
        "enhancements": [
            "Integrate GPO auditing with SIEM",
            "Block execution of PowerShell commands altering password storage settings"
        ],
        "summary": "Enabling reversible password encryption in Active Directory exposes plaintext passwords to attackers. By collecting encryption components and user parameters, adversaries can decrypt user credentials.",
        "remediation": "Disable the reversible encryption setting via GPO, remove exposed keys, and reset affected credentials.",
        "improvements": "Deploy continuous auditing of AD account configurations and block legacy auth-dependent policies.",
        "mitre_version": "16.1"
    }
