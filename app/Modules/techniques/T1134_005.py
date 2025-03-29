def get_content():
    return {
        "id": "T1134.005",
        "url_id": "T1134/005",
        "title": "Access Token Manipulation: SID-History Injection",
        "description": (
            "Adversaries may use SID-History Injection to escalate privileges and bypass access controls. "
            "The Windows security identifier (SID) is a unique value that identifies a user or group account. "
            "SIDs are used by Windows security in both security descriptors and access tokens. "
            "An account can hold additional SIDs in the SID-History Active Directory attribute, allowing interoperable account migration "
            "between domains (e.g., all values in SID-History are included in access tokens). "
            "With Domain Administrator (or equivalent) rights, harvested or well-known SID values may be inserted into SID-History to enable "
            "impersonation of arbitrary users/groups such as Enterprise Administrators. This manipulation may result in elevated access "
            "to local resources and/or access to otherwise inaccessible domains via lateral movement techniques such as "
            "[Remote Services](https://attack.mitre.org/techniques/T1021), "
            "[SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002), or "
            "[Windows Remote Management](https://attack.mitre.org/techniques/T1021/006)."
        ),
        "tags": ["Privilege Escalation", "Defense Evasion", "Windows", "Active Directory"],
        "tactic": "Defense Evasion, Privilege Escalation",
        "protocol": "Windows API, Active Directory",
        "os": "Windows",
        "tips": [
            "Monitor changes to the SID-History attribute in Active Directory.",
            "Investigate users with unexpected or duplicate SID-History values.",
            "Monitor for API calls to `DsAddSidHistory` used to modify SID attributes.",
            "Enable logging for Account Management events in Active Directory."
        ],
        "data_sources": "Active Directory: Active Directory Object Modification, Process: OS API Execution, User Account: User Account Metadata",
        "log_sources": [
            {"type": "Security Event Logs", "source": "Windows Event Log", "destination": "SIEM"},
            {"type": "Active Directory Logs", "source": "Domain Controller", "destination": "SIEM"},
            {"type": "API Monitoring", "source": "ETW (Event Tracing for Windows)", "destination": "Forensic Analysis"},
        ],
        "source_artifacts": [
            {"type": "SID-History Modification", "location": "Active Directory", "identify": "Unauthorized changes to SID-History attribute"},
            {"type": "Process Execution", "location": "Windows Event Logs", "identify": "Execution of tools modifying SID-History"},
        ],
        "destination_artifacts": [
            {"type": "User Privilege Escalation", "location": "Access Tokens", "identify": "Elevated access through SID-History injection"},
        ],
        "detection_methods": [
            "Monitor PowerShell usage of `Get-ADUser` to inspect SID-History values.",
            "Track API calls to `DsAddSidHistory` for unauthorized SID modifications.",
            "Analyze domain controller logs for unexpected changes in account privileges."
        ],
        "apt": ["APT groups known for abusing Active Directory manipulations"],
        "spl_query": [
            "index=windows_logs EventCode=4738 \n| search Attribute_Changed='SID-History' \n| stats count by Account_Name, Change_Type",
        ],
        "hunt_steps": [
            "Query Active Directory for users with unexpected SID-History values.",
            "Analyze security logs for unauthorized privilege escalations via SID manipulation.",
            "Check for tools like Mimikatz or PowerShell scripts modifying SID-History."
        ],
        "expected_outcomes": [
            "Privilege Escalation Detected: Investigate unauthorized SID-History injections.",
            "No Malicious Activity Found: Confirm normal administrative changes."
        ],
        "false_positive": "Legitimate domain migrations may cause SID-History changes; validate against expected migration activities.",
        "clearing_steps": [
            "Remove unauthorized SID-History entries from affected accounts.",
            "Audit administrative activity and ensure proper access control mechanisms.",
            "Restrict access to `DsAddSidHistory` API to prevent unauthorized usage."
        ],
        "mitre_mapping": [
            {"tactic": "Privilege Escalation", "technique": "T1134.005", "example": "Using SID-History to impersonate Enterprise Administrators."},
        ],
        "watchlist": [
            "Monitor for excessive SID-History modifications in a short period.",
            "Detect users with elevated privileges via SID-History without proper authorization.",
            "Investigate changes to domain controllers related to SID attributes."
        ],
        "enhancements": [
            "Enable detailed Active Directory logging for user and group modifications.",
            "Restrict Domain Administrator permissions to prevent abuse of SID-History.",
            "Implement endpoint monitoring solutions to detect unauthorized Active Directory API usage."
        ],
        "summary": "Adversaries may manipulate the SID-History attribute in Active Directory to escalate privileges and impersonate higher-privileged users.",
        "remediation": "Regularly audit Active Directory for unauthorized changes, enforce strong role-based access controls, and limit access to domain administrator accounts.",
        "improvements": "Enhance monitoring and alerting on Active Directory modifications to detect and respond to SID-History abuse."
    }
