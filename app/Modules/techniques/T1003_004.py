def get_content():
    return {
        "id": "T1003.004",
        "url_id": "T1003/004",
        "title": "OS Credential Dumping: LSA Secrets",
        "description": "Adversaries with SYSTEM access may dump Local Security Authority (LSA) secrets from memory or registry to obtain credentials such as service account passwords.",
        "tags": ["lsa", "registry", "mimikatz", "secrets", "SYSTEM access", "lsa secrets", "credential dumping"],
        "tactic": "Credential Access",
        "protocol": "",
        "os": "Windows",
        "tips": [
            "Monitor access to HKLM\\SECURITY\\Policy\\Secrets in the registry",
            "Look for command-line usage of Mimikatz, reg.exe, or PowerSploit modules like Invoke-Mimikatz",
            "Enable detailed PowerShell logging to capture suspicious scripts"
        ],
        "data_sources": "Command, Windows Registry",
        "log_sources": [
            {"type": "Command", "source": "", "destination": ""},
            {"type": "Windows Registry", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Windows Registry Hives", "location": "HKLM\\SECURITY\\Policy\\Secrets", "identify": "LSA secrets storage location"},
            {"type": "Windows Defender Logs", "location": "Microsoft-Windows-Windows Defender/Operational", "identify": "Alerts on Mimikatz or PowerSploit activity"},
            {"type": "Shell History", "location": "PowerShell transcripts or Event ID 4104", "identify": "Credential dumping PowerShell commands"}
        ],
        "destination_artifacts": [],
        "detection_methods": [
            "Detect access to registry key: HKLM\\SECURITY\\Policy\\Secrets",
            "Look for use of Mimikatz or similar tools dumping secrets from memory",
            "Monitor PowerShell execution for suspicious dumping behavior"
        ],
        "apt": [
            "APT29", "APT34", "APT33", "APT35", "Ke3chang", "MuddyWater", "Elfin", "Leafminer", "Union", "BRONZE UNION", "The Dukes", "OilRig"
        ],
        "spl_query": [
            'index=windows_logs sourcetype=WinRegistry registry_path="HKLM\\\\SECURITY\\\\Policy\\\\Secrets"',
            'index=windows_logs sourcetype=Sysmon EventCode=1 command_line="*mimikatz*" OR command_line="*Invoke-Mimikatz*"'
        ],
        "hunt_steps": [
            "Identify attempts to access or export LSA secrets registry key",
            "Search for memory-dumping tools or commands referencing LSA",
            "Review PowerShell transcripts for credential access behavior"
        ],
        "expected_outcomes": [
            "Detection of SYSTEM-level access to sensitive credential stores",
            "Identification of registry access to LSA secrets",
            "Evidence of Mimikatz or script-based credential dumping"
        ],
        "false_positive": "Legitimate backup or forensic tools may access LSA secrets. Correlate with scheduled activities or known admin actions.",
        "clearing_steps": [
            "Remove unauthorized tools like mimikatz from disk",
            "Rotate service and system account credentials",
            "Review audit logs and restore registry from backup if altered"
        ],
        "mitre_mapping": [
            {"tactic": "Credential Access", "technique": "T1552", "example": "LSA secrets used to extract service account credentials"}
        ],
        "watchlist": [
            "Access to HKLM\\SECURITY\\Policy\\Secrets",
            "Commands using 'reg.exe' to export secrets",
            "PowerShell modules like PowerSploit’s Invoke-Mimikatz"
        ],
        "enhancements": [
            "Enable registry auditing for sensitive keys like Policy\\Secrets",
            "Use EDR to detect memory scraping behavior",
            "Apply LSA protection to restrict access to secrets"
        ],
        "summary": "LSA secrets in the Windows registry can be dumped by attackers with SYSTEM access using tools like Mimikatz or reg.exe to gain credentials like service account passwords.",
        "remediation": "Delete credential dumping tools, change exposed passwords, enable LSA protection, and restore registry integrity.",
        "improvements": "Use Secure Boot, Credential Guard, and apply strict ACLs on registry keys holding secrets.",
        "mitre_version": "16.1"
    }
