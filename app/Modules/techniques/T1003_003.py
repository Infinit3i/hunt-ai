def get_content():
    return {
        "id": "T1003.003",
        "url_id": "T1003/003",
        "title": "OS Credential Dumping: NTDS",
        "description": "Adversaries may access or copy the Active Directory database (NTDS.dit) from a domain controller to extract credentials and domain information.",
        "tags": ["ntds", "active directory", "secretsdump", "volume shadow copy", "ntdsutil", "credential dumping"],
        "tactic": "Credential Access",
        "protocol": "",
        "os": "Windows",
        "tips": [
            "Monitor for access to %SystemRoot%\\NTDS\\ntds.dit on Domain Controllers",
            "Detect use of Volume Shadow Copy or esentutl.exe to duplicate NTDS files",
            "Track tools like secretsdump.py and ntdsutil usage on sensitive systems"
        ],
        "data_sources": "Sysmon, Command, File",
        "log_sources": [
            {"type": "Command", "source": "", "destination": ""},
            {"type": "File", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "File", "location": "C:\\Windows\\NTDS\\ntds.dit", "identify": "Copy or access to Active Directory database"},
            {"type": "File", "location": "C:\\Windows\\System32\\config\\SYSTEM", "identify": "Accessed alongside NTDS for decryption keys"},
            {"type": "File Access Times (MACB Timestamps)", "location": "Volume Shadow Copies", "identify": "Used to bypass locked NTDS.dit file"}
        ],
        "destination_artifacts": [],
        "detection_methods": [
            "Monitor file access to ntds.dit, especially via backup or shadow copy paths",
            "Detect use of esentutl.exe, ntdsutil.exe, or secretsdump.py",
            "Look for lateral movement or privilege escalation after NTDS access"
        ],
        "apt": [
            "APT41", "FIN6", "FIN12", "Volt Typhoon", "NICKEL", "Elephant Beetle", "BRONZE PRESIDENT", "BRONZE SILHOUETTE", "Cicada", "Chimera", "Octo Tempest"
        ],
        "spl_query": [
            'index=windows_logs (process_name="esentutl.exe" OR process_name="ntdsutil.exe" OR command_line="*ntds.dit*")',
            'index=windows_logs file_path="*\\NTDS\\ntds.dit" OR command_line="*VolumeShadowCopy*"'
        ],
        "hunt_steps": [
            "Search for file access to ntds.dit, especially through shadow copy paths",
            "Review system events for use of esentutl, ntdsutil, or secretsdump",
            "Look for post-access activity involving credential cracking or lateral movement"
        ],
        "expected_outcomes": [
            "Detection of attempts to extract AD credentials from NTDS.dit",
            "Identification of unauthorized access to domain controller files",
            "Post-dump usage of harvested credentials across the domain"
        ],
        "false_positive": "Legitimate domain backups or disaster recovery testing may involve NTDS access. Correlate with change windows and admin activity.",
        "clearing_steps": [
            "Delete any extracted copies of NTDS.dit and SYSTEM hives",
            "Revoke and rotate credentials that may have been exposed",
            "Review VSS snapshots for unauthorized creation or access"
        ],
        "mitre_mapping": [
            {"tactic": "Credential Access", "technique": "T1078", "example": "Domain account logins using credentials obtained from dumped NTDS"}
        ],
        "watchlist": [
            "Processes accessing \\NTDS\\ntds.dit",
            "Commands using Volume Shadow Copy targeting SYSTEM and NTDS files",
            "Use of impacket’s secretsdump or similar tools"
        ],
        "enhancements": [
            "Restrict access to NTDS.dit and SYSTEM files via GPO",
            "Log and alert on backup or copy activity targeting these files",
            "Use EDR tools to monitor VSS snapshot usage and data exfiltration"
        ],
        "summary": "Adversaries may target the NTDS.dit file on Domain Controllers to extract Active Directory credentials, using tools like secretsdump, ntdsutil, or shadow copies.",
        "remediation": "Delete dumped credential files, rotate all domain credentials, and restrict access to Domain Controller backup files.",
        "improvements": "Enforce admin-tiering, block execution of credential dumpers on domain controllers, and monitor shadow copy abuse.",
        "mitre_version": "16.1"
    }
