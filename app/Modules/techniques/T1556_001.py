def get_content():
    return {
        "id": "T1556.001",
        "url_id": "T1556/001",
        "title": "Modify Authentication Process: Domain Controller Authentication",
        "description": "Adversaries may patch the authentication process on a domain controller to bypass typical authentication and gain access to user accounts. This technique may involve injecting a skeleton key into LSASS, allowing the attacker to authenticate as any domain user with a predefined password until the system reboots.",
        "tags": ["Skeleton Key", "LSASS Injection", "Domain Controller", "Authentication Bypass", "Persistence"],
        "tactic": "Credential Access, Defense Evasion, Persistence",
        "protocol": "",
        "os": "Windows",
        "tips": [
            "Monitor for suspicious OpenProcess calls targeting lsass.exe.",
            "Review modifications to cryptdll.dll and samsrv.dll exports.",
            "Implement consistent account activity audit policies.",
            "Correlate login activity with physical or VPN access data."
        ],
        "data_sources": "File: File Modification, Logon Session: Logon Session Creation, Process: OS API Execution, Process: Process Access",
        "log_sources": [
            {"type": "File", "source": "", "destination": ""},
            {"type": "Logon Session", "source": "", "destination": ""},
            {"type": "Process", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Process", "location": "lsass.exe", "identify": "Patched in-memory authentication routines"}
        ],
        "destination_artifacts": [],
        "detection_methods": [
            "Memory integrity monitoring on LSASS",
            "API call tracing to OpenProcess targeting LSASS",
            "Audit DLL exports for cryptdll.dll/samsrv.dll",
            "Unusual logon patterns and concurrent account usage"
        ],
        "apt": [
            "Chimera"
        ],
        "spl_query": [
            "index=windows_logs process_name=lsass.exe OR dll_name=cryptdll.dll OR dll_name=samsrv.dll\n| search api_call=OpenProcess OR memory_patch=true"
        ],
        "hunt_steps": [
            "Check domain controller for LSASS tampering.",
            "Analyze authentication DLLs for modified exports.",
            "Investigate logon sessions for reused credentials across endpoints."
        ],
        "expected_outcomes": [
            "Detection of authentication bypass via skeleton key",
            "Concurrent access to multiple systems using same credentials"
        ],
        "false_positive": "Security tools may access LSASS memory for legit reasons. Validate against process signature and behavior.",
        "clearing_steps": [
            "Reboot domain controller to clear memory-only patches.",
            "Perform memory dump and forensic analysis of LSASS.",
            "Restore and verify integrity of authentication DLLs."
        ],
        "clearing_playbook": [
            "https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-phishing"
        ],
        "mitre_mapping": [
            {"tactic": "Privilege Escalation", "technique": "T1055", "example": "LSASS memory manipulation for credential access."}
        ],
        "watchlist": [
            "OpenProcess access to lsass.exe",
            "Simultaneous logins using different credentials on same endpoint",
            "Modifications to authentication-related DLLs"
        ],
        "enhancements": [
            "Enable Credential Guard on domain controllers.",
            "Integrate live memory scanning with endpoint monitoring tools"
        ],
        "summary": "Adversaries can gain stealthy and persistent access to domain accounts by patching LSASS on domain controllers to inject a skeleton key. This backdoor method bypasses standard credential validation until a system reboot.",
        "remediation": "Restart the affected domain controller, verify DLL integrity, and perform credential hygiene and audit.",
        "improvements": "Deploy endpoint monitoring with LSASS integrity validation and analyze anomalies in domain login behavior.",
        "mitre_version": "16.1"
    }