def get_content():
    return {
        "id": "T1222.001",
        "url_id": "T1222/001",
        "title": "Windows File and Directory Permissions Modification",
        "description": "Adversaries may modify file or directory permissions/attributes to evade access control lists (ACLs) and access protected files. Windows implements file and directory ACLs as Discretionary Access Control Lists (DACLs), which identify accounts that are allowed or denied access to securable objects. Adversaries can abuse built-in Windows utilities like `icacls`, `cacls`, `takeown`, and `attrib`, or use PowerShell cmdlets to interact with DACLs, potentially enabling persistence, privilege escalation, or execution flow hijacking.",
        "tags": ["ACL evasion", "icacls", "takeown", "PowerShell DACL", "Windows permissions", "defense evasion"],
        "tactic": "Defense Evasion",
        "protocol": "",
        "os": "Windows",
        "tips": [
            "Track use of icacls, cacls, and takeown on critical folders.",
            "Review PowerShell commands modifying file permissions.",
            "Baseline normal DACL changes and alert on deviations."
        ],
        "data_sources": "Active Directory, Command, File, Process",
        "log_sources": [
            {"type": "Active Directory", "source": "Windows Security", "destination": ""},
            {"type": "Command", "source": "Sysmon", "destination": ""},
            {"type": "File", "source": "Windows Security", "destination": ""},
            {"type": "Process", "source": "Sysmon", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Windows Security Logs", "location": "Security.evtx", "identify": "Event ID 4670 - DACL modification"},
            {"type": "Sysmon Logs", "location": "Microsoft-Windows-Sysmon/Operational", "identify": "PowerShell or icacls command modifying DACL"}
        ],
        "destination_artifacts": [],
        "detection_methods": [
            "Audit DACL changes with Security Event ID 4670",
            "Monitor for PowerShell cmdlets altering permissions",
            "Track usage of takeown.exe, attrib.exe on sensitive files"
        ],
        "apt": [
            "Ryuk", "WastedLocker", "BlackCat", "PLATINUM", "Grandoreiro", "Indrik Spider", "CaddyWiper", "WannaCry"
        ],
        "spl_query": [
            "index=wineventlog EventCode=4670 \n| stats count by ObjectName, SubjectUserName, ProcessName",
            "index=sysmon EventCode=1 Image=*powershell.exe OR Image=*icacls.exe \n| search CommandLine=*DACL* OR CommandLine=*takeown* \n| stats count by CommandLine, User, Image"
        ],
        "hunt_steps": [
            "Detect recent DACL modifications to sensitive directories",
            "Correlate changes with associated process or user",
            "Validate ownership and inheritance permissions after observed changes"
        ],
        "expected_outcomes": [
            "Detection of unauthorized DACL changes",
            "Revealing attempts to bypass ACL restrictions",
            "Increased insight into persistence setup or privilege escalation"
        ],
        "false_positive": "Administrators or software updates may trigger legitimate DACL changes. Use context and frequency to reduce false alerts.",
        "clearing_steps": [
            "Use icacls or PowerShell to restore original ACL settings",
            "Reapply correct permissions via GPO or SCCM",
            "Revoke inappropriate ownership or full control permissions"
        ],
        "clearing_playbook": [
            "https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-malware"
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1222.001", "example": "Use of takeown and icacls to enable execution of otherwise protected binaries"},
            {"tactic": "Persistence", "technique": "T1546.008", "example": "Enabling access to accessibility binaries by taking ownership and modifying DACLs"},
            {"tactic": "Privilege Escalation", "technique": "T1574", "example": "Modify startup file permissions to hijack execution flow"}
        ],
        "watchlist": [
            "PowerShell commands modifying DACLs",
            "Takeown used outside expected maintenance windows",
            "Permissions change events near ransomware execution timestamps"
        ],
        "enhancements": [
            "Alert on changes to DACLs on C:\\Windows\\System32",
            "Restrict use of permission modification utilities to admin group only",
            "Audit scheduled tasks and services for altered file paths with lax permissions"
        ],
        "summary": "Windows File and Directory Permissions Modification enables adversaries to elevate access and evade defenses by altering DACLs using native tools. These actions may serve as prerequisites for persistence, data access, or execution flow manipulation.",
        "remediation": "Audit permissions regularly. Reapply hardened ACLs. Prevent unauthorized changes via access restrictions and endpoint monitoring.",
        "improvements": "Implement EDR detections for takeown/icacls/cacls usage. Restrict ownership transfer rights. Use signed baselines for DACL auditing.",
        "mitre_version": "16.1"
    }
