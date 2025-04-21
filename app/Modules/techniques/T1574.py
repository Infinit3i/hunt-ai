def get_content():
    return {
        "id": "T1574",
        "url_id": "T1574",
        "title": "Hijack Execution Flow",
        "description": "Adversaries may execute their own malicious payloads by hijacking the way operating systems run programs. Hijacking execution flow can be used for persistence, privilege escalation, and defense evasion by loading adversary-controlled code into trusted processes.\n\nCommon techniques include DLL search order hijacking, unquoted service paths, environment variable abuse, registry manipulation, and binary replacement. The goal is to alter how the OS or application locates and loads executable code or libraries, often without detection. These hijacks may exploit file system, registry, or environmental weaknesses to insert malicious payloads.\n\nThis behavior can lead to stealthy persistence, privilege escalation, and execution of code that masquerades as legitimate system behavior. Detection relies on analyzing process behavior, file system changes, environment variables, and registry activity for anomalies that indicate execution flow redirection.",
        "tags": ["execution_hijack", "persistence", "privilege_escalation", "defense_evasion", "MITRE"],
        "tactic": "Defense Evasion",
        "protocol": "N/A",
        "os": "Windows, Linux, macOS",
        "tips": [
            "Use Sysinternals Autoruns to detect changes in system execution paths.",
            "Restrict write access to critical application and system directories.",
            "Harden execution policies using AppLocker or Windows Defender Application Control."
        ],
        "data_sources": "Process Monitoring, Windows Event, Sysmon, EDR, Registry, File System",
        "log_sources": [
            {"type": "Process Execution Logs", "source": "Sysmon (Event ID 1 - Process Creation), Windows Security Logs", "destination": ""},
            {"type": "Registry Modification Logs", "source": "Sysmon (Event ID 13 - Registry Modification), Windows Event Logs", "destination": ""},
            {"type": "DLL Load Monitoring", "source": "Sysmon (Event ID 7 - DLL Load)", "destination": ""},
            {"type": "Threat Intelligence Feeds", "source": "VirusTotal, Hybrid Analysis, MISP", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "DLL/EXE", "location": "%TEMP%, %APPDATA%, C:\\Users\\Public", "identify": "Hijacked or injected payloads placed alongside legitimate executables"}
        ],
        "destination_artifacts": [
            {"type": "Registry Keys, DLLs, Services", "location": "HKLM\\SYSTEM\\CurrentControlSet\\Services, C:\\Windows\\System32", "identify": "Modified service paths, DLLs, or hijacked registry values"}
        ],
        "detection_methods": [
            "Monitor for unsigned DLLs loaded by signed processes from unusual directories.",
            "Alert on creation or modification of registry values related to service configuration or execution flow.",
            "Correlate process behavior to detect child processes or network activity inconsistent with parent application profiles."
        ],
        "apt": [
            "APT10", "APT41", "LuminousMoth", "Cobalt Kitty", "Sidewinder", "TA416", "LuckyMouse",
            "MUSTANG PANDA", "OceanLotus", "PlugX", "Emissary Panda", "Patchwork", "Metador", "Raspberry Robin"
        ],
        "spl_query": "index=sysmon sourcetype=\"Sysmon\" EventCode=7\n| where Image like '%\\Temp\\%' OR Image like '%\\Users\\Public\\%'\n| stats count by Image, ProcessId, ProcessName",
        "hunt_steps": [
            "Run Queries in SIEM: Detect execution flow hijacking via DLL injection or registry modifications.",
            "Correlate with Threat Intelligence Feeds: Validate loaded DLLs and modified registry entries against known attack techniques.",
            "Analyze Execution Context: Identify which user or service account made modifications to execution flow.",
            "Investigate Persistence Mechanisms: Look for scheduled tasks, registry persistence, or startup folder entries related to hijacked execution flow.",
            "Validate & Escalate: If execution flow hijacking activity is detected → Escalate to Incident Response."
        ],
        "expected_outcomes": [
            "Execution Flow Hijack Detected: Block or remove the hijacked execution flow modification. Investigate further for malware persistence or lateral movement.",
            "No Malicious Activity Found: Improve baseline monitoring for legitimate execution flow changes."
        ],
        "false_positive": "Some developers use execution redirection techniques for debugging or legacy support. Correlate with update/install behavior and known-good hashes before escalating.",
        "clearing_steps": [
            "Remove the malicious DLL or binary from hijacked location.",
            "Restore registry keys or system paths to their legitimate state.",
            "Reapply secure ACLs to directories and binaries involved.",
            "Reset affected service configurations or rebuild affected systems if systemic tampering is discovered."
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1574 (Hijack Execution Flow)", "example": "Adversaries modify execution flow to run malicious code."},
            {"tactic": "Execution", "technique": "T1204.002 (User Execution - Malicious File)", "example": "Hijacked processes may execute unauthorized payloads."},
            {"tactic": "Persistence", "technique": "T1098 (Account Manipulation)", "example": "Attackers may modify user accounts to maintain access."}
        ],
        "watchlist": [
            "Flag execution flow modifications involving DLL injection or registry edits.",
            "Detect process injections targeting critical system processes.",
            "Monitor unusual child process behavior linked to execution hijacking."
        ],
        "enhancements": [
            "Implement application control policies to prevent unauthorized execution modifications.",
            "Deploy endpoint detection for hijacking-based persistence techniques.",
            "Harden registry and process execution policies to prevent manipulation."
        ],
        "summary": "Monitor and detect execution flow hijacking attempts by analyzing process execution, DLL loading, and registry modifications. This technique is widely abused by threat actors for stealthy persistence and privilege escalation.",
        "remediation": "Block unauthorized execution flow modifications, investigate further for malware persistence, and improve detection baselines.",
        "improvements": "Strengthen process monitoring policies and enhance security configurations to prevent execution hijacking.",
        "mitre_version": "16.1"
    }
