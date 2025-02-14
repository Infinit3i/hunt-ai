def get_content():
    return {
        "id": "T1574",
        "url_id": "T1574",
        "title": "Hijack Execution Flow",
        "tactic": "Defense Evasion",
        "data_sources": "Process Monitoring, Windows Event, Sysmon, EDR, Registry, File System",
        "protocol": "N/A",
        "os": "Windows, Linux, macOS",
        "objective": "Detect and mitigate hijack execution flow attacks, where adversaries manipulate the normal execution flow of processes to execute malicious code.",
        "scope": "Monitor process injections, DLL hijacking, and other execution flow modifications.",
        "threat_model": "Adversaries hijack execution flow to load malicious code into trusted processes, bypass security mechanisms, and persist using execution hijacking techniques.",
        "hypothesis": [
            "Are there unauthorized DLLs loaded by critical system processes?",
            "Are legitimate processes exhibiting unusual execution patterns?",
            "Are there suspicious registry modifications related to execution flow control?"
        ],
        "log_sources": [
            {"type": "Process Execution Logs", "source": "Sysmon (Event ID 1 - Process Creation), Windows Security Logs"},
            {"type": "Registry Modification Logs", "source": "Sysmon (Event ID 13 - Registry Modification), Windows Event Logs"},
            {"type": "DLL Load Monitoring", "source": "Sysmon (Event ID 7 - DLL Load)"},
            {"type": "Threat Intelligence Feeds", "source": "VirusTotal, Hybrid Analysis, MISP"}
        ],
        "detection_methods": [
            "Monitor DLL loads and identify non-standard locations for system-critical DLLs.",
            "Detect registry modifications that indicate execution hijacking (e.g., Image File Execution Options).",
            "Correlate process execution patterns with known hijacking techniques."
        ],
        "spl_query": "index=sysmon sourcetype=\"Sysmon\" EventCode=7 | where Image like '%\\Temp\\%' OR Image like '%\\Users\\Public\\%' | stats count by Image, ProcessId, ProcessName",
        "sigma_rule": "https://grep.app/search?f.repo=SigmaHQ%2Fsigma&q=T1574",
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
        "summary": "Monitor and detect execution flow hijacking attempts by analyzing process execution, DLL loading, and registry modifications.",
        "remediation": "Block unauthorized execution flow modifications, investigate further for malware persistence, and improve detection baselines.",
        "improvements": "Strengthen process monitoring policies and enhance security configurations to prevent execution hijacking."
    }
