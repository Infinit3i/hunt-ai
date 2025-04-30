def get_content():
    return {
        "id": "T1003.001",
        "url_id": "T1003/001",
        "title": "OS Credential Dumping: LSASS Memory",
        "description": "Adversaries may access credentials stored in LSASS memory by dumping its content or interacting with it through various tools and techniques.",
        "tags": ["lsass", "mimikatz", "comsvcs.dll", "rundll32", "ssp", "werfault", "credential dumping"],
        "tactic": "Credential Access",
        "protocol": "",
        "os": "Windows",
        "tips": [
            "Monitor for suspicious access to LSASS memory (e.g., procdump, mimikatz, comsvcs.dll)",
            "Enable LSASS as a protected process on supported systems",
            "Implement Credential Guard or isolate LSASS using Windows Defender Exploit Guard"
        ],
        "data_sources": "Sysmon, Command File, Logon Session, Process, Windows Registry",
        "log_sources": [
            {"type": "Command", "source": "", "destination": ""},
            {"type": "File", "source": "", "destination": ""},
            {"type": "Logon Session", "source": "", "destination": ""},
            {"type": "Process", "source": "", "destination": ""},
            {"type": "Windows Registry", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Memory Dumps", "location": "C:\\Windows\\Temp\\ or attacker-defined location", "identify": "lsass.dmp, lsass_dump.dmp"},
            {"type": "Windows Defender Logs", "location": "Microsoft-Windows-Windows Defender/Operational", "identify": "Alerts on credential theft tools"},
            {"type": "Windows Registry Hives", "location": "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\Security Packages", "identify": "Added/modified SSPs"}
        ],
        "destination_artifacts": [],
        "detection_methods": [
            "Monitor LSASS memory access by unauthorized tools (e.g., procdump, mimikatz, comsvcs.dll)",
            "Track process access to LSASS using Sysmon Event ID 10 or Event Tracing for Windows",
            "Inspect loaded Security Support Provider (SSP) DLLs"
        ],
        "apt": [
            "APT1", "APT33", "APT34", "APT35", "APT39", "APT40", "APT41", "BRONZE BUTLER", "BRONZE PRESIDENT", "Cobalt Kitty", "Elfin", "FIN6", "FIN8", "FIN12", "FIN13",
            "GALLIUM", "Ke3chang", "Leafminer", "Lyceum", "Metador", "MuddyWater", "PLATINUM", "Sednit", "StellarParticle", "Tick", "Turla", "Volt Typhoon", "WastedLocker"
        ],
        "spl_query": [
            'index=sysmon (EventCode=10 OR EventCode=1) process_name IN ("procdump.exe", "rundll32.exe", "mimikatz.exe", "powershell.exe") command_line="*lsass*"',
            'index=wineventlog EventCode=4688 CommandLine="*lsass*" AND ParentProcessName!="lsass.exe"'
        ],
        "hunt_steps": [
            "Search for suspicious processes accessing LSASS memory (e.g., Event ID 10)",
            "Look for command-line use of tools targeting lsass.exe",
            "Check for memory dump artifacts on disk",
            "Review registry keys for unauthorized SSP DLLs"
        ],
        "expected_outcomes": [
            "Detection of credential access through LSASS interaction",
            "Identification of unauthorized memory dump activity",
            "Evidence of lateral movement preparation using stolen credentials"
        ],
        "false_positive": "Legitimate tools like antivirus or backup agents may access LSASS. Validate process origin and parent-child relationships.",
        "clearing_steps": [
            "Delete any LSASS dumps: `del /f /q C:\\path\\to\\lsass.dmp`",
            "Restore original Security Packages in Registry if modified",
            "Reboot system if new SSPs were registered to clear malicious ones from memory",
            "Enable Credential Guard or PPL (Protected Process Light) if supported"
        ],
        "mitre_mapping": [
            {"tactic": "Lateral Movement", "technique": "T1550", "example": "Using credentials stolen from LSASS memory to access remote systems"}
        ],
        "watchlist": [
            "Command-line usage: procdump -ma lsass.exe",
            "rundll32.exe with comsvcs.dll and lsass PID",
            "mimikatz and powershell invoking sekurlsa::"
        ],
        "enhancements": [
            "Enable LSASS as a protected process (PPL) on supported systems",
            "Deploy EDR rules that flag LSASS access from non-whitelisted binaries",
            "Implement Attack Surface Reduction (ASR) rules to block credential theft"
        ],
        "summary": "Adversaries target the LSASS process to obtain in-memory credentials, using tools like Mimikatz, procdump, or custom DLLs, enabling lateral movement and privilege escalation.",
        "remediation": "Remove dumped credential files, restore clean registry configurations, implement LSASS protection and EDR alerts for credential access behaviors.",
        "improvements": "Use Secure Boot, Credential Guard, and protected LSASS to harden against this technique. Educate staff on securing privileged sessions.",
        "mitre_version": "16.1"
    }
