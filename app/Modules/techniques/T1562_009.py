def get_content():
    return {
        "id": "T1562.009",
        "url_id": "T1562/009",
        "title": "Impair Defenses: Safe Mode Boot",
        "description": "Adversaries may abuse Windows Safe Mode to disable endpoint defenses. Safe Mode launches Windows with a minimal set of drivers and services, which often excludes third-party security tools such as EDR and antivirus solutions. By booting into Safe Mode, attackers can evade detection, disable protections, or perform malicious activity with fewer constraints.\n\nSafe Mode can be triggered by modifying Boot Configuration Data (BCD) using utilities like `bcdedit.exe` or `bootcfg.exe`. Furthermore, adversaries may configure their malware to persist by adding entries to registry keys responsible for starting services during Safe Mode, such as `HKLM\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal`. Malicious programs can also use techniques like registering COM objects to execute in Safe Mode.\n\nThis tactic is frequently observed in ransomware attacks and advanced evasion campaigns.",
        "tags": ["safemode", "bcdedit", "bootcfg", "registry", "evasion", "ransomware"],
        "tactic": "Defense Evasion",
        "protocol": "",
        "os": "Windows",
        "tips": [
            "Alert on modifications to BCD using `bcdedit` or `bootcfg` commands.",
            "Track new services or registry values that load during Safe Mode.",
            "Monitor Safe Mode reboots on non-maintenance windows in enterprise environments."
        ],
        "data_sources": "Command, Process, Windows Registry",
        "log_sources": [
            {"type": "Command", "source": "CLI", "destination": ""},
            {"type": "Process", "source": "Host", "destination": ""},
            {"type": "Windows Registry", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Command Execution", "location": "bcdedit.exe, bootcfg.exe", "identify": "Configuring system to boot into Safe Mode"},
            {"type": "Registry Keys", "location": "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal", "identify": "Injected malware persistence"},
            {"type": "Startup Scripts", "location": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "identify": "Startup entries with leading * to execute in Safe Mode"}
        ],
        "destination_artifacts": [
            {"type": "Process Creation", "location": "Event ID 4688 or Sysmon ID 1", "identify": "Execution of boot modification commands"},
            {"type": "Registry Modifications", "location": "SafeBoot and Run keys", "identify": "Unusual or unauthorized modifications"},
            {"type": "System Boot State", "location": "Windows logs or boot records", "identify": "Booted into Safe Mode unexpectedly"}
        ],
        "detection_methods": [
            "Monitor for use of `bcdedit` or `bootcfg` to configure Safe Mode boot",
            "Detect registry key additions under SafeBoot\\Minimal or SafeBoot\\Network",
            "Watch for execution of non-standard services or programs after Safe Mode boot",
            "Correlate system reboots with changes to BCD or Safe Mode indicators"
        ],
        "apt": ["Black Basta", "REvil", "MedusaLocker", "AvosLocker"],
        "spl_query": [
            "index=wineventlog EventCode=4688 \n| search CommandLine IN (*bcdedit*, *bootcfg*) \n| stats count by host, user, CommandLine",
            "index=sysmon EventCode=1 \n| search Image=*bcdedit.exe* OR Image=*bootcfg.exe* \n| stats count by host, Image, CommandLine",
            "index=wineventlog EventCode=4657 \n| search ObjectName=\"*SafeBoot*\" OR ObjectName=\"*CurrentVersion\\Run*\" \n| stats count by host, ObjectName, NewValue"
        ],
        "hunt_steps": [
            "Identify if any systems rebooted into Safe Mode unexpectedly",
            "Check registry for new keys under SafeBoot\\Minimal and Run with suspicious values",
            "Correlate safe boot triggers with known malware indicators or suspicious file drops",
            "Search for use of `bcdedit.exe` shortly before reboot or ransomware execution"
        ],
        "expected_outcomes": [
            "Discovery of unauthorized BCD changes pointing to Safe Mode boot",
            "Detection of malicious persistence entries loading only in Safe Mode",
            "Alerting on COM object or registry manipulation tied to malware activity"
        ],
        "false_positive": "System administrators may use Safe Mode during legitimate troubleshooting. Validate by correlating with tickets or known maintenance events.",
        "clearing_steps": [
            "Remove unauthorized BCD entries with `bcdedit /deletevalue safeboot`",
            "Delete malicious registry entries from SafeBoot and Run keys",
            "Reboot system into normal mode and restore legitimate service configuration"
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1562.009", "example": "Using bcdedit to force a reboot into Safe Mode and disable EDR"}
        ],
        "watchlist": [
            "Creation of registry keys under SafeBoot\\Minimal or Run with * prefix",
            "Safe Mode boots on systems with no maintenance scheduled",
            "Repeated use of boot modification tools by unauthorized users"
        ],
        "enhancements": [
            "Configure endpoint protection tools to run in Safe Mode or detect safe boot entries",
            "Use EDRs capable of triggering alerts on BCD modifications or unexpected Safe Mode",
            "Harden permissions for modifying boot configurations"
        ],
        "summary": "T1562.009 covers adversary use of Windows Safe Mode to disable security controls and ensure malware execution. Through BCD edits and registry manipulation, attackers can achieve stealth and persistence.",
        "remediation": "Restrict access to boot configuration tools, detect and alert on Safe Mode triggers, and use security tools that operate even in limited boot environments.",
        "improvements": "Apply Group Policy restrictions on bootloader tools, enable auditing on critical registry paths, and develop incident response playbooks for Safe Mode abuse.",
        "mitre_version": "16.1"
    }
