def get_content():
    return {
        "id": "T1014",
        "url_id": "T1014",
        "title": "Rootkit",
        "description": "Adversaries may use rootkits to hide the presence of malware by intercepting and modifying OS API calls or lower system layers.",
        "tags": ["rootkit", "defense evasion", "firmware", "MBR", "kernel", "stealth", "malware", "hooking", "driver", "userland"],
        "tactic": "Defense Evasion",
        "protocol": "",
        "os": "Linux, Windows, macOS",
        "tips": [
            "Use memory forensics tools like Volatility to inspect memory for hidden modules.",
            "Enable Secure Boot and disable legacy BIOS when possible.",
            "Re-flash firmware and rebuild from known-good images after detection."
        ],
        "data_sources": "Drive, File, Firmware",
        "log_sources": [
            {"type": "Drive", "source": "", "destination": ""},
            {"type": "File", "source": "", "destination": ""},
            {"type": "Firmware", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Loaded DLLs", "location": "C:\\Windows\\System32\\drivers", "identify": "Suspicious or unsigned kernel drivers"},
            {"type": "Memory Dumps", "location": "Live memory capture", "identify": "Hidden processes or modules"},
            {"type": "Registry Hives (SYSTEM)", "location": "C:\\Windows\\System32\\config\\SYSTEM", "identify": "Malicious service or driver entries"}
        ],
        "destination_artifacts": [
            {"type": "Firmware", "location": "UEFI/BIOS", "identify": "Tampered or unsigned firmware modules"},
            {"type": "File Access Times (MACB Timestamps)", "location": "C:\\Windows\\System32\\drivers", "identify": "Driver tampering or backdating"},
            {"type": "Event Logs", "location": "Windows Event Viewer", "identify": "Unexpected driver/service load activity"}
        ],
        "detection_methods": [
            "Monitor for kernel hooks and hidden drivers using memory forensics tools",
            "Use rootkit scanners such as GMER, chkrootkit, and rkhunter",
            "Baseline signed drivers and services and monitor for deviation",
            "Monitor MBR/UEFI firmware integrity with tools like CHIPSEC"
        ],
        "apt": ["APT28", "Turla", "Rocke", "Winnti", "LoJax"],
        "spl_query": [
            'index=sysmon EventCode=6 ImageLoaded="*\\\\drivers\\\\*.sys" \n| search NOT ImageLoaded IN ("*signed*", "*trusted*")',
            'index=windows_logs EventCode=1 \n| search CommandLine="*mbr*" OR CommandLine="*rootkit*"',
            'index=sysmon EventCode=7 \n| search ImageLoaded="*unknown_driver.sys"'
        ],
        "hunt_steps": [
            "Search memory for hidden drivers or kernel hooks",
            "Check for unsigned drivers loaded at boot",
            "Inspect SYSTEM registry hive for suspicious services",
            "Compare UEFI hashes against manufacturer baselines"
        ],
        "expected_outcomes": [
            "Discovery of hidden kernel modules",
            "Detection of tampered firmware or boot sector",
            "Evidence of stealthy persistence via drivers or services"
        ],
        "false_positive": "Legitimate security software or kernel debugging tools may exhibit similar behaviors; verify signatures and source.",
        "clearing_steps": [
            "Boot from trusted media and collect memory image",
            "Reflash firmware using OEM tools",
            "Wipe and reinstall operating system from clean media",
            "Reset secure boot keys and re-enable secure boot"
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1556.001", "example": "Rootkit hides credential access tools via service-level hooks"},
            {"tactic": "Persistence", "technique": "T1542.001", "example": "Firmware-based rootkits persist even after OS reinstallation"}
        ],
        "watchlist": [
            "Unsigned drivers in System32\\drivers",
            "Processes hidden from task managers but visible in memory",
            "Unexplained changes to MBR or BIOS configuration"
        ],
        "enhancements": [
            "Enable Secure Boot and firmware integrity checking",
            "Deploy EDR solutions capable of memory and kernel inspection",
            "Regularly validate driver and service baselines"
        ],
        "summary": "Rootkits allow adversaries to conceal malicious activity by modifying core components of the operating system or firmware, enabling long-term persistence and stealth.",
        "remediation": "Rebuild the affected system from trusted sources. Reset secure boot keys, reflash firmware, and wipe all affected drives.",
        "improvements": "Incorporate firmware scanning into standard forensic processes. Automate integrity checks against driver and bootloader baselines.",
        "mitre_version": "16.1"
    }
