def get_content():
    return {
        "id": "T1216.002",
        "url_id": "T1216/002",
        "title": "System Script Proxy Execution: SyncAppvPublishingServer",
        "description": "Adversaries may abuse SyncAppvPublishingServer.vbs, a signed Microsoft Visual Basic script used for virtual application publishing (App-V), to proxy PowerShell command execution. By passing a PowerShell command as a parameter to this script, adversaries may bypass script execution policies or evade detection controls. This method can serve as an alternative to directly invoking `powershell.exe`, leveraging a trusted and signed binary.",
        "tags": ["LOLBAS", "Defense Evasion", "Script Proxy Execution", "SyncAppvPublishingServer", "PowerShell Bypass"],
        "tactic": "Defense Evasion",
        "protocol": "",
        "os": "Windows",
        "tips": [
            "Hunt for abnormal use of SyncAppvPublishingServer.vbs with PowerShell-like syntax in its parameters.",
            "Flag execution of VBScript interpreters (`wscript.exe`, `cscript.exe`) invoking this script.",
            "Implement AppLocker or WDAC rules that restrict usage of high-risk, seldom-used signed scripts."
        ],
        "data_sources": "Script Execution, Process Creation, Command-Line Monitoring",
        "log_sources": [
            {"type": "Script", "source": "Sysmon Event ID 1", "destination": ""},
            {"type": "Command", "source": "Event ID 4688 (Windows Security)", "destination": ""},
            {"type": "Process", "source": "EDR Tools (Defender ATP, CrowdStrike, etc.)", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Script File", "location": "C:\\Windows\\System32\\SyncAppvPublishingServer.vbs", "identify": "Launched with suspicious command-line containing PowerShell keywords"}
        ],
        "destination_artifacts": [
            {"type": "Child Process", "location": "Spawned PowerShell instance", "identify": "Command-line with encoded or obfuscated PowerShell content"}
        ],
        "detection_methods": [
            "Detect command-line arguments invoking SyncAppvPublishingServer.vbs with embedded PowerShell code.",
            "Look for `wscript.exe` or `cscript.exe` processes using this script in rare contexts.",
            "Correlate script execution with outbound connections or lateral movement behavior."
        ],
        "apt": [],
        "spl_query": [
            "index=windows (Image=\"*SyncAppvPublishingServer.vbs*\" AND CommandLine=\"*powershell*\") | table _time, host, user, Image, CommandLine"
        ],
        "hunt_steps": [
            "Search for SyncAppvPublishingServer.vbs usage in EDR or SIEM logs.",
            "Correlate usage with known PowerShell execution sequences or LOLBAS activity.",
            "Review parent-child process trees for unusual command flow via `wscript.exe` or `powershell.exe`."
        ],
        "expected_outcomes": [
            "Identification of evasion attempts using SyncAppvPublishingServer.vbs.",
            "Establishment of baseline usage to reduce false positives."
        ],
        "false_positive": "Rare, but may occur in environments where App-V is actively used and the script is legitimately invoked.",
        "clearing_steps": [
            "Kill suspicious processes.",
            "Restrict script execution via AppLocker or Software Restriction Policies.",
            "Investigate endpoint behavior for post-execution activity (e.g., lateral movement, credential access)."
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1216.002", "example": "Adversaries invoke SyncAppvPublishingServer.vbs with embedded PowerShell to evade detection."}
        ],
        "watchlist": [
            "Flag any execution of SyncAppvPublishingServer.vbs that includes inline code execution or suspicious parameters.",
            "Monitor for this script used outside its normal operational context (e.g., during lateral movement)."
        ],
        "enhancements": [
            "Develop custom detection signatures for abuse of VBScript proxy scripts.",
            "Incorporate LOLBAS techniques into continuous threat hunting cycles.",
            "Apply behavioral baselining to signed script usage across the enterprise."
        ],
        "summary": "SyncAppvPublishingServer.vbs can be abused by adversaries to execute PowerShell commands indirectly, bypassing script restrictions and leveraging Microsoft's signed binaries to evade defenses.",
        "remediation": "Disable or restrict usage of legacy signed scripts like SyncAppvPublishingServer.vbs unless operationally required. Apply command-line auditing and behavioral controls.",
        "improvements": "Enforce strict allowlisting, implement PowerShell Constrained Language Mode, and monitor for indirect execution chains from LOLBAS binaries.",
        "mitre_version": "16.1"
    }
