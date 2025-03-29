def get_content():
    return {
        "id": "T1218.005",
        "url_id": "T1218/005",
        "title": "System Binary Proxy Execution: Mshta",
        "tactic": "Defense Evasion",
        "protocol": "HTTP, HTTPS, VBScript, JavaScript",
        "os": "Windows",
        "tips": [
            "Look for `mshta.exe` spawning child processes unexpectedly or executing script directly from URLs.",
            "Monitor command-line arguments passed to `mshta.exe`, especially those containing inline scripting or suspicious URLs.",
            "If HTA files are not used legitimately in your environment, treat any invocation of `mshta.exe` as suspicious."
        ],
        "data_sources": "Command Execution, File Creation, Network Connection Creation, Process Creation",
        "log_sources": [
            {"type": "Process Creation", "source": "Sysmon (Event ID 1)", "destination": "SIEM"},
            {"type": "Command Execution", "source": "Windows Event Logs (4688)", "destination": "SIEM"},
            {"type": "Network Traffic", "source": "Firewall or Proxy Logs", "destination": "SIEM"},
            {"type": "File Creation", "source": "EDR or AV telemetry", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "HTA or SCT File", "location": "Web URLs or Temp directories", "identify": "Script-based payloads executed via mshta.exe"}
        ],
        "destination_artifacts": [
            {"type": "Process", "location": "Memory", "identify": "Suspicious child processes spawned from mshta.exe (e.g., powershell.exe, cmd.exe)"}
        ],
        "detection_methods": [
            "Monitor use of `mshta.exe` especially with inline script blocks or remote URLs.",
            "Analyze parent-child process relationships to detect mshta.exe spawning unusual binaries.",
            "Check proxy logs for `.hta` or `.sct` file downloads followed by mshta invocation."
        ],
        "apt": ["G0032", "G0067", "G0133", "G0096"],
        "spl_query": [
            "index=windows sourcetype=WinEventLog:Security EventCode=4688 New_Process_Name=*mshta.exe*",
            "index=sysmon EventCode=1 Image=*\\mshta.exe CommandLine=*script:* OR CommandLine=*http*",
            "index=proxy OR index=network dest_url=*hta OR *sct | stats count by src_ip, dest_url"
        ],
        "hunt_steps": [
            "Search for mshta.exe usage with embedded scripting or references to external .hta/.sct URLs.",
            "Correlate mshta.exe executions with child processes that perform discovery, download tools, or exfiltrate data.",
            "Look for unusual download patterns of HTA/SCT payloads followed by mshta execution.",
            "Cross-reference known attacker infrastructure or indicators of compromise from threat intelligence."
        ],
        "expected_outcomes": [
            "Detection of unauthorized mshta.exe execution invoking remote scripts or payloads.",
            "Identification and blocking of attacker infrastructure hosting HTA/SCT files.",
            "Enrichment of threat intelligence with attacker behavior patterns leveraging mshta."
        ],
        "false_positive": "Legitimate applications occasionally use HTA for internal administration tasks, though rare in modern environments.",
        "clearing_steps": [
            "Terminate any mshta.exe process associated with malicious execution.",
            "Delete associated HTA/SCT files and revoke any user accounts used in the abuse chain.",
            "Apply AppLocker/WDAC rules to restrict mshta usage to authorized scripts only."
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1218.005 (System Binary Proxy Execution: Mshta)", "example": "Executing malicious VBScript via mshta.exe to evade traditional controls."}
        ],
        "watchlist": [
            "Trigger alerts on mshta.exe executed with command-line arguments containing `vbscript:` or `http:`.",
            "Flag any access to remote `.hta` or `.sct` files followed by mshta execution.",
            "Watch for HTA-based payload delivery in phishing or drive-by campaigns."
        ],
        "enhancements": [
            "Restrict mshta.exe execution via WDAC or AppLocker.",
            "Implement browser-based security controls to prevent download or execution of HTA/SCT content.",
            "Apply behavioral signatures to detect process chains involving mshta."
        ],
        "summary": "Mshta.exe is a signed Microsoft binary that can be abused by adversaries to execute malicious HTA, VBScript, or JavaScript content, often remotely hosted, bypassing standard security controls.",
        "remediation": "Disable or restrict mshta.exe via Windows Defender Application Control or AppLocker. Audit and block HTA execution in environments where it is not required.",
        "improvements": "Train analysts on detecting mshta abuse, implement sandbox analysis for HTA payloads, and integrate URL/IP threat feeds to catch remote script sources.",
        "mitre_version": "16.1"
    }
