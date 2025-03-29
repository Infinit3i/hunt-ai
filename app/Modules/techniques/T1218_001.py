def get_content():
    return {
        "id": "T1218.001",
        "url_id": "T1218/001",
        "title": "System Binary Proxy Execution: Compiled HTML File",
        "tactic": "Defense Evasion",
        "protocol": "N/A",
        "os": "Windows",
        "tips": [
            "Block or restrict the use of hh.exe unless absolutely necessary.",
            "Inspect command-line arguments passed to hh.exe for anomalies.",
            "Monitor for unusual parent-child process relationships involving hh.exe."
        ],
        "data_sources": "Command Execution, File Creation, Process Creation",
        "log_sources": [
            {"type": "Command Execution", "source": "Sysmon Event ID 1", "destination": "SIEM"},
            {"type": "File Creation", "source": "EDR Logs", "destination": "Endpoint Security"},
            {"type": "Process Creation", "source": "Windows Security Logs (4688)", "destination": "SIEM"}
        ],
        "source_artifacts": [
            {"type": "Malicious CHM File", "location": "Email attachment or web download", "identify": "Unexpected .chm files in user directories"}
        ],
        "destination_artifacts": [
            {"type": "Process Tree", "location": "System Processes", "identify": "hh.exe spawning cmd.exe, powershell.exe, or other suspicious children"}
        ],
        "detection_methods": [
            "Monitor hh.exe execution and inspect command-line parameters.",
            "Detect unusual parent-child process relationships involving hh.exe.",
            "Alert on CHM file access or execution in non-standard environments."
        ],
        "apt": ["G0032", "G0096"],
        "spl_query": [
            "index=windows EventCode=4688 NewProcessName=*hh.exe* | table _time, ParentProcessName, CommandLine",
            "index=endpoint process_name=hh.exe | stats count by user, command_line"
        ],
        "hunt_steps": [
            "Identify systems where hh.exe has been executed recently.",
            "Correlate execution of hh.exe with downloaded .chm files or suspicious email attachments.",
            "Analyze command-line arguments and resulting child processes of hh.exe."
        ],
        "expected_outcomes": [
            "Detection of .chm-based evasion or initial access techniques.",
            "Identification of user execution events involving suspicious CHM payloads."
        ],
        "false_positive": "Legitimate help file viewing via hh.exe may occur, though infrequent in most enterprise environments.",
        "clearing_steps": [
            "Remove malicious .chm files and quarantine affected systems.",
            "Revoke any payloads or access mechanisms established via hh.exe abuse.",
            "Patch systems vulnerable to CHM execution bypass techniques."
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1218.001 (System Binary Proxy Execution: CHM)", "example": "hh.exe executing malicious .chm file payloads to evade controls."}
        ],
        "watchlist": [
            "Track use of hh.exe especially outside of system help functions.",
            "Detect CHM file executions initiated by users or suspicious sources."
        ],
        "enhancements": [
            "Apply AppLocker or WDAC rules to restrict hh.exe.",
            "Use behavioral analytics to flag non-standard usage of signed binaries.",
            "Limit script execution from CHM containers via GPO or registry modifications."
        ],
        "summary": "Adversaries may abuse CHM (Compiled HTML Help) files and hh.exe to proxy execution of malicious code, bypassing security tools that do not monitor signed binaries effectively.",
        "remediation": "Limit the use of hh.exe, monitor for abuse of CHM files, and implement application control policies.",
        "improvements": "Integrate CHM-based execution tracking into baseline anomaly detection and educate users on suspicious file attachments.",
        "mitre_version": "16.1"
    }
