def get_content():
    return {
        "id": "T1059.006",  # Tactic Technique ID
        "url_id": "1059/006",  # URL segment for technique reference
        "title": "Command and Scripting Interpreter: Python",  # Name of the attack technique
        "description": "Adversaries may abuse Python for malicious script execution across Windows, macOS, and Linux.",  # Simple description of the attack technique
        "tags": [
            "execution",
            "python",
            "command and scripting interpreter"
        ],
        "tactic": "Execution",  # Associated MITRE ATT&CK tactic
        "protocol": "N/A",  # Protocol used in the attack technique (Python is typically executed locally, though can be remote)
        "os": "Windows, macOS, Linux",  # Targeted operating systems
        "tips": [
            "Monitor Python process creation and command-line arguments for suspicious activity.",
            "Restrict or remove Python installations on systems where it is not required.",
            "Capture and analyze Python scripts when possible to determine malicious actions.",
            "Establish baseline usage patterns to reduce false positives from legitimate developers."
        ],
        "data_sources": "Windows Security, Windows System, Sysmon, Linux Auditd, macOS System logs",
        "log_sources": [
            {
                "type": "Windows Security",
                "source": "Event ID 4688 (Process Creation)",
                "destination": "SIEM"
            },
            {
                "type": "Sysmon",
                "source": "Event ID 1 (Process Creation)",
                "destination": "SIEM"
            },
            {
                "type": "Linux Auditd",
                "source": "/var/log/audit/audit.log",
                "destination": "SIEM"
            },
            {
                "type": "macOS System",
                "source": "Unified logs",
                "destination": "SIEM"
            }
        ],
        "source_artifacts": [
            {
                "type": "Script",
                "location": "Local disk or network share",
                "identify": "Python files (.py) or obfuscated scripts"
            },
            {
                "type": "Process",
                "location": "Running processes",
                "identify": "python.exe or python processes with suspicious arguments"
            }
        ],
        "destination_artifacts": [
            {
                "type": "File",
                "location": "Downloaded or created by Python scripts",
                "identify": "Malicious payload or data exfiltration files"
            },
            {
                "type": "Network Traffic",
                "location": "Outbound connections",
                "identify": "Suspicious Python-based HTTP/HTTPS or other protocol usage"
            }
        ],
        "detection_methods": [
            "Analyze process creation events for python or python.exe usage",
            "Review command-line arguments for suspicious or obfuscated code",
            "Correlate Python processes with unexpected network connections",
            "Monitor file modifications by Python scripts in sensitive directories"
        ],
        "apt": [
            "APT31",
            "MuddyWater",
            "Kimsuky",
            "Machete"
        ],
        "spl_query": [
            "sourcetype=WinEventLog:Security EventCode=4688 CommandLine=*python* \n| stats count by Host, AccountName, CommandLine"
        ],
        "hunt_steps": [
            "Gather Windows Security, Sysmon, Linux Audit, and macOS logs for process creation events involving Python.",
            "Search for unknown or obfuscated Python scripts in unusual directories.",
            "Check for newly installed Python interpreters on hosts that do not typically use Python.",
            "Correlate suspicious Python processes with network traffic for possible data exfiltration or command-and-control."
        ],
        "expected_outcomes": [
            "Identification of malicious Python usage or scripts outside of normal developer workflows.",
            "Detection of Python-based post-compromise activities such as data collection or lateral movement.",
            "Correlation of Python execution with other indicators of compromise to uncover full attack paths."
        ],
        "false_positive": "Legitimate Python usage by developers or automation tasks can generate alerts; tuning is required to reduce noise.",
        "clearing_steps": [
            "Terminate suspicious Python processes and remove associated scripts.",
            "Uninstall or restrict Python on systems where it is not required.",
            "Investigate and remediate any compromised user accounts or credentials used to run malicious scripts.",
            "Review and restore system configurations or files altered by the malicious Python activities."
        ],
        "mitre_mapping": [
            {
                "tactic": "Defense Evasion",
                "technique": "Obfuscated Files or Information (T1027)",
                "example": "Adversaries may use obfuscated Python scripts to avoid detection."
            }
        ],
        "watchlist": [
            "Python executions with encoded or obfuscated command arguments",
            "Python scripts located in temporary or user directories that are unusual for Python development",
            "Frequent or repetitive Python execution on endpoints with no legitimate business need"
        ],
        "enhancements": [
            "Implement application control solutions to block unauthorized Python binaries or scripts.",
            "Enable script-based logging or EDR solutions that can capture Python command execution details.",
            "Use sandboxing or detonation environments for suspicious Python scripts."
        ],
        "summary": "Python is a cross-platform scripting language that adversaries may abuse for malicious code execution and automation.",
        "remediation": "Limit Python installations to necessary systems, enforce strong monitoring and logging, and isolate suspicious Python activities.",
        "improvements": "Deploy advanced endpoint detection solutions capable of inspecting script content, and develop robust threat hunting playbooks for Python-based threats."
    }
