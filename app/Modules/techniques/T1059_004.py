def get_content():
    return {
        "id": "T1059.004",  # Tactic Technique ID
        "url_id": "1059/004",  # URL segment for technique reference
        "title": "Command and Scripting Interpreter: Unix Shell",  # Name of the attack technique
        "description": "Adversaries may abuse Unix shell commands and scripts for execution on Linux and macOS systems, leveraging shells like sh, bash, or zsh to run malicious code or automate malicious tasks.",  # Simple description of the attack technique
        "tags": [
            "execution",
            "unix shell",
            "command and scripting interpreter"
        ],
        "tactic": "Execution",  # Associated MITRE ATT&CK tactic
        "protocol": "N/A",  # Typically executed locally, though remote shells exist
        "os": "Linux, macOS",  # Targeted operating systems
        "tips": [
            "Monitor shell script execution, especially in unusual or privileged contexts.",
            "Restrict or disable script execution for users who do not require it.",
            "Capture and analyze shell scripts from the file system to understand malicious actions.",
            "Review environment variables and shell histories for suspicious entries."
        ],
        "data_sources": "Linux Auditd, macOS System logs, Syslog, EDR telemetry",
        "log_sources": [
            {
                "type": "Linux Auditd",
                "source": "/var/log/audit/audit.log",
                "destination": "SIEM"
            },
            {
                "type": "macOS System",
                "source": "Unified logs",
                "destination": "SIEM"
            },
            {
                "type": "Syslog",
                "source": "/var/log/syslog or /var/log/messages",
                "destination": "SIEM"
            }
        ],
        "source_artifacts": [
            {
                "type": "Script",
                "location": "Local disk or network share",
                "identify": "Shell scripts (.sh, .bash, etc.)"
            },
            {
                "type": "Process",
                "location": "Running processes",
                "identify": "sh, bash, zsh, or other Unix shells with suspicious arguments"
            }
        ],
        "destination_artifacts": [
            {
                "type": "File",
                "location": "Downloaded or created by shell scripts",
                "identify": "Potential malicious payloads, data exfiltration files"
            },
            {
                "type": "Network Traffic",
                "location": "Outbound connections",
                "identify": "Suspicious shell-based remote connections (e.g., SSH tunnels)"
            }
        ],
        "detection_methods": [
            "Analyze process creation logs for shell invocations with unusual or privileged contexts",
            "Review command-line arguments and environment variables for obfuscated or malicious commands",
            "Monitor file creation/modification by shell scripts in sensitive directories",
            "Correlate shell script activity with network logs to detect potential data exfiltration or lateral movement"
        ],
        "apt": [
            "APT32",
            "Kobalos",
            "TeamTNT",
            "Machete"
        ],
        "spl_query": [
            "sourcetype=syslog \"bash\" OR \"sh\" OR \"zsh\" \n| stats count by host, process, cmd"
        ],
        "hunt_steps": [
            "Collect and centralize shell process creation events in SIEM.",
            "Search for scripts or shell commands in unexpected or privileged directories.",
            "Correlate suspicious shell activity with network traffic for potential data exfiltration or pivoting.",
            "Investigate any new or modified shell scripts that appear outside typical administrative processes."
        ],
        "expected_outcomes": [
            "Detection of malicious shell usage or scripts used for post-compromise activities.",
            "Identification of unusual or unauthorized shell invocations requiring elevated privileges.",
            "Correlation of shell-based behavior with other intrusion artifacts to reveal broader attack patterns."
        ],
        "false_positive": "Legitimate administrative or developer tasks may trigger similar alerts, requiring careful tuning and baseline creation.",
        "clearing_steps": [
            "Terminate any malicious shell sessions and remove associated scripts.",
            "Revoke compromised credentials and enforce least privilege to limit shell access.",
            "Restore any altered system or application configurations and investigate the source of malicious scripts.",
            "Enhance monitoring on critical systems where shell usage is common but must remain secure."
        ],
        "mitre_mapping": [
            {
                "tactic": "Persistence",
                "technique": "Boot or Logon Initialization Scripts (T1037)",
                "example": "Adversaries may place malicious shell scripts in initialization files to run at startup."
            }
        ],
        "watchlist": [
            "Shell commands that execute base64 or other encoded payloads",
            "Shell scripts that appear in directories where shell usage is not expected",
            "Frequent or scheduled shell script executions occurring outside normal maintenance windows"
        ],
        "enhancements": [
            "Enable EDR solutions that monitor shell processes and script execution in real-time.",
            "Implement application allow-listing to prevent unauthorized shell script execution.",
            "Restrict interactive shell access to privileged accounts only when absolutely necessary."
        ],
        "summary": "Unix shells are integral to Linux and macOS systems but can be exploited by adversaries to execute commands, automate malicious tasks, and establish persistence.",
        "remediation": "Limit shell script usage to necessary administrative or developer tasks, enable detailed logging, and isolate suspicious shell processes.",
        "improvements": "Deploy solutions that detect abnormal shell usage, enforce strict user permissions, and regularly audit shell scripts on critical systems."
    }
