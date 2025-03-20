def get_content():
    return {
        "id": "T1140",  # Tactic Technique ID
        "url_id": "1140",  # URL segment for technique reference
        "title": "Deobfuscate/Decode Files or Information",  # Name of the attack technique
        "description": "Adversaries may decode or deobfuscate files or information to hide artifacts of intrusion from analysis, leveraging built-in malware functionality or system utilities like certutil or copy /b.",  # Simple description (one pair of quotes)
        "tags": [
            "Deobfuscate",
            "Decode",
            "certutil",
            "copy /b",
            "User Execution",
            "Windows API",
            "Malware Analysis",
            "PowerShell",
            "WMI",
            "Encryption"
        ],  # Up to 10 tags
        "tactic": "Defense Evasion",  # Associated MITRE ATT&CK tactic
        "protocol": "Various",  # Protocol used in the attack technique
        "os": "Linux, Windows, macOS",  # Targeted operating systems
        "tips": [
            "Monitor for suspicious usage of certutil, copy /b, or other system utilities",
            "Look for unexpected script executions that may contain deobfuscation routines",
            "Correlate file modifications or process creations with known obfuscation/decoding patterns"
        ],
        "data_sources": "File: File Modification, Process: Process Creation, Script: Script Execution",
        "log_sources": [
            {
                "type": "File",
                "source": "File System Auditing",
                "destination": "SIEM"
            },
            {
                "type": "Process",
                "source": "Endpoint Monitoring",
                "destination": "SIEM"
            },
            {
                "type": "Script",
                "source": "Script Auditing/Logging",
                "destination": "SIEM"
            }
        ],
        "source_artifacts": [
            {
                "type": "Obfuscated Files/Information",
                "location": "Local or remote systems",
                "identify": "Encoded or compressed malware payloads, scripts, or data"
            }
        ],
        "destination_artifacts": [
            {
                "type": "Deobfuscated Data",
                "location": "System memory or disk after decoding/deobfuscation",
                "identify": "Readable or executable malicious content"
            }
        ],
        "detection_methods": [
            "Analyze command-line arguments for known decoding or deobfuscation utilities",
            "Monitor for suspicious file or script modifications that indicate decoding operations",
            "Correlate endpoint logs for abnormal usage of built-in OS commands like certutil"
        ],
        "apt": [],  # No specific APT group listed
        "spl_query": [],
        "hunt_steps": [
            "Check for newly created or modified files with suspicious names or encodings",
            "Identify processes that run decoding commands or scripts outside normal usage",
            "Correlate decoded content with known malware signatures or patterns"
        ],
        "expected_outcomes": [
            "Detection of malicious data being decoded or deobfuscated on the host",
            "Identification of adversaries leveraging OS utilities or custom routines to hide malicious payloads",
            "Prevention of successful malware execution through detection of decode/deobfuscate actions"
        ],
        "false_positive": "Legitimate compression, archiving, or encryption tools used by administrators may mimic deobfuscation routines. Validate context and intended purpose.",
        "clearing_steps": [
            "Terminate or quarantine processes performing unauthorized decoding",
            "Remove or isolate decoded malicious files",
            "Review and restrict permissions for system utilities that can facilitate deobfuscation"
        ],
        "mitre_mapping": [
            {
                "tactic": "Defense Evasion",
                "technique": "Deobfuscate/Decode Files or Information (T1140)",
                "example": "Using certutil or custom scripts to decode an obfuscated payload"
            }
        ],
        "watchlist": [
            "Processes that call certutil with decode parameters",
            "copy /b usage correlating with new malicious binaries",
            "PowerShell or script commands containing base64 or encryption routines"
        ],
        "enhancements": [
            "Implement real-time monitoring of suspicious command-line activity",
            "Use sandboxing solutions to detect and block deobfuscation attempts",
            "Deploy EDR solutions to trace file lineage and detect hidden payloads"
        ],
        "summary": "Adversaries can hide malicious content through obfuscation, requiring decoding/deobfuscation at runtime. Monitoring for suspicious system utilities or script usage can help detect and disrupt these techniques.",
        "remediation": "Limit access to utilities like certutil, restrict script execution policies, and maintain updated threat intelligence on deobfuscation methods.",
        "improvements": "Use advanced logging and behavior analysis to detect hidden code execution, implement strong endpoint protections, and regularly train analysts on emerging obfuscation/deobfuscation tactics."
    }
