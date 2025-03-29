def get_content():
    return {
        "id": "T1059.005",  # Tactic Technique ID
        "url_id": "T1059/005",  # URL segment for technique reference
        "title": "Command and Scripting Interpreter: Visual Basic",  # Name of the attack technique
        "description": "Adversaries may abuse Visual Basic (VB) and derivative languages like VBA and VBScript for malicious code execution. This can include malicious macros embedded in Office documents or VBScript files used to run commands via wscript.exe/cscript.exe.",  # Simple description
        "tags": [
            "execution",
            "visual basic",
            "vba",
            "vbscript",
            "command and scripting interpreter"
        ],
        "tactic": "Execution",  # Associated MITRE ATT&CK tactic
        "protocol": "N/A",  # VB typically executes locally, though it can leverage network-based components
        "os": "Linux, Windows, macOS",  # Targeted operating systems (VB .NET core cross-platform, though most commonly Windows)
        "tips": [
            "Monitor for unusual Office processes spawning other executables (e.g., cmd.exe, powershell.exe).",
            "Capture and analyze suspicious VBA macros or VBScript files to determine malicious intent.",
            "Look for usage of wscript.exe or cscript.exe in environments where VBScript is not commonly used.",
            "Restrict VBScript execution via Group Policy or software restriction policies if not needed."
        ],
        "data_sources": "Windows Security, Windows System, Sysmon, Application Log, EDR telemetry",
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
                "type": "Application Log",
                "source": "Microsoft Office Alerts or other relevant logs",
                "destination": "SIEM"
            }
        ],
        "source_artifacts": [
            {
                "type": "Script",
                "location": "Local or network shares",
                "identify": "VBScript files (.vbs), VBA macros embedded in Office docs, or .NET VB executables"
            },
            {
                "type": "Process",
                "location": "Running processes",
                "identify": "wscript.exe, cscript.exe, or Office processes executing VB code"
            }
        ],
        "destination_artifacts": [
            {
                "type": "File",
                "location": "Downloaded or created by VB scripts/macros",
                "identify": "Malicious payload or exfiltrated data"
            },
            {
                "type": "Network Traffic",
                "location": "Outbound connections",
                "identify": "Suspicious VB-based HTTP/HTTPS or other protocol usage"
            }
        ],
        "detection_methods": [
            "Analyze process creation events for cscript.exe/wscript.exe usage with suspicious command-line arguments",
            "Monitor for Office applications (e.g., WINWORD.EXE, EXCEL.EXE) spawning command-line interpreters or scripts",
            "Correlate unusual VB script executions with network or file modification events",
            "Look for encoded or obfuscated VB scripts/macros in logs and on disk"
        ],
        "apt": [
            "MuddyWater",
            "TA505",
            "Gamaredon",
            "FIN7"
        ],
        "spl_query": [
            "sourcetype=WinEventLog:Security EventCode=4688 CommandLine=*wscript* OR CommandLine=*cscript* \n| stats count by Host, AccountName, CommandLine"
        ],
        "hunt_steps": [
            "Collect process creation logs for wscript.exe, cscript.exe, and Office apps from endpoints.",
            "Search for unusual or obfuscated VB code within macros or script files in shared locations.",
            "Correlate suspicious VB activity with network traffic for potential exfiltration or command-and-control.",
            "Investigate any newly enabled VB-related registry keys or execution policies."
        ],
        "expected_outcomes": [
            "Detection of malicious Visual Basic usage or macros used in phishing attachments.",
            "Identification of suspicious script or macro activity leading to unauthorized actions or lateral movement.",
            "Correlation of VB-based events with additional TTPs that indicate a broader attack campaign."
        ],
        "false_positive": "Legitimate administrative scripts, developer testing, or automation tasks may trigger VB-based alerts; baseline and tuning are necessary.",
        "clearing_steps": [
            "Terminate malicious VB-related processes (e.g., wscript.exe, cscript.exe) and remove associated scripts.",
            "Disable or limit Office macros in Group Policy or via application controls where not required.",
            "Quarantine and investigate suspicious documents or script files, then restore affected systems if compromised.",
            "Reinstate default settings or security policies if they were altered to enable malicious VB execution."
        ],
        "mitre_mapping": [
            {
                "tactic": "Defense Evasion",
                "technique": "Obfuscated Files or Information (T1027)",
                "example": "Adversaries may use obfuscated VBA macros to bypass detection."
            },
            {
                "tactic": "Initial Access",
                "technique": "Spearphishing Attachment (T1566.001)",
                "example": "Adversaries may embed malicious VBA macros within documents for phishing."
            }
        ],
        "watchlist": [
            "Office applications spawning command shells or suspicious processes",
            "Encoded or obfuscated VB scripts, macros, or command-line parameters",
            "Frequent or anomalous cscript.exe/wscript.exe executions in user space"
        ],
        "enhancements": [
            "Implement application control or allow-listing for script engines and macros.",
            "Enable advanced Office macro security settings (block macros from the Internet).",
            "Deploy EDR solutions that monitor script engines and suspicious macro usage in real time."
        ],
        "summary": "Visual Basic, including VBA and VBScript, can be abused by adversaries to execute malicious code. This often occurs via Office macros or standalone VBScript files.",
        "remediation": "Limit VB macro usage, enforce macro security policies, monitor for suspicious script usage, and educate users about macro-enabled phishing threats.",
        "improvements": "Adopt threat intelligence for known malicious VB macros, refine detection rules for cscript.exe/wscript.exe usage, and regularly audit macro-enabled documents within the environment."
    }
