def get_content():
    return {
        "id": "T1036.007",
        "url_id": "T1036/007",
        "title": "Masquerading: Double File Extensions",
        "tactic": "Defense Evasion",
        "data_sources": "Process Creation Logs, File System Logs, Endpoint Logs, Security Monitoring Tools",
        "protocol": "File Name Manipulation, Extension Spoofing, User Deception",
        "os": "Windows, Linux, macOS",
        "objective": "Detect and mitigate adversaries using double file extensions to disguise malicious executables and trick users into execution.",
        "scope": "Identify suspicious file execution and process creation events where files have misleading double extensions to evade security tools.",
        "threat_model": "Adversaries append double extensions to filenames (e.g., `invoice.pdf.exe`) to manipulate how the file appears in the operating system, making it seem like a benign document while actually executing malicious code.",
        "hypothesis": [
            "Are there executables running with misleading double file extensions?",
            "Are adversaries leveraging file extension obfuscation to execute malicious payloads?",
            "Is there an increase in process execution where filenames visually resemble non-executable files?"
        ],
        "log_sources": [
            {"type": "Process Creation Logs", "source": "Sysmon (Event ID 1, 11), Windows Security Logs (Event ID 4688)"},
            {"type": "File System Logs", "source": "Windows Event Logs (Event ID 4663), Linux Auditd, macOS Unified Logs"},
            {"type": "Endpoint Logs", "source": "EDR (CrowdStrike, Defender ATP, Carbon Black)"},
            {"type": "Security Monitoring Tools", "source": "SIEM, Host-based IDS Logs"}
        ],
        "detection_methods": [
            "Monitor for execution of binaries containing misleading double file extensions.",
            "Detect processes where the binary name visually resembles a document or image but is actually an executable.",
            "Identify execution of files with unexpected or deceptive filename structures."
        ],
        "spl_query": [
            "index=endpoint sourcetype=sysmon \n| search process_name=*.pdf.exe OR process_name=*.jpg.scr OR process_name=*.docx.bat \n| stats count by host, user, process_name, file_path"
        ],
        "hunt_steps": [
            "Run Queries in SIEM: Identify execution of filenames containing double extensions.",
            "Analyze Process Creation Logs: Detect anomalies in how the operating system interprets filenames.",
            "Monitor for Unexpected Binary Execution: Identify executables running with misleading file structures.",
            "Correlate with Threat Intelligence: Compare with known defense evasion techniques.",
            "Validate & Escalate: If malicious activity is found → Escalate to Incident Response."
        ],
        "expected_outcomes": [
            "Masquerading via Double Extensions Detected: Block execution of obfuscated binaries and investigate affected hosts.",
            "No Malicious Activity Found: Improve detection models for extension spoofing-based defense evasion techniques."
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1036.007 (Double File Extensions)", "example": "Adversaries renaming `malware.exe` to `document.pdf.exe` to evade detection."},
            {"tactic": "Execution", "technique": "T1204 (User Execution)", "example": "Malware leveraging misleading extensions to trick users into execution."}
        ],
        "watchlist": [
            "Flag executions of files with misleading double extensions.",
            "Monitor for anomalies in process execution related to filename structure.",
            "Detect unauthorized renaming of executables using extension spoofing."
        ],
        "enhancements": [
            "Deploy file integrity monitoring to detect filename manipulations.",
            "Implement behavioral analytics to detect abnormal process execution.",
            "Improve correlation between extension spoofing activity and known threat actor techniques."
        ],
        "summary": "Document detected malicious masquerading via double extension manipulation-based defense evasion activity and affected systems.",
        "remediation": "Block execution of obfuscated filenames, revoke compromised access, and enhance monitoring.",
        "improvements": "Refine detection models and improve analysis of double extension-based masquerading techniques."
    }
