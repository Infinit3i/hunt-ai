def get_content():
    """
    Returns structured content for the Obfuscated Files or Information technique.
    """
    return {
        "id": "T1027",
        "url_id": "T1027",
        "title": "Obfuscated Files or Information",
        "tactic": "Defense Evasion",
        "data_sources": "File monitoring, Process monitoring, Binary analysis",
        "protocol": "N/A",
        "os": "Windows, Linux, macOS",
        "objective": "Adversaries may attempt to evade detection by obfuscating files, scripts, and other data.",
        "scope": "Monitor file changes, script execution, and binary modifications for signs of obfuscation techniques.",
        "threat_model": "Obfuscation techniques help attackers hide malicious intent, making detection more difficult by security tools.",
        "hypothesis": [
            "Are scripts or binaries using excessive encoding or compression?",
            "Are there signs of string obfuscation in executed files?",
            "Is an attacker hiding payloads within seemingly benign files?"
        ],
        "tips": [
            "Monitor for excessive Base64, XOR, or ROT13 encoding in scripts and executables.",
            "Detect unusual compression or packing methods in binaries.",
            "Look for signs of polymorphic or self-modifying code."
        ],
        "log_sources": [
            {"type": "File Monitoring", "source": "Windows Event Logs, Sysmon Event ID 11, Linux Audit Logs"},
            {"type": "Process Execution", "source": "Sysmon Event ID 1, Windows Security Event ID 4688"},
            {"type": "Binary Analysis", "source": "Static and dynamic malware analysis tools"}
        ],
        "source_artifacts": [
            {"type": "Encoded Scripts", "location": "C:\\Users\\<Username>\\AppData\\Local", "identify": "Scripts with Base64, XOR obfuscation"}
        ],
        "destination_artifacts": [
            {"type": "Packed Executables", "location": "/var/tmp", "identify": "Malware using UPX or custom packers"}
        ],
        "detection_methods": [
            "Analyze script execution logs for excessive encoding mechanisms.",
            "Use entropy analysis to detect highly compressed or packed files.",
            "Detect command-line arguments containing encoded payloads."
        ],
        "apt": ["G0016", "G0032"],
        "spl_query": [
            "index=windows EventCode=4688 CommandLine=*base64* | table Time, User, CommandLine",
            "index=linux syslog Message=*shc* | table Time, Process, User"
        ],
        "hunt_steps": [
            "Search for known obfuscation techniques in script execution logs.",
            "Analyze suspicious binaries using unpacking tools.",
            "Review recent script execution activity for signs of obfuscation."
        ],
        "expected_outcomes": [
            "Obfuscated malware detected and neutralized.",
            "No malicious obfuscation found, improving detection baselines."
        ],
        "false_positive": "Legitimate software and scripts may use encoding for compression or protection.",
        "clearing_steps": [
            "Remove malicious obfuscated scripts and executables.",
            "Monitor for reappearance of obfuscated artifacts."],
        "mitre_mapping": [
            {"tactic": "Execution", "technique": "T1204.002 (User Execution - Malicious File)", "example": "Adversaries may use obfuscation to deliver and execute malicious payloads."}
        ],
        "watchlist": [
            "Flag Base64-encoded scripts in PowerShell and Bash.",
            "Detect unusual string manipulation functions in active processes."
        ],
        "enhancements": [
            "Deploy static and dynamic analysis tools to detect obfuscation techniques.",
            "Improve behavioral analysis rules for script execution monitoring."
        ],
        "summary": "Obfuscation is used by adversaries to evade detection by security tools.",
        "remediation": "Implement strict execution policies and scanning techniques to detect obfuscated files.",
        "improvements": "Enhance automated detection of obfuscation techniques across scripts and binaries."
    }
