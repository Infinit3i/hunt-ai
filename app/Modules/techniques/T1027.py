def get_content():
    """
    Returns structured content for the Obfuscated Files or Information technique.
    """
    return {
        "id": "T1027",
        "url_id": "T1027",
        "title": "Obfuscated Files or Information",
        "tactic": "Defense Evasion",
        "description": "Adversaries may attempt to make an executable or file difficult to detect or analyze by encrypting, encoding, or obfuscating its contents. This technique is commonly used to evade detection by security products and analysts. Attackers may use techniques like Base64 encoding, XOR encoding, packing, and encryption to hide the presence of malicious payloads.",
        "tags": ["Obfuscation", "Encoding", "Packing", "Encryption", "Evasion"],
        "data_sources": "File Monitoring, Process Execution, Binary Analysis, Memory Analysis",
        "protocol": "N/A",
        "os": "Windows, Linux, macOS",
        "tips": [
            "Monitor for excessive Base64, XOR, or ROT13 encoding in scripts and executables.",
            "Detect unusual compression or packing methods in binaries.",
            "Look for signs of polymorphic or self-modifying code.",
            "Analyze processes for scripts or executables loaded from temporary directories.",
            "Detect scripts using excessive string manipulation functions to decode payloads."
        ],
        "log_sources": [
            {"type": "File Monitoring", "source": "Windows Event Logs, Sysmon Event ID 11 (File Creation), Linux Audit Logs"},
            {"type": "Process Execution", "source": "Sysmon Event ID 1 (Process Creation), Windows Security Event ID 4688"},
            {"type": "Binary Analysis", "source": "Static and dynamic malware analysis tools"},
            {"type": "Memory Analysis", "source": "Volatility, Rekall, Windows Defender AMSI Logs"}
        ],
        "source_artifacts": [
            {"type": "Encoded Scripts", "location": "C:\\Users\\<Username>\\AppData\\Local", "identify": "Scripts with Base64, XOR obfuscation"},
            {"type": "Packed Malware", "location": "/var/tmp", "identify": "Files with high entropy, indicating potential packing"},
            {"type": "Encrypted Payloads", "location": "Registry, Memory", "identify": "Shellcode or malicious scripts stored in registry keys"}
        ],
        "destination_artifacts": [
            {"type": "Packed Executables", "location": "/var/tmp", "identify": "Malware using UPX or custom packers"},
            {"type": "Encoded PowerShell Scripts", "location": "C:\\Windows\\Temp", "identify": "Scripts using -enc (encoded) flag"},
            {"type": "Compressed Archives", "location": "/tmp", "identify": "Zip or tar files containing obfuscated payloads"}
        ],
        "detection_methods": [
            "Analyze script execution logs for excessive encoding mechanisms.",
            "Use entropy analysis to detect highly compressed or packed files.",
            "Detect command-line arguments containing encoded payloads.",
            "Monitor for execution of scripts from non-standard directories.",
            "Identify obfuscation techniques such as string-reversing, Unicode encoding, or excessive whitespace."
        ],
        "apt": ["G0016 (FIN7)", "G0032 (APT32)", "G0082 (TA505)", "G0139 (Wizard Spider)"],
        "spl_query": [
            "index=windows EventCode=4688 CommandLine=*base64* \n| table _time, User, CommandLine",
            "index=linux syslog Message=*shc* \n| table _time, Process, User",
            "index=endpoint sourcetype=sysmon EventCode=1 CommandLine=* -enc * \n| table _time, User, CommandLine",
            "index=network sourcetype=zeek_dns query=*pastebin.com* OR query=*bit.ly* \n| table _time, src_ip, query",
            "index=malware_analysis sourcetype=pe_analysis entropy > 7.5 \n| table _time, file_name, entropy"
        ],
        "hunt_steps": [
            "Search for known obfuscation techniques in script execution logs.",
            "Analyze suspicious binaries using unpacking tools.",
            "Review recent script execution activity for signs of obfuscation.",
            "Correlate network traffic with encoded payload downloads.",
            "Detect use of process injection techniques combined with encoded scripts."
        ],
        "expected_outcomes": [
            "Obfuscated malware detected and neutralized.",
            "No malicious obfuscation found, improving detection baselines.",
            "Encoded payloads identified and decoded for further analysis."
        ],
        "false_positive": "Legitimate software and scripts may use encoding for compression or protection. Automated encryption or DRM tools can trigger false positives.",
        "clearing_steps": [
            "Identify and remove malicious obfuscated scripts and executables.",
            "Use static analysis tools to unpack and inspect potentially obfuscated binaries.",
            "Clear registry keys containing encoded or hidden payloads.",
            "Monitor for reappearance of obfuscated artifacts.",
            "Review network traffic logs for signs of payload staging or exfiltration."
        ],
        "mitre_mapping": [
            {"tactic": "Execution", "technique": "T1204.002 (User Execution - Malicious File)", "example": "Adversaries may use obfuscation to deliver and execute malicious payloads."},
            {"tactic": "Defense Evasion", "technique": "T1027.002 (Software Packing)", "example": "Attackers use UPX, Themida, or custom packers to make detection harder."},
            {"tactic": "Defense Evasion", "technique": "T1027.003 (Steganography)", "example": "Obfuscated payloads hidden in image files (e.g., PNG, JPG) for covert execution."},
            {"tactic": "Defense Evasion", "technique": "T1027.005 (Indicator Removal from Tools)", "example": "Adversaries strip metadata from malware binaries to evade detection."}
        ],
        "watchlist": [
            "Flag Base64-encoded scripts in PowerShell and Bash.",
            "Detect unusual string manipulation functions in active processes.",
            "Monitor execution of encoded commands or scripts with -enc flags.",
            "Track use of suspiciously high-entropy files indicative of packing or encryption."
        ],
        "enhancements": [
            "Deploy static and dynamic analysis tools to detect obfuscation techniques.",
            "Improve behavioral analysis rules for script execution monitoring.",
            "Implement YARA rules for detecting obfuscated payloads.",
            "Enable memory forensics on suspicious running processes."
        ],
        "summary": "Obfuscation is used by adversaries to evade detection by security tools by encoding, compressing, or encrypting malicious payloads.",
        "remediation": "Implement strict execution policies and scanning techniques to detect obfuscated files. Remove detected obfuscated malware and analyze the payloads to prevent reinfection.",
        "improvements": "Enhance automated detection of obfuscation techniques across scripts and binaries. Integrate threat intelligence to detect newly emerging obfuscation methods."
    }
