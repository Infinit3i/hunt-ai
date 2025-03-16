def get_content():
    return {
        "id": "T1059.010",  # MITRE ATT&CK technique ID
        "url_id": "1059/010",  # URL segment for reference
        "title": "Command and Scripting Interpreter: AutoHotKey & AutoIT",  # Attack technique name
        "description": "Adversaries may execute commands and perform malicious tasks using AutoIT and AutoHotKey automation scripts. "
                       "AutoIT and AutoHotKey (AHK) are scripting languages that enable users to automate Windows tasks. These automation "
                       "scripts can be used to perform a wide variety of actions, such as clicking on buttons, entering text, and opening "
                       "and closing programs. Adversaries may use AHK (.ahk) and AutoIT (.au3) scripts to execute malicious code on a victim's "
                       "system. For example, adversaries have used AHK to execute payloads and other modular malware such as keyloggers. "
                       "Adversaries have also used custom AHK files containing embedded malware as phishing payloads. These scripts may also "
                       "be compiled into self-contained executable payloads (.exe).",
        "tags": [
            "t1059.010",
            "autohotkey execution",
            "autoit scripting",
            "ahk malware",
            "autoit malware",
            "autohotkey keylogger",
            "autoit automation abuse",
            "windows scripting attack",
            "malicious automation scripts",
            "ahk phishing payload",
            "autoit compiled exe",
            "windows command execution",
            "scripting language abuse",
            "process creation monitoring"
        ],
        "tactic": "Execution",
        "platforms": ["Windows"],
        "data_sources": "Command: Command Execution, Process: Process Creation",
        "log_sources": [
            {"type": "System Logs", "source": "Windows Event Logs", "destination": "SIEM"},
            {"type": "Behavioral Monitoring", "source": "Endpoint Detection & Response (EDR)", "destination": "SOC"}
        ],
        "watchlist": [
            "unexpected autohotkey execution",
            "suspicious autoit script activity",
            "unusual script-based process creation"
        ],
        "detection_methods": ["Process Monitoring", "Command-line Analysis", "Behavioral Anomaly Detection"],
        "apt": ["Malware using AutoHotKey or AutoIT"],
        "expected_outcomes": ["Detection of unauthorized AutoHotKey or AutoIT script execution"],
        "remediation": "Restrict AutoHotKey & AutoIT execution via policy controls, monitor script-based process creation, and block unauthorized script execution.",
        "mitre_mapping": [
            {"tactic": "Execution", "technique": "T1059.010", "example": "Adversary using AHK scripts to execute malicious payloads."}
        ],
        "summary": "AutoHotKey and AutoIT abuse is commonly used in Windows-based attacks for automation, persistence, and malware execution.",
        "improvements": "Enhance Windows script execution monitoring, enforce least privilege, and block unauthorized script execution."
    }
