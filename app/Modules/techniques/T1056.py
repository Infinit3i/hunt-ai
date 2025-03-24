def get_content():
    return {
        "id": "T1056",
        "url_id": "T1056",
        "title": "Input Capture",
        "description": "Adversaries may use methods of capturing user input to obtain credentials or collect information. During normal system usage, users often provide credentials to various different locations, such as login pages/portals or system dialog boxes. Input capture mechanisms may be transparent to the user (e.g. Credential API Hooking) or rely on deceiving the user into providing input into what they believe to be a genuine service (e.g. Web Portal Capture).",
        "tags": ["Collection", "Credential Access"],
        "tactic": "Collection",
        "protocol": "",
        "os": "Windows, macOS, Linux, Network",
        "tips": [
            "Monitor for certain Windows API calls (e.g. `SetWindowsHook`, `GetKeyState`, and `GetAsyncKeyState`) that are often used in keylogging techniques.",
            "Check for unauthorized drivers or kernel modules that may indicate keylogging or API hooking is taking place.",
            "Monitor malicious instances of Command and Scripting Interpreters for unusual input capture activity."
        ],
        "data_sources": "Driver: Driver Load, File: File Modification, Process: OS API Execution, Process: Process Creation, Process: Process Metadata, Windows Registry: Windows Registry Key Modification",
        "log_sources": [
            {"type": "Process", "source": "OS API Execution", "destination": ""},
            {"type": "File", "source": "File Modification", "destination": ""},
            {"type": "Driver", "source": "Driver Load", "destination": ""},
            {"type": "Registry", "source": "Windows Registry Key Modification", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Malicious Code", "location": "Injected in memory", "identify": "Keylogger, API Hooking"}
        ],
        "destination_artifacts": [
            {"type": "Captured Input", "location": "Login pages/portals, system dialog boxes", "identify": "Captured user credentials or sensitive information"}
        ],
        "detection_methods": [
            "Monitor for specific Windows API calls such as `SetWindowsHook`, `GetKeyState`, and `GetAsyncKeyState` that may indicate keylogging activities.",
            "Look for unusual processes that could be used for malicious input capture, including unauthorized driver loads or process creations.",
            "Detect any suspicious behavior from Command and Scripting Interpreters that might relate to input capture."
        ],
        "apt": ["John Lambert, Microsoft Threat Intelligence Center"],
        "spl_query": [
            "| index=sysmon sourcetype=process | search SetWindowsHook OR GetKeyState OR GetAsyncKeyState"
        ],
        "hunt_steps": [
            "Monitor for signs of unauthorized driver or kernel module loading that could be related to keylogging.",
            "Check for unusual registry modifications or API calls indicative of malicious input capture."
        ],
        "expected_outcomes": [
            "Detection of input capture activities through identification of keylogging attempts or unauthorized API hooks."
        ],
        "false_positive": "Legitimate use of keylogger or API hooking software may result in false positives. Adjust filtering rules to mitigate.",
        "clearing_steps": [
            "Terminate the malicious process capturing input.",
            "Remove any injected code or malicious drivers that were responsible for capturing input."
        ],
        "mitre_mapping": [
            {"tactic": "Collection", "technique": "T1056", "example": "Capture user input through keylogging techniques."}
        ],
        "watchlist": [
            "Watch for abnormal processes or API calls related to keylogging and input capture.",
            "Monitor for malicious instances of scripting interpreters or command line tools used for collecting user data."
        ],
        "enhancements": [
            "Enhance detection by correlating input capture techniques with other post-compromise activities."
        ],
        "summary": "Input Capture is a technique used by adversaries to capture user input, such as credentials or sensitive information, through keylogging or deceiving the user into entering data into fake services.",
        "remediation": "Terminate any keylogging processes, remove unauthorized drivers or kernel modules, and restore system integrity.",
        "improvements": "Regularly monitor for changes to input capture behaviors and adjust detection rules accordingly.",
        "mitre_version": "16.1"
    }
