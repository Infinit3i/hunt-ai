def get_content():
    return {
        "id": "T1574.001",
        "url_id": "T1574/001",
        "title": "Hijack Execution Flow: DLL Search Order Hijacking",
        "tactic": "Persistence, Privilege Escalation",
        "data_sources": "File Monitoring, Process Monitoring, Windows Event Logs, Memory Analysis",
        "protocol": "N/A",
        "os": "Windows, Linux, macOS",
        "objective": "Adversaries leverage DLL hijacking to execute malicious code by placing a rogue DLL in a directory where an application will load it instead of the legitimate one.",
        "scope": "Monitor file system and process execution behavior to detect unauthorized DLL injection and hijacking attempts.",
        "threat_model": "Attackers may use DLL hijacking to maintain persistence, escalate privileges, or execute malicious code stealthily.",
        "hypothesis": [
            "Are new or unsigned DLLs being loaded by high-privileged processes?",
            "Are applications executing unexpected or modified DLLs?"
        ],
        "tips": [
            "Monitor process loading paths to detect DLL hijacking attempts.",
            "Use AppLocker or Software Restriction Policies to restrict unauthorized DLL execution."
        ],
        "log_sources": [
            {"type": "File Monitoring", "source": "Sysmon Event ID 11", "destination": "SIEM"},
            {"type": "Process Execution", "source": "Sysmon Event ID 1", "destination": "SIEM"},
            {"type": "Windows Event Logs", "source": "Event ID 7045", "destination": "Windows Security Logs"}
        ],
        "source_artifacts": [
            {"type": "File System", "location": "C:\\ProgramData\\", "identify": "Unsigned DLLs appearing in system directories."}
        ],
        "destination_artifacts": [
            {"type": "Memory Analysis", "location": "Running Processes", "identify": "DLLs loaded from unexpected locations."}
        ],
        "detection_methods": [
            "Monitor new DLLs appearing in application directories.",
            "Identify processes loading DLLs from non-standard paths.",
            "Correlate DLL loads with known malicious hashes."
        ],
        "apt": ["G0016 - APT29", "G0032 - Lazarus Group"],
        "spl_query": [
            "index=windows EventCode=7045 ImagePath=*.dll | stats count by ImagePath, ProcessName"
        ],
        "hunt_steps": [
            "Identify unusual DLLs loaded by legitimate processes.",
            "Investigate newly created files in application directories.",
            "Analyze memory for suspicious DLL injections."
        ],
        "expected_outcomes": [
            "Detection of malicious DLL loading mechanisms.",
            "Identification of persistence mechanisms leveraging DLL hijacking."
        ],
        "false_positive": "Some software legitimately loads DLLs from user-writable directories. Baseline analysis is required.",
        "clearing_steps": [
            "Delete unauthorized DLLs from system directories.",
            "Reinstall affected software to restore legitimate DLLs.",
            "Audit system privileges to prevent unauthorized DLL modifications."
        ],
        "mitre_mapping": [
            {"tactic": "Privilege Escalation", "technique": "T1548", "example": "Attackers may exploit DLL hijacking to escalate privileges."}
        ],
        "watchlist": [
            "Monitor for newly created DLLs in application directories.",
            "Track execution of unsigned DLLs loaded by privileged processes."
        ],
        "enhancements": [
            "Implement application whitelisting to prevent unauthorized DLL loading.",
            "Enable advanced logging to detect abnormal DLL load behavior."
        ],
        "summary": "DLL hijacking allows attackers to execute malicious code by replacing or inserting a DLL in an application’s search path.",
        "remediation": "Audit and remove unauthorized DLLs, enforce strict software execution policies.",
        "improvements": "Enhance monitoring capabilities with behavioral analysis and endpoint detection tools."
    }




'''
        {
            "title": "File System Analysis",
            "content": """
### File System Analysis
- Look for new or unsigned `.exe` and `.dll` files in unusual locations.
- Example Indicators:
    - Timestamp: 2021-02-18 03:42:31
        - Impact: -
        - Method: mach Meta
        - File Name: `c:/ProgramData/mcoemcpy.exe` (size: 77824)
    - File: `c:/ProgramData/McUtil.dll` (size: 131072)
            """
        },
        {
            "title": "Memory Analysis",
            "content": """
### Memory Analysis
- Identify system processes or DLLs loaded from unusual locations.
- Pay attention to:
    - Processes running unexpected code.
    - DLLs loaded from locations outside expected directories.
- Newly created DLLs and executables can indicate malicious activity.
            """
        },
        {
            "title": "Command Line Analysis",
            "content": """
### Command Line Analysis
- Review suspicious command-line execution patterns.
    - Example:
        - Command: `C:\\ProgramData\\ncoenchy.exe 0x4`
        - Method: mach Meta
- Check for signs of injection or other manipulation.
            """
        },
        {
            "title": "SANS DFIR Insights",
            "content": """
### SANS DFIR Insights
- Nearly all DLL hijacks require placing a new DLL or executable onto the file system.
- Investigative Techniques:
    - **File Timeline Analysis**:
        - Focus on newly created files during times of interest.
    - **Memory Forensics**:
        - Analyze running processes for unexpected DLL locations.
- Obscure DLLs are more likely to be targeted since common DLLs are usually preloaded into memory.
- Other anomalous actions like network beaconing or named pipe creation can lead to detection.
            """
        }
    ]
'''