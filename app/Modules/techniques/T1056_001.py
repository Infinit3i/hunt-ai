def get_content():
    """
    Returns structured content for the Keylogging (T1056.001) technique.
    """
    return {
        "id": "T1056.001",
        "url_id": "T1056/001",
        "title": "Keylogging",
        "tactic": "Credential Access",
        "data_sources": "Process Monitoring, File Monitoring, Windows Event Logs",
        "protocol": "N/A",
        "os": "Windows, Linux, macOS",
        "objective": "Capture user keystrokes to obtain credentials and other sensitive data.",
        "scope": "Monitor processes and files for unauthorized keystroke logging.",
        "threat_model": "Adversaries use keyloggers to capture user input and exfiltrate credentials.",
        "hypothesis": [
            "Are unauthorized processes recording keystrokes?",
            "Is there unexpected file creation in common keylogging storage paths?",
            "Are suspicious processes injecting themselves into input-handling applications?"
        ],
        "tips": [
            "Monitor processes that interact with keyboard hooks.",
            "Check for unexpected file creation in user directories.",
            "Detect processes making calls to SetWindowsHookEx or GetAsyncKeyState API functions."
        ],
        "log_sources": [
            {"type": "Process Monitoring", "source": "Sysmon Event ID 1", "destination": "Security.evtx"},
            {"type": "File Monitoring", "source": "Keylogging software logs", "destination": "Filesystem"},
            {"type": "Windows Event Logs", "source": "Event ID 4656", "destination": "Security.evtx"}
        ],
        "source_artifacts": [
            {"type": "Executable", "location": "C:\\Users\\<User>\\AppData\\Local", "identify": "Unusual keylogging software."}
        ],
        "destination_artifacts": [
            {"type": "Log Files", "location": "C:\\Users\\<User>\\Documents", "identify": "Unexpected keystroke log files."}
        ],
        "detection_methods": [
            "Monitor API calls to SetWindowsHookEx, GetAsyncKeyState, and GetForegroundWindow.",
            "Detect unauthorized processes capturing keyboard input.",
            "Analyze process memory for hooks into user input functions."
        ],
        "apt": ["G0016", "G0032"],
        "spl_query": [
            "index=windows EventCode=4656 Object_Type=Process Handle_Name=*keyboard* | table Time, ProcessName, User"
        ],
        "hunt_steps": [
            "Search for processes using keyboard hooks.",
            "Analyze unusual log file activity.",
            "Investigate suspicious API call patterns related to keystroke capturing."
        ],
        "expected_outcomes": [
            "Detection of unauthorized keylogging software.",
            "Identification of anomalous keystroke logging behaviors."
        ],
        "false_positive": "Legitimate applications like accessibility tools may use keyboard hooks.",
        "clearing_steps": [
            "Terminate the malicious process.",
            "Remove associated log files.",
            "Audit registry and startup entries for persistence mechanisms."
        ],
        "mitre_mapping": [
            {"tactic": "Credential Access", "technique": "T1056.002 (GUI Input Capture)", "example": "Adversaries may capture screen input in addition to keystrokes."}
        ],
        "watchlist": [
            "Monitor for processes interacting with keyboard input APIs.",
            "Flag unauthorized software writing keystroke logs."
        ],
        "enhancements": [
            "Implement endpoint protection to detect keystroke logging behavior.",
            "Use least privilege principles to restrict access to keyboard input APIs."
        ],
        "summary": "Keyloggers capture keystrokes to steal credentials and other sensitive data.",
        "remediation": "Remove unauthorized keylogging software and apply endpoint monitoring.",
        "improvements": "Enhance detection capabilities by monitoring for suspicious API calls and unauthorized keystroke log files."
    }
