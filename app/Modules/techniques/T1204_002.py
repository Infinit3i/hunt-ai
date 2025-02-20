def get_content():
    """
    Returns structured content for the Malicious File Execution technique (T1204.002).
    """
    return {
        "id": "T1204.002",
        "url_id": "T1204/002",
        "title": "Malicious File Execution",
        "tactic": "Execution",
        "data_sources": "Process monitoring, File monitoring, Windows Event Logs",
        "protocol": "N/A",
        "os": "Windows, Linux, macOS",
        "objective": "Adversaries may trick users into executing malicious files through social engineering or execution from compromised locations.",
        "scope": "Monitor for unauthorized file execution from user directories, downloads, or temp folders.",
        "threat_model": "Attackers may deliver executable files disguised as legitimate software, leveraging user interaction to execute malware.",
        "hypothesis": [
            "Are users executing files from suspicious locations (Downloads, Temp, AppData)?",
            "Are unsigned executables being run with administrative privileges?",
            "Are attackers using social engineering to trick users into executing malicious files?"
        ],
        "tips": [
            "Monitor process execution from Downloads, Temp, or email attachments.",
            "Detect execution of unsigned or newly created binaries.",
            "Block execution of scripts and macros from untrusted sources."
        ],
        "log_sources": [
            {"type": "Process Execution", "source": "Sysmon Event ID 1, Windows Event Logs 4688", "destination": "Security.evtx"},
            {"type": "File Monitoring", "source": "Sysmon Event ID 11", "destination": "System.evtx"}
        ],
        "source_artifacts": [
            {"type": "Executable Files", "location": "C:\\Users\\<username>\\Downloads", "identify": "Suspicious executable files"}
        ],
        "destination_artifacts": [
            {"type": "Process Execution", "location": "C:\\Windows\\Temp", "identify": "Malicious process spawned from user directories"}
        ],
        "detection_methods": [
            "Monitor execution of files from suspicious locations.",
            "Detect processes spawned by office applications or scripting engines.",
            "Analyze command-line arguments for execution of suspicious files."
        ],
        "apt": ["G0016", "G0094"],
        "spl_query": [
            "index=windows EventCode=4688 NewProcessName=*\\Downloads\\*.exe",
            "index=windows EventCode=1 Image=*\\Temp\\*.exe"
        ],
        "hunt_steps": [
            "Identify processes executed from Downloads or Temp folders.",
            "Correlate process execution with user activity and logs.",
            "Investigate file origins and determine potential social engineering techniques."
        ],
        "expected_outcomes": [
            "Malicious file execution detected and mitigated.",
            "No suspicious activity found, refining detection baselines."
        ],
        "false_positive": "Users may install legitimate software from unverified sources.",
        "clearing_steps": [
            "Delete malicious executables from user directories.",
            "Investigate and remove persistence mechanisms if present."
        ],
        "mitre_mapping": [
            {"tactic": "Execution", "technique": "T1204.002 (Malicious File Execution)", "example": "Adversaries execute malicious payloads by tricking users."}
        ],
        "watchlist": [
            "Monitor execution of newly created or downloaded executable files.",
            "Detect scripts or batch files running from user directories."
        ],
        "enhancements": [
            "Implement application whitelisting to prevent execution from unauthorized locations.",
            "Educate users on risks of executing unknown files."
        ],
        "summary": "Attackers may leverage malicious file execution as a means of initial compromise or persistence.",
        "remediation": "Ensure software execution policies restrict running files from untrusted locations.",
        "improvements": "Enhance user training on social engineering risks and implement stricter execution policies."
    }
