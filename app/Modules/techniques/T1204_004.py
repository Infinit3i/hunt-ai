def get_content():
    return {
        "id": "T1204.004",
        "url_id": "T1204/004",
        "title": "Malicious Copy and Paste",
        "description": "An adversary may rely upon a user copying and pasting code in order to gain execution.",
        "tags": ["user execution", "social engineering", "copy-paste", "initial access", "script injection"],
        "tactic": "execution",
        "protocol": "",
        "os": "Windows, Linux, macOS",
        "tips": [
            "Educate users to avoid copying and pasting commands from unknown or suspicious websites.",
            "Disable automatic clipboard access from untrusted web pages.",
            "Use script restriction policies where applicable."
        ],
        "data_sources": "Command, File, Network Traffic, Process",
        "log_sources": [
            {"type": "Command", "source": "", "destination": ""},
            {"type": "File", "source": "", "destination": ""},
            {"type": "Network Traffic", "source": "", "destination": ""},
            {"type": "Process", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Windows Registry", "location": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU", "identify": "Recently executed commands via Run dialog"},
            {"type": "Clipboard Data", "location": "System Memory", "identify": "Presence of staged commands copied from web pages"}
        ],
        "destination_artifacts": [
            {"type": "Event Logs", "location": "Sysmon Operational", "identify": "Process creation and execution traced to user-triggered actions"}
        ],
        "detection_methods": [
            "Look for base64 or PowerShell encoded commands issued by interactive sessions.",
            "Monitor clipboard and command history for injected payloads.",
            "Detect traffic spikes to malicious hosts following suspicious execution."
        ],
        "apt": ["Lumma Stealer", "Lazarus"],
        "spl_query": [
            "sourcetype=WinEventLog:Sysmon EventCode=1(CommandLine=*Invoke-WebRequest* OR CommandLine=*wget* OR CommandLine=*curl*)\n| stats count by Image, CommandLine, ParentImage, User, host, _time\n| sort -_time",
            "sourcetype=WinEventLog:Sysmon EventCode=11(TargetFilename=\"*.exe\" OR TargetFilename=\"*.ps1\")\n| stats count by TargetFilename, Image, User, host, _time\n| sort -_time",
            "sourcetype=WinEventLog:Sysmon EventCode=13(TargetObject=\"HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Explorer\\\\RunMRU\")\n| stats count by TargetObject, Details, User, host, _time\n| sort -_time"
        ],
        "hunt_steps": [
            "Review RunMRU registry keys for unusual commands.",
            "Check for recent process executions by the current user.",
            "Correlate with known attack payloads delivered via CAPTCHA or pop-up mechanisms."
        ],
        "expected_outcomes": [
            "Detection of user-initiated code execution resulting from social engineering tricks."
        ],
        "false_positive": "Power users or developers may copy and paste code into terminals frequently. Validate intent and source.",
        "clearing_steps": [
            "Clear RunMRU entries via reg delete or GUI cleanup.",
            "Delete any downloaded payloads in known temp directories.",
            "Terminate any processes that were launched via malicious scripts."
        ],
        "clearing_playbook": [
            "https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-malware"
        ],
        "mitre_mapping": [
            {"tactic": "execution", "technique": "T1204", "example": "User Execution"},
            {"tactic": "initial-access", "technique": "T1566.002", "example": "Phishing: Spearphishing Link"}
        ],
        "watchlist": [
            "Encoded or obfuscated one-liner commands pasted into terminals",
            "Unusual use of curl, wget, or PowerShell in interactive sessions"
        ],
        "enhancements": [
            "Deploy clipboard protection or warning banners for copy-paste commands.",
            "Train users to report any suspicious prompts asking them to paste code."
        ],
        "summary": "Malicious Copy and Paste exploits user trust and social engineering to bypass security controls and execute attacker-supplied commands.",
        "remediation": "Limit script execution capabilities, and educate users on recognizing and avoiding deceptive content.",
        "improvements": "Integrate behavior-based detection to flag misuse of interactive script execution pathways.",
        "mitre_version": "17.0"
    }
