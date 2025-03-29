def get_content():
    return {
        "id": "T1203",
        "url_id": "T1203",
        "title": "Exploitation for Client Execution",
        "description": "Adversaries may exploit software vulnerabilities in client applications to execute code.",
        "tags": ["Execution", "Exploit", "Phishing", "Drive-by Compromise", "Office Files", "Browser"],
        "tactic": "Execution",
        "protocol": "N/A",
        "os": "Windows, Linux, macOS",
        "tips": [
            "Monitor crash reports and exploit mitigation logs for targeted applications.",
            "Use EDR tools to identify suspicious document or PDF behavior.",
            "Apply least-privilege principles to reduce exploit impact."
        ],
        "data_sources": "Application Log, File, Network Traffic, Process",
        "log_sources": [
            {"type": "Application Log", "source": "Client Application", "destination": "SIEM"},
            {"type": "File", "source": "User Machine", "destination": ""},
            {"type": "Network Traffic", "source": "", "destination": "Proxy or EDR"},
            {"type": "Process", "source": "Client System", "destination": "SIEM"}
        ],
        "source_artifacts": [
            {"type": "Malicious Document", "location": "User Downloads", "identify": "Exploit-laced Office or PDF files"},
            {"type": "Process List", "location": "System Memory", "identify": "Unexpected child processes from Office or browser apps"}
        ],
        "destination_artifacts": [
            {"type": "Injected Payloads", "location": "Memory", "identify": "Shellcode injected into trusted processes"},
            {"type": "Network Connections", "location": "Firewall/EDR Logs", "identify": "Outbound traffic post exploit"}
        ],
        "detection_methods": [
            "Monitor process tree anomalies (e.g., winword.exe spawning cmd.exe).",
            "Scan for known exploit patterns in document files.",
            "Use memory scanning for post-exploitation indicators."
        ],
        "apt": [
            "APT28", "TA459", "Inception Framework", "NOBELIUM", "MUSTANG PANDA", "Sidewinder", "Cobalt Group",
            "Andariel", "OceanLotus", "Sandworm", "Patchwork", "Elfin", "Frankenstein", "Sofacy", "SpeakUp"
        ],
        "spl_query": [
            "index=sysmon EventCode=1\n| search ParentImage=*winword.exe OR ParentImage=*excel.exe OR ParentImage=*acrord32.exe\n| stats count by ParentImage, Image, CommandLine, User",
            "index=proxy OR index=network http.method=GET AND http.uri=*exploit* | stats count by uri_path, src_ip"
        ],
        "hunt_steps": [
            "Identify Office or browser processes spawning unexpected children.",
            "Look for PDF or Office files recently opened from email or browser.",
            "Analyze memory dumps of targeted processes for shellcode or injection."
        ],
        "expected_outcomes": [
            "Detection of code execution via exploit-laced client-side apps.",
            "Identification of suspicious parent-child execution flows."
        ],
        "false_positive": "Software updates, scripting add-ins, or automation tools may mimic similar behaviors.",
        "clearing_steps": [
            "taskkill /F /IM winword.exe",
            "Delete suspicious documents from user directories.",
            "Apply patches for vulnerable Office or browser versions.",
            "Run full memory and disk AV scan.",
            "Flush DNS cache: ipconfig /flushdns"
        ],
        "clearing_playbook": ["https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-phishing"],
        "mitre_mapping": [
            {"tactic": "Execution", "technique": "T1059", "example": "Adversaries may execute scripts after exploitation of client apps"},
            {"tactic": "Persistence", "technique": "T1136", "example": "A malicious document may lead to creation of persistence mechanisms"},
        ],
        "watchlist": [
            "Office apps spawning scripting engines or cmd.exe",
            "PDF readers executing or spawning external processes",
            "Users receiving files over email or through drive-by links"
        ],
        "enhancements": [
            "Enable ASR (Attack Surface Reduction) rules in Microsoft Defender.",
            "Use protected view for Office documents from the internet.",
            "Implement sandbox-based detonation of all external document files."
        ],
        "summary": "This technique involves exploiting vulnerabilities in client applications like browsers or Office software to achieve code execution. The approach leverages user interaction or drive-by tactics to deliver malicious content.",
        "remediation": "Keep client software updated, use endpoint protection, disable macros and scripting features by default.",
        "improvements": "Deploy memory protection technologies, enhance proxy filtering for exploit kits, and correlate endpoint behavior with threat intelligence.",
        "mitre_version": "16.1"
    }
