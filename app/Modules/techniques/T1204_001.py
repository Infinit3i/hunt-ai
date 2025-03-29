def get_content():
    return {
        "id": "T1204.001",
        "url_id": "T1204/001",
        "title": "User Execution: Malicious Link",
        "description": "An adversary may rely upon a user clicking a malicious link in order to gain execution.",
        "tags": ["Execution", "Phishing", "Malicious Link", "Drive-by", "Social Engineering"],
        "tactic": "Execution",
        "protocol": "HTTP, HTTPS",
        "os": "Windows, Linux, macOS",
        "tips": [
            "Monitor URLs clicked from emails and web browsers that result in file downloads or redirection.",
            "Inspect command-line processes triggered by browsers or email clients.",
            "Use web filtering and safe browsing tools to block malicious destinations."
        ],
        "data_sources": "File, Network Traffic",
        "log_sources": [
            {"type": "File", "source": "Browser Downloads", "destination": ""},
            {"type": "Network Traffic", "source": "Proxy Logs", "destination": ""},
            {"type": "Network Traffic", "source": "DNS Logs", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Email Content", "location": "Inbox or webmail", "identify": "Hyperlinks that lead to unknown domains"},
            {"type": "Browser Cache", "location": "%LocalAppData%\\Google\\Chrome\\User Data\\Default\\Cache", "identify": "Artifacts of redirected download payloads"}
        ],
        "destination_artifacts": [
            {"type": "Downloaded Files", "location": "%UserProfile%\\Downloads", "identify": "Payloads like .exe, .js, .scr from non-corporate domains"},
            {"type": "Process Execution", "location": "Memory", "identify": "Malicious executables launched from downloads"}
        ],
        "detection_methods": [
            "URL sandboxing or domain reputation analysis",
            "Proxy or firewall logs inspecting link redirection chains",
            "Browser spawned processes like powershell.exe, cmd.exe, or mshta.exe"
        ],
        "apt": [
            "TA505", "MUSTANG PANDA", "Sidewinder", "Patchwork", "Confucius", "Bumblebee", "TA450", "Cobalt Group", "Qakbot", "Elfin", "WinterVivern"
        ],
        "spl_query": [
            "index=proxy http_uri=* (http_uri=\"*.exe\" OR http_uri=\"*.scr\" OR http_uri=\"*.js\")\n| table _time, src_ip, http_uri, user_agent",
            "index=windows EventCode=4688 (ParentImage=\"*chrome.exe\" OR ParentImage=\"*outlook.exe\") (CommandLine=\"*powershell*\" OR CommandLine=\"*mshta*\")\n| stats count by ParentImage, Image, CommandLine"
        ],
        "hunt_steps": [
            "Review recent proxy logs for click-through activity to known phishing domains",
            "Correlate link click activity with download and execution behavior",
            "Scan inboxes for email campaigns with embedded links or QR codes"
        ],
        "expected_outcomes": [
            "Malicious link-clicking activity traced to payload download or browser exploit",
            "Normal link usage filtered through corporate web filters or secure DNS"
        ],
        "false_positive": "Legitimate applications may occasionally download executables. Validate download source and command-line execution context.",
        "clearing_steps": [
            "Clear browser cache and download history",
            "Delete downloaded malware or scripts",
            "Terminate any running malicious child processes",
            "Flush DNS resolver cache: ipconfig /flushdns"
        ],
        "clearing_playbook": ["https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-phishing"],
        "mitre_mapping": [
            {"tactic": "Execution", "technique": "T1203", "example": "Browser exploit triggered upon clicking a malicious link"},
            {"tactic": "Initial Access", "technique": "T1566.002", "example": "Phishing email with malicious link initiates download"}
        ],
        "watchlist": [
            "File downloads from public URLs clicked in email",
            "Execution of scripts or binaries downloaded shortly after a URL visit",
            "Browser processes spawning cmd or PowerShell"
        ],
        "enhancements": [
            "Use sandbox detonation for unknown URLs",
            "Apply domain-based blocklists and allowlists",
            "Implement URL rewriting and inspection in email security gateways"
        ],
        "summary": "This technique involves execution resulting from a user clicking a malicious link, often via email or a compromised website. It may lead to browser exploitation or the download and execution of additional payloads.",
        "remediation": "Educate users on link risks, enforce download controls, and deploy endpoint/browser monitoring.",
        "improvements": "Enhance threat intel enrichment on clicked domains, block script-based file downloads, and monitor browser execution chains.",
        "mitre_version": "16.1"
    }
