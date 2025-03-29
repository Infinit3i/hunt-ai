def get_content():
    return {
        "id": "T1210",
        "url_id": "T1210",
        "title": "Exploitation of Remote Services",
        "description": "Adversaries may exploit remote services to gain unauthorized access to internal systems once inside of a network.",
        "tags": ["Lateral Movement", "Remote Exploitation", "Vulnerability", "Post-Exploitation", "Privilege Escalation"],
        "tactic": "Lateral Movement",
        "protocol": "SMB, RDP, SSH, MySQL, HTTP",
        "os": "Windows, Linux, macOS",
        "tips": [
            "Keep patch management automated and frequent across all endpoints and servers.",
            "Use host-based intrusion detection to flag process crashes and behavior anomalies.",
            "Restrict lateral movement by enforcing network segmentation and least privilege."
        ],
        "data_sources": "Application Log, Network Traffic",
        "log_sources": [
            {"type": "Application Log", "source": "Event Viewer, Syslog, Systemd Journal", "destination": ""},
            {"type": "Network Traffic", "source": "Firewall, IDS/IPS, Suricata, Zeek", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Exploit Attempts", "location": "Network Traffic or Exploit Tool Output", "identify": "Payloads targeting vulnerable services (e.g., EternalBlue/MS17-010)"},
            {"type": "Scan Results", "location": "Reconnaissance Tool Logs", "identify": "Fingerprinting results showing unpatched services"}
        ],
        "destination_artifacts": [
            {"type": "Crash Dumps", "location": "C:\\CrashDumps or /var/crash", "identify": "Service failure due to unsuccessful exploit"},
            {"type": "Process Injection", "location": "Target Memory", "identify": "Injected shellcode post exploitation"}
        ],
        "detection_methods": [
            "Analyze failed login attempts followed by process execution.",
            "Inspect packet captures for exploit signatures or malformed requests.",
            "Correlate unpatched software with incoming connections from peer hosts."
        ],
        "apt": [
            "APT28", "Emissary Panda", "MuddyWater", "Tonto Team", "Carbon Spider", "Qakbot", "PIONEER KITTEN", "Earth Lusca", "Ryuk", "WannaCry", "NotPetya"
        ],
        "spl_query": [
            "index=network sourcetype=ids_alerts signature_id=*exploit* OR signature_id=*remote_code_exec*\n| stats count by src_ip, dest_ip, signature_id",
            "index=windows EventCode=1000 (Message=\"*.exe\" OR Message=\"crash*\" OR Message=\"fault*\")\n| stats count by host, Message"
        ],
        "hunt_steps": [
            "Identify systems with remote access services exposed internally (e.g., SMB, RDP).",
            "Correlate recent lateral network access to unpatched or outdated systems.",
            "Search for exploit tool usage such as Metasploit, Cobalt Strike, or Empire.",
            "Check for post-exploitation indicators like new user creation or scheduled tasks."
        ],
        "expected_outcomes": [
            "Exploitation attempts against remote services are detected and blocked.",
            "Compromise confirmed via logs or memory analysis on target systems.",
            "No exploitation observed, patching confirmed across vulnerable systems."
        ],
        "false_positive": "Port scans or vulnerability scanners may simulate exploit-like traffic. Validate with behavioral indicators.",
        "clearing_steps": [
            "Patch the exploited service and verify remediation via vulnerability scans.",
            "Isolate affected systems and check for persistence mechanisms or malware.",
            "Terminate unauthorized sessions and reset compromised credentials.",
            "Review and harden firewall rules to restrict unnecessary remote access."
        ],
        "clearing_playbook": ["https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-network-compromise"],
        "mitre_mapping": [
            {"tactic": "Lateral Movement", "technique": "T1210", "example": "Exploitation of SMB vulnerability MS17-010 for lateral access"},
            {"tactic": "Privilege Escalation", "technique": "T1068", "example": "Gaining SYSTEM after remote code execution via service exploit"},
            {"tactic": "Execution", "technique": "T1055", "example": "Post-exploit code injection into running process"}
        ],
        "watchlist": [
            "New service start events on previously dormant systems",
            "Incoming connections to SMB, RDP, or SSH with anomalous timing or frequency",
            "Outbound traffic following exploitation — such as C2 or staging"
        ],
        "enhancements": [
            "Deploy EDR capable of detecting exploit shellcode and memory injection",
            "Run regular internal vulnerability assessments to catch missed patches",
            "Use honeypots to catch exploitation attempts internally"
        ],
        "summary": "This technique describes lateral movement through exploitation of remote services using vulnerabilities such as SMB, RDP, and database servers once inside a network.",
        "remediation": "Patch all known vulnerabilities, use application allowlisting, and restrict unnecessary remote services.",
        "improvements": "Integrate threat intelligence signatures for known exploit payloads and harden lateral paths via ACLs and firewall controls.",
        "mitre_version": "16.1"
    }
