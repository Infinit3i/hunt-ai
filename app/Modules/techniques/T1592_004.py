def get_content():
    return {
        "id": "T1592.004",
        "url_id": "T1592/004",
        "title": "Gather Victim Host Information: Client Configurations",
        "description": "Adversaries may gather information about the victim's client configurations that can be used during targeting. This includes details such as OS version, architecture, language, time zone, and virtualization status. These insights can aid adversaries in tailoring exploits or evasion tactics.",
        "tags": ["reconnaissance", "client profiling", "targeted attacks"],
        "tactic": "Reconnaissance",
        "protocol": "HTTP/HTTPS",
        "os": "Windows, Linux, macOS",
        "tips": [
            "Deploy endpoint hardening policies to limit exposure of client fingerprinting data.",
            "Use browser privacy settings to suppress or randomize user-agent and language headers.",
            "Monitor outbound traffic for unusual requests to external scripts or beacons."
        ],
        "data_sources": "Internet Scan, Application Log, Process, User Account",
        "log_sources": [
            {"type": "Internet Scan", "source": "", "destination": ""},
            {"type": "Application Log", "source": "", "destination": ""},
            {"type": "Process", "source": "", "destination": ""},
            {"type": "User Account", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Browser History", "location": "User Profile > AppData", "identify": "Visited malicious or compromised collection sites"},
            {"type": "Process List", "location": "Memory Snapshot", "identify": "Injected or unauthorized data collection processes"}
        ],
        "destination_artifacts": [
            {"type": "Network Connections", "location": "Firewall/Proxy Logs", "identify": "Outbound connections to reconnaissance servers"},
            {"type": "Sysmon Logs", "location": "Event ID 1, 3", "identify": "Process creation or network activity related to recon scripts"}
        ],
        "detection_methods": [
            "Monitor browser user-agent and language string anomalies.",
            "Detect script execution collecting system information via logging tools like Sysmon or EDR.",
            "Correlate requests to known malicious infrastructure associated with ScanBox or similar kits."
        ],
        "apt": ["HAFNIUM", "ScanBox operators"],
        "spl_query": [
            'index=sysmon\n| search Image=*powershell.exe* OR CommandLine="*Get-WmiObject*" OR CommandLine="*systeminfo*"\n| stats count by Hostname, ParentImage, CommandLine'
        ],
        "hunt_steps": [
            "Review outbound web traffic to identify beaconing to known reconnaissance servers.",
            "Inspect endpoint logs for commands querying system metadata.",
            "Analyze web content served to internal clients for embedded reconnaissance scripts."
        ],
        "expected_outcomes": [
            "Identification of systems with collected host metadata exfiltrated externally.",
            "Detection of anomalous user-agent strings or system profiling behavior.",
            "Uncovering early reconnaissance efforts tailored to target vulnerabilities."
        ],
        "false_positive": "Legitimate IT tools and scripts may collect similar client configuration details for asset inventory or diagnostics. Baseline expected behavior to reduce alert noise.",
        "clearing_steps": [
            "Terminate suspicious recon processes and block associated outbound domains.",
            "Reset browsers and purge local caches storing malicious scripts.",
            "Update AV/EDR definitions to flag known reconnaissance kits like ScanBox."
        ],
        "clearing_playbook": [
            "https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-data-exfiltration"
        ],
        "mitre_mapping": [
            {"tactic": "Resource Development", "technique": "T1587", "example": "Tailoring malware to match identified system configurations"},
            {"tactic": "Initial Access", "technique": "T1195", "example": "Delivering supply chain payload compatible with target architecture"}
        ],
        "watchlist": [
            "Unusual user-agent headers in HTTP traffic",
            "Frequent systeminfo or WMI queries by non-admin users",
            "Outbound connections to rare or new IPs post site visit"
        ],
        "enhancements": [
            "Integrate system baseline checks into EDR telemetry.",
            "Use sandbox environments to emulate client fingerprinting and detect data leakage.",
            "Deploy honeypots configured with deceptive system configurations."
        ],
        "summary": "This technique focuses on collecting metadata about victim systems to optimize attack methods. Adversaries may leverage scripts embedded in websites or delivered via phishing to silently profile client machines, enabling precision exploitation.",
        "remediation": "Enforce browser hardening and block outbound connections to suspicious recon domains. Conduct threat hunting for known recon tool behavior and sanitize affected endpoints.",
        "improvements": "Enhance client-side protections to minimize data leakage. Implement layered logging across network, host, and application to correlate subtle fingerprinting activity.",
        "mitre_version": "16.1"
    }
