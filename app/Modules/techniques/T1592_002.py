def get_content():
    return {
        "id": "T1592.002",
        "url_id": "T1592/002",
        "title": "Gather Victim Host Information: Software",
        "description": "Adversaries may gather information about the victim's host software that can be used during targeting. Information about installed software may include types and versions on specific hosts, as well as defensive tools such as antivirus or SIEMs.",
        "tags": ["reconnaissance", "host profiling", "software inventory"],
        "tactic": "Reconnaissance",
        "protocol": "HTTP",
        "os": "Windows, Linux, macOS",
        "tips": [
            "Correlate network traffic with known scanner user-agent strings.",
            "Monitor for outbound connections to domains known for passive reconnaissance tools."
        ],
        "data_sources": "Internet Scan",
        "log_sources": [
            {"type": "Internet Scan", "source": "", "destination": ""},
            {"type": "Windows Security", "source": "", "destination": ""},
            {"type": "Sysmon", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Browser History", "location": "%APPDATA%\\Browser\\History", "identify": "User visited reconnaissance-linked site"},
            {"type": "Network Connections", "location": "System Network Logs", "identify": "Outbound traffic to reconnaissance domains"}
        ],
        "destination_artifacts": [
            {"type": "Event Logs", "location": "%SystemRoot%\\System32\\winevt\\Logs", "identify": "Possible reconnaissance scanning detected"}
        ],
        "detection_methods": [
            "Analyze outbound connections to uncommon domains",
            "Monitor user-agent strings in HTTP headers",
            "Inspect proxy logs for reconnaissance patterns"
        ],
        "apt": [
            "Andariel", "Charming Kitten", "Sandworm"
        ],
        "spl_query": [
            "index=proxy_logs user_agent=*scanner* OR user_agent=*curl* OR user_agent=*python-requests*\n| stats count by src_ip, user_agent"
        ],
        "hunt_steps": [
            "Review proxy logs for anomalous user-agents",
            "Check DNS queries for domain names associated with recon activity",
            "Correlate external connections with reconnaissance tool behavior"
        ],
        "expected_outcomes": [
            "Identification of scanning behavior aimed at host software enumeration",
            "Early detection of potential target profiling activities"
        ],
        "false_positive": "Legitimate vulnerability scanners or IT inventory tools may trigger similar artifacts. Validate context and frequency.",
        "clearing_steps": [
            "Clear browser history with: RunDll32.exe InetCpl.cpl,ClearMyTracksByProcess 1",
            "Flush DNS cache: ipconfig /flushdns",
            "Delete event logs: wevtutil cl Application"
        ],
        "clearing_playbook": [
            "https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-phishing"
        ],
        "mitre_mapping": [
            {"tactic": "Initial Access", "technique": "T1133", "example": "Use of remote service post-recon"},
            {"tactic": "Resource Development", "technique": "T1587", "example": "Develop capability post-software enumeration"}
        ],
        "watchlist": [
            "Connections to known recon sites",
            "Hosts generating high-volume HTTP HEAD requests"
        ],
        "enhancements": [
            "Integrate user-agent anomaly detection in SIEM",
            "Enrich proxy logs with threat intelligence feeds"
        ],
        "summary": "Adversaries collect software information on victim hosts to inform follow-on actions like initial access or capability development.",
        "remediation": "Limit software exposure via external-facing services, implement egress filtering, and regularly audit network traffic.",
        "improvements": "Deploy advanced HTTP inspection proxies and ensure all user-agent logs are normalized for analysis.",
        "mitre_version": "16.1"
    }
