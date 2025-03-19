def get_content():
    return {
        "id": "T1584.004",  # Tactic Technique ID
        "url_id": "1584/004",  # URL segment for technique reference
        "title": "Compromise Infrastructure: Server",  # Name of the attack technique
        "description": "Adversaries may compromise third-party servers to stage or host malicious operations (e.g., Command and Control or phishing campaigns), allowing them to leverage existing infrastructure and remain less visible to defenders.",  # Simple description
        "tags": [
            "server compromise",
            "web server",
            "email server",
            "resource development"
        ],
        "tactic": "Resource Development",  # Associated MITRE ATT&CK tactic
        "protocol": "Various",  # Protocol used in the attack technique
        "os": "N/A",  # Targeted operating systems
        "tips": [
            "Monitor internet-facing servers for unusual configurations or installed software.",
            "Search for identifiable C2 patterns such as listening services, SSL/TLS anomalies, or suspicious certificates.",
            "Leverage threat intelligence to identify known malicious infrastructure linked to adversary campaigns."
        ],
        "data_sources": "Internet Scan",  # Data sources relevant to detection
        "log_sources": [
            {"type": "Internet Scan", "source": "Response Content", "destination": ""},
            {"type": "Internet Scan", "source": "Response Metadata", "destination": ""}
        ],
        "source_artifacts": [
            {
                "type": "Server configuration",
                "location": "Compromised server filesystem",
                "identify": "Check for malicious web shells, scripts, or binaries"
            }
        ],
        "destination_artifacts": [
            {
                "type": "Network Traffic",
                "location": "Outbound connections",
                "identify": "Identify suspicious traffic indicative of C2 or phishing campaigns"
            }
        ],
        "detection_methods": [
            "Monitor compromised server indicators through internet scanning tools or SSL/TLS fingerprinting.",
            "Check for suspicious services, domains, or certificates that may indicate adversary-controlled servers.",
            "Analyze web server logs for anomalous file uploads or modifications."
        ],
        "apt": [
            "Lazarus",
            "Turla",
            "Berserk Bear",
            "Evasive Panda",
            "Sandworm"
        ],
        "spl_query": [
            "index=network \n| stats count by src_ip, dest_ip, http_host"
        ],
        "hunt_steps": [
            "Correlate known malicious IPs/domains with server traffic logs to identify potential compromise.",
            "Review newly provisioned or modified servers for suspicious processes and files.",
            "Use SSL/TLS certificate transparency to detect newly issued certificates linked to known adversary patterns."
        ],
        "expected_outcomes": [
            "Identification of compromised third-party servers hosting malicious content.",
            "Detection of suspicious SSL/TLS certificates or listening services indicative of adversary C2."
        ],
        "false_positive": "Legitimate changes (e.g., hosting provider updates, certificate renewals) may appear suspicious; validate via change records and administrative logs.",
        "clearing_steps": [
            "Remove malicious software or web shells from the compromised server.",
            "Reinstall/patch the operating system and update services to the latest secure versions.",
            "Rotate credentials and enforce stronger access controls (e.g., MFA, IP allowlists).",
            "Monitor for further unauthorized changes or traffic post-remediation."
        ],
        "mitre_mapping": [
            {
                "tactic": "Resource Development",
                "technique": "Compromise Infrastructure: DNS Server (T1584.002)",
                "example": "After compromising a server, adversaries may also compromise DNS servers to redirect or hide traffic."
            }
        ],
        "watchlist": [
            "Unexpected server configurations or sudden changes in hosting environment.",
            "Unusual traffic patterns from servers (e.g., spikes in outbound connections).",
            "Certificates or domains associated with known adversary infrastructure."
        ],
        "enhancements": [
            "Automate server scanning for suspicious binaries or web shells.",
            "Integrate server logs with a SIEM to detect anomalies and correlate with threat intelligence.",
            "Leverage endpoint detection on servers to capture file system and process activity."
        ],
        "summary": "By compromising third-party servers, adversaries can covertly host malicious content or command and control infrastructure, reducing their need to acquire infrastructure directly and complicating attribution.",
        "remediation": "Secure publicly exposed servers by applying patches, restricting administrative access, and monitoring for unexpected file or configuration changes. Implement strong authentication and logging practices.",
        "improvements": "Adopt continuous scanning of external-facing infrastructure, employ certificate transparency monitoring, and maintain strict change-control processes for servers to quickly identify and remediate unauthorized modifications."
    }
