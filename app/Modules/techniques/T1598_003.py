def get_content():
    return {
        "id": "T1598.003",
        "url_id": "T1598/003",
        "title": "Phishing for Information: Spearphishing Link",
        "description": "Adversaries may send spearphishing messages with a malicious link to elicit sensitive information that can be used during targeting. These messages often leverage social engineering tactics and are designed to trick users into clicking links that lead to credential harvesting websites, impersonated portals, or adversary-controlled infrastructure.",
        "tags": ["spearphishing", "credential harvesting", "quishing", "reconnaissance", "vulnerability exploitation"],
        "tactic": "Reconnaissance",
        "protocol": "HTTP(S)",
        "os": "",
        "tips": [
            "Train users to verify links and look for signs of spoofed websites.",
            "Implement robust email filtering with URL analysis and sandboxing.",
            "Deploy endpoint protections that monitor browser-based phishing indicators."
        ],
        "data_sources": "Application Log, Network Traffic",
        "log_sources": [
            {"type": "Application Log", "source": "", "destination": ""},
            {"type": "Network Traffic", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Browser History", "location": "User Profile", "identify": "Visited phishing page URLs"},
            {"type": "Clipboard Data", "location": "System Memory", "identify": "Copied phishing links"}
        ],
        "destination_artifacts": [
            {"type": "Web Server Logs", "location": "Remote phishing infrastructure", "identify": "Credential POST requests from victims"}
        ],
        "detection_methods": [
            "Inspect URLs in emails for spoofing or known phishing domains.",
            "Monitor outbound connections to newly registered or rare domains.",
            "Use content disarm and reconstruction (CDR) to neutralize phishing payloads."
        ],
        "apt": [
            "Star Blizzard", "COBALT DICKENS", "Zebrocy", "Ocean Lotus", "COLDRIVER", "Charming Kitten", "Kimsuky", "Silent Librarian"
        ],
        "spl_query": [
            'index=email_logs\n| search "http" OR "https"\n| eval lower_url=lower(url)\n| where like(lower_url,"%login%") OR like(lower_url,"%auth%")\n| stats count by sender, recipient, url'
        ],
        "hunt_steps": [
            "Identify emails containing suspicious shortened or obfuscated links.",
            "Search for QR codes or HTML email content with 1x1 tracking pixels.",
            "Correlate traffic to possible adversary-in-the-middle phishing kits (Evilginx2, EvilProxy)."
        ],
        "expected_outcomes": [
            "Detection of spearphishing emails containing credential harvesting links.",
            "Discovery of sessions hijacked using stolen cookies."
        ],
        "false_positive": "Legitimate marketing emails may contain tracking pixels or shortened links. Whitelist known business domains after review.",
        "clearing_steps": [
            "Force password resets for exposed credentials.",
            "Revoke session tokens or cookies for compromised accounts.",
            "Report phishing sites to takedown services and block at the perimeter."
        ],
        "clearing_playbook": [
            "https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-phishing"
        ],
        "mitre_mapping": [
            {"tactic": "Credential Access", "technique": "T1556", "example": "Stolen credentials used for initial access"},
            {"tactic": "Persistence", "technique": "T1550.004", "example": "Session cookie reuse bypassing MFA"}
        ],
        "watchlist": [
            "Newly registered phishing domains",
            "Email subject lines with urgency or password expiration themes",
            "Presence of BitB-style fake login popups in user screenshots"
        ],
        "enhancements": [
            "Deploy phishing-resistant MFA (FIDO2/WebAuthn).",
            "Enrich link scanning tools with threat intelligence feeds.",
            "Enable real-time alerts for impersonated domains."
        ],
        "summary": "Spearphishing links are a common technique used to lure victims to malicious websites where credentials and session tokens may be stolen. Attackers often obfuscate URLs or use phishing kits to proxy legitimate services while harvesting sensitive data.",
        "remediation": "Force credential resets, review endpoint behavior for malicious downloads or script execution, and implement email link scanning with isolation if possible.",
        "improvements": "Enhance phishing simulations with quishing and BitB scenarios, and monitor DNS queries for sudden resolution spikes to newly seen domains.",
        "mitre_version": "16.1"
    }
