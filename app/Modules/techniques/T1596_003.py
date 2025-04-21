def get_content():
    return {
        "id": "T1596.003",
        "url_id": "T1596/003",
        "title": "Search Open Technical Databases: Digital Certificates",
        "description": "Adversaries may search public digital certificate data for information about victims that can be used during targeting. Certificates used in HTTPS, code signing, and S/MIME can expose organizational details like names, geographic locations, subdomains, or email addresses.",
        "tags": ["certificate transparency", "ssl reconnaissance", "tls certificate", "x509", "osint"],
        "tactic": "Reconnaissance",
        "protocol": "TLS, HTTPS",
        "os": "",
        "tips": [
            "Use certificate minimization strategies—avoid overexposing domains or metadata.",
            "Regularly inspect CT logs for new certificates issued under your org’s name.",
            "Consider certificate pinning and use short-lived certs to reduce attack windows."
        ],
        "data_sources": "Certificate, Internet Scan, Domain Name, Asset",
        "log_sources": [
            {"type": "Certificate", "source": "", "destination": ""},
            {"type": "Internet Scan", "source": "", "destination": ""},
            {"type": "Domain Name", "source": "", "destination": ""},
            {"type": "Asset", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Browser History", "location": "Adversary Machine", "identify": "Lookups to crt.sh, censys.io, SSLShopper"},
            {"type": "DNS Cache", "location": "Adversary System", "identify": "Resolution of cert hosting domains or discovered subdomains"}
        ],
        "destination_artifacts": [
            {"type": "Certificates", "location": "Victim Server", "identify": "Organizational details and SAN entries revealed via TLS handshake"},
            {"type": "Network Connections", "location": "Public Portals", "identify": "Inbound requests querying cert info or hosting new phishing certs"}
        ],
        "detection_methods": [
            "Monitor for unusual certificate issuance using CT log monitoring tools.",
            "Correlate subdomain enumeration with certificate transparency search history.",
            "Inspect logs for repeated TLS handshakes by reconnaissance IPs focused on cert inspection."
        ],
        "apt": [],
        "spl_query": [
            'index=network_traffic\n| search tls_subject="*.yourdomain.com" AND user_agent IN ("openssl", "curl", "zgrab")\n| stats count by src_ip, tls_subject'
        ],
        "hunt_steps": [
            "Enumerate all valid certificates issued to your org across CT logs.",
            "Analyze issuance timelines for anomalies or third-party impersonation.",
            "Correlate internal DNS logs with discovered SAN entries."
        ],
        "expected_outcomes": [
            "Identification of organizational exposure through certificate metadata.",
            "Prevention of phishing or spoofing campaigns based on cert impersonation."
        ],
        "false_positive": "Security researchers, compliance scanners, or uptime checkers may perform TLS handshakes and metadata pulls regularly.",
        "clearing_steps": [
            "Revoke any unintended certificates with your CA.",
            "Replace verbose certs with minimized metadata versions.",
            "Notify third parties of improper certificate issuance if impersonation detected."
        ],
        "clearing_playbook": [
            "https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-data-exfiltration"
        ],
        "mitre_mapping": [
            {"tactic": "Initial Access", "technique": "T1199", "example": "Adversary uses domain from SAN entry to host spoofed login portal"},
            {"tactic": "Credential Access", "technique": "T1556", "example": "Stolen cert info used to trick victims into entering credentials"}
        ],
        "watchlist": [
            "New certs registered to your domain in CT logs",
            "Certs containing odd SAN values like misspellings or lookalikes",
            "Inbound reconnaissance using TLS scanners"
        ],
        "enhancements": [
            "Use CT log monitoring services (e.g., CertStream, Google CT) to detect cert issuance.",
            "Deploy DNS sinkholes for rogue cert SANs matching your infrastructure.",
            "Create alerts for outbound DNS queries to known certificate reconnaissance tools."
        ],
        "summary": "Certificate metadata and CT logs can reveal significant details about an organization’s infrastructure. Adversaries use this information to pivot to other reconnaissance techniques, phishing, or domain impersonation.",
        "remediation": "Implement certificate lifecycle hygiene, monitor CT logs, and revoke or reissue improperly exposed certs.",
        "improvements": "Automate cert transparency log ingestion and alerting; rotate certs regularly and reduce SAN bloat.",
        "mitre_version": "16.1"
    }
