def get_content():
    return {
        "id": "T1608.003",
        "url_id": "T1608/003",
        "title": "Stage Capabilities: Install Digital Certificate",
        "description": "Adversaries may install SSL/TLS certificates as part of preparation for malicious operations. These digital certificates can be installed on web or email servers to establish encrypted communications, adding legitimacy to attacker infrastructure or enabling secure channels for command and control (C2).\n\nCertificates typically include a public key, owner identity, and a digital signature from a trusted certificate authority (CA). If valid, the certificate allows for encrypted, authenticated connections with the server. Adversaries may use certificates obtained from public CAs ([Digital Certificates](https://attack.mitre.org/techniques/T1588/004)) or generate their own self-signed certificates ([Digital Certificates](https://attack.mitre.org/techniques/T1587/003)).\n\nOnce a certificate is in hand, adversaries may upload it to infrastructure they control—either newly acquired ([Acquire Infrastructure](https://attack.mitre.org/techniques/T1583)) or previously compromised ([Compromise Infrastructure](https://attack.mitre.org/techniques/T1584))—to enable HTTPS or other encrypted protocols. This is often done to obscure network traffic and avoid detection during later phases of attack, such as [Asymmetric Cryptography](https://attack.mitre.org/techniques/T1573/002) over [Web Protocols](https://attack.mitre.org/techniques/T1071/001)).",
        "tags": ["https", "tls", "ssl", "certificate", "encryption", "c2", "credibility"],
        "tactic": "Resource Development",
        "protocol": "HTTPS",
        "os": "PRE",
        "tips": [
            "Pivot on certificate fingerprints to uncover additional malicious infrastructure.",
            "Use certificate transparency logs to track adversary-generated or reused certificates.",
            "Analyze certificate fields (e.g., CN, SAN) for suspicious domains or patterns."
        ],
        "data_sources": "Internet Scan: Response Content",
        "log_sources": [
            {"type": "Web Proxy", "source": "", "destination": "Server"},
            {"type": "SSL Inspection", "source": "", "destination": ""},
            {"type": "Network Sensor", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Certificate File", "location": "Attacker-Controlled Server", "identify": "PEM/CRT file used to enable HTTPS"},
            {"type": "CSR", "location": "Adversary Workstation", "identify": "Certificate Signing Request to obtain a valid cert"},
            {"type": "Self-signed Certificate", "location": "C2 Infrastructure", "identify": "Untrusted root CA with malicious trust chain"}
        ],
        "destination_artifacts": [
            {"type": "Signed Certificate", "location": "Server Certificate Store", "identify": "Installed cert allowing encrypted sessions"},
            {"type": "Web Config", "location": "Apache/Nginx/IIS", "identify": "SSL configuration referencing attacker cert"},
            {"type": "HTTPS Listener", "location": "Malicious Web Service", "identify": "Enabled secure traffic for phishing or C2"}
        ],
        "detection_methods": [
            "Monitor for installation of certificates on newly spun-up infrastructure.",
            "Track SSL certificate metadata such as CN, issuer, and fingerprint.",
            "Flag new certificates on known malicious IPs or domains."
        ],
        "apt": [
            "APT29: Used Let's Encrypt and other trusted CAs to issue certificates for C2 domains.",
            "FIN7: Installed certs on phishing and skimmer sites to avoid browser warnings.",
            "Lazarus Group: Deployed self-signed certs on internal infrastructure to secure lateral movement."
        ],
        "spl_query": "index=network_traffic sourcetype=ssl* \n| stats count by ssl_subject, ssl_issuer, ssl_fingerprint, dest_ip, uri_domain \n| search ssl_issuer IN [\"Let's Encrypt\", \"Cloudflare Inc ECC CA\"] \n| where count > 5",
        "spl_rule": "https://research.splunk.com/detections/tactics/resource-development/",
        "elastic_rule": "https://github.com/elastic/detection-rules/search?q=tls+certificate",
        "sigma_rule": "https://github.com/SigmaHQ/sigma/search?q=ssl+certificate",
        "hunt_steps": [
            "Query for newly registered certs on infrastructure tied to suspicious domains.",
            "Correlate certificate hashes with domains receiving a spike in traffic.",
            "Identify self-signed or mismatched certificates not issued by trusted CAs."
        ],
        "expected_outcomes": [
            "Discovery of certificates deployed on adversary-controlled systems.",
            "Visibility into attacker infrastructure using encryption for stealth.",
            "Linking of certificate metadata to other malicious domains or C2 servers."
        ],
        "false_positive": "Legitimate services often use Let's Encrypt or self-signed certificates for internal testing or CI/CD environments.",
        "clearing_steps": [
            "Revoke adversary-issued or self-signed certificates via hosting provider or CA.",
            "Remove certificates from server configuration and rotate to trusted certs.",
            "Block traffic to domains or IPs serving malicious or mismatched certificates."
        ],
        "mitre_mapping": [
            {"tactic": "Resource Development", "technique": "T1608.003", "example": "FIN7 deployed Let's Encrypt certificates on phishing infrastructure to bypass browser security warnings and appear legitimate to targets."}
        ],
        "watchlist": [
            "New domains issuing Let's Encrypt certs with low reputation scores.",
            "Servers presenting certs with high reuse across unrelated domains.",
            "Sudden increase in HTTPS traffic to unrecognized IPs or CDNs."
        ],
        "enhancements": [
            "Deploy certificate pinning where feasible for high-risk services.",
            "Use passive DNS and SSL metadata tools to monitor certificate usage.",
            "Integrate certificate transparency monitoring with threat intelligence workflows."
        ],
        "summary": "Adversaries may stage digital certificates on attacker infrastructure to support encrypted C2, phishing, or spoofed services. This enables stealthy, trusted communication and improves the believability of fake or malicious websites.",
        "remediation": "Revoke and replace compromised or attacker-installed certificates. Enforce TLS inspection where policy allows. Audit certificate issuance and usage across infrastructure.",
        "improvements": "Automate certificate metadata ingestion into threat intelligence feeds. Enrich detection with CT logs and fingerprint correlations. Promote certificate hygiene across all externally accessible services.",
        "mitre_version": "16.1"
    }
