def get_content():
    return {
        "id": "T1588.004",
        "url_id": "T1588/004",
        "title": "Obtain Capabilities: Digital Certificates",
        "description": "Adversaries may buy and/or steal SSL/TLS certificates that can be used during targeting. These certificates help instill trust and are commonly used for encrypting command and control traffic or conducting adversary-in-the-middle (AiTM) attacks. Certificates may be obtained through legitimate services, front organizations, or stolen from compromised entities including certificate authorities. Once acquired, adversaries may install them on malicious infrastructure to evade detection and enhance operational security.",
        "tags": ["resource-development", "certificate-theft", "encryption", "trust-abuse", "aitm"],
        "tactic": "Resource Development",
        "protocol": "HTTPS, TLS",
        "os": "Any",
        "tips": [
            "Monitor newly issued certificates associated with your domain or similar ones",
            "Track changes in SSL certs on known infrastructure",
            "Inspect certificate metadata for anomalous patterns"
        ],
        "data_sources": "Certificate, Internet Scan, Web Credential, Cloud Service, Application Log",
        "log_sources": [
            {"type": "Certificate", "source": "", "destination": ""},
            {"type": "Internet Scan", "source": "", "destination": ""},
            {"type": "Web Credential", "source": "", "destination": ""},
            {"type": "Cloud Service", "source": "", "destination": ""},
            {"type": "Application Log", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Browser History", "location": "Browser cache and history logs", "identify": "Access to Let's Encrypt or certificate authorities"},
            {"type": "Memory Dumps", "location": "Process memory during runtime", "identify": "Private key remnants or signed cert artifacts"}
        ],
        "destination_artifacts": [
            {"type": "Registry Hives (SOFTWARE)", "location": "HKLM\\SOFTWARE\\Microsoft\\SystemCertificates", "identify": "Root certs added programmatically"},
            {"type": "File", "location": "C:\\ProgramData\\SSL\\*.pem", "identify": "Installed certificate files used for HTTPS"}
        ],
        "detection_methods": [
            "Monitor for certificate registration activities associated with suspicious domains",
            "Alert on unusual SSL certificate changes in known infrastructure",
            "Correlate cert metadata with threat intel (issuer, fingerprint, CN)"
        ],
        "apt": ["Silent Librarian", "LuminousMoth", "PLEAD", "Honeybee", "AppleJeus", "COBALT DICKENS"],
        "spl_query": [
            "index=network sourcetype=ssl_certificates subject=* OR issuer=*lets encrypt*\n| stats count by subject, issuer, src_ip",
            "index=winregistry path=\"*Microsoft*SystemCertificates*\" value_name=TrustedPublisher\n| stats count by host, value_data"
        ],
        "hunt_steps": [
            "Pivot on suspicious SSL certificate fingerprints",
            "Scan passive DNS for reuse of certificate Common Names or SANs",
            "Look for abnormal root certificate installations on endpoints"
        ],
        "expected_outcomes": [
            "Detection of illegitimate or suspicious certificate usage",
            "Identification of C2 infrastructure using stealth certs",
            "Mapping adversary trust abuse across systems"
        ],
        "false_positive": "Organizations that automate certificate issuance or rotate keys frequently may trigger alerts. Whitelist known automation pipelines.",
        "clearing_steps": [
            "Revoke fraudulent certificates via CA portal",
            "Remove unauthorized root certificates from trust stores",
            "Block domains tied to illegitimate certificate activity"
        ],
        "clearing_playbook": ["https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-phishing"],
        "mitre_mapping": [
            {"tactic": "Command and Control", "technique": "T1573.002", "example": "Encrypt C2 traffic using stolen TLS certificate"},
            {"tactic": "Defense Evasion", "technique": "T1553.004", "example": "Install root certificate to bypass HTTPS checks"},
            {"tactic": "Collection", "technique": "T1557", "example": "Perform adversary-in-the-middle using trusted certificate"}
        ],
        "watchlist": [
            "Recently issued certificates with similar names to company domains",
            "Use of free cert providers by unknown infrastructure",
            "Downloads or references to stolen certificate bundles"
        ],
        "enhancements": [
            "Deploy certificate transparency monitoring tools (e.g., crt.sh alerts)",
            "Leverage TLS fingerprinting (JA3/JA4) to detect anomalous SSL behavior",
            "Maintain asset-based cert baseline for comparison"
        ],
        "summary": "Digital certificates obtained by adversaries enhance the stealth and legitimacy of their operations. These are used to encrypt traffic, enable MITM, or bypass SSL checks by leveraging trust relationships.",
        "remediation": "Leverage CA revocation services, investigate cert issuance spikes, and remove rogue root certificates. Conduct impact analysis on systems communicating over suspect SSL channels.",
        "improvements": "Integrate certificate telemetry with SIEM, track TLS cert reuse across infrastructure, and automate alerts on cert abuse patterns.",
        "mitre_version": "16.1"
    }
