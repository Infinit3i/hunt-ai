def get_content():
    return {
        "id": "T1588.003",
        "url_id": "T1588/003",
        "title": "Obtain Capabilities: Code Signing Certificates",
        "description": "Adversaries may buy and/or steal code signing certificates that can be used during targeting. These certificates allow adversaries to digitally sign malicious executables or scripts, making them appear trustworthy to users and security tools. Certificates may be acquired through legitimate purchases using front companies or stolen directly from compromised entities. The goal is to increase trust in the payload and potentially bypass security controls that favor signed binaries.",
        "tags": ["resource-development", "code-signing", "certificate-theft", "trust-abuse", "stealth"],
        "tactic": "Resource Development",
        "protocol": "",
        "os": "Any",
        "tips": [
            "Track issuance and usage of code signing certificates within your organization",
            "Monitor for newly signed binaries from unknown or suspicious publishers",
            "Pivot on certificate thumbprints or issuer information in threat intelligence platforms"
        ],
        "data_sources": "Malware Repository: Malware Metadata, Endpoint: File Metadata, Certificate",
        "log_sources": [
            {"type": "Malware Repository", "source": "", "destination": ""},
            {"type": "Endpoint", "source": "File Metadata", "destination": ""},
            {"type": "Certificate", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "PE File", "location": "Malware sandbox samples", "identify": "Digitally signed malware with known thumbprint"},
            {"type": "Memory Dump", "location": "In-memory cert material from compromised system", "identify": "Private key remnants or cert objects"}
        ],
        "destination_artifacts": [
            {"type": "File", "location": "C:\\Windows\\Temp\\*.exe", "identify": "Signed payload dropped to disk"},
            {"type": "Registry", "location": "HKCU\\Software\\Microsoft\\SystemCertificates", "identify": "Certificate installation artifacts"}
        ],
        "detection_methods": [
            "Monitor code signing events and inspect certificate issuer, validity, and thumbprint",
            "Correlate signed binaries with threat intelligence and known malware reports",
            "Detect anomalous or infrequent certificate issuers among internal apps"
        ],
        "apt": ["APT41", "Lazarus Group", "FIN12", "Iron Tiger", "Palmerworm", "Ryuk", "MegaCortex", "Sardonic"],
        "spl_query": [
            "index=malware_repository signature_status=\"Signed\" thumbprint!=<known trusted list>\n| stats count by file_name, publisher, thumbprint",
            "index=endpoint sourcetype=winlog source_image=* path=\"*\\Temp\\*.exe\" signature_status=\"Signed\"\n| stats count by host, file_name, signer"
        ],
        "hunt_steps": [
            "Hunt for recently seen signed executables from unknown or suspicious issuers",
            "Review rare code signing cert thumbprints seen in internal environments",
            "Scan sandboxed samples for reused cert signatures"
        ],
        "expected_outcomes": [
            "Detection of adversary-signed malware or tools",
            "Identification of stolen or abused code signing certs",
            "Enhanced visibility into cert-based trust abuse"
        ],
        "false_positive": "New internal code signing operations may trigger alerts. Validate new certs and whitelist known development teams or software pipelines.",
        "clearing_steps": [
            "Revoke compromised code signing certificates via provider",
            "Purge affected binaries from endpoints and remove registry or file traces",
            "Update blocklists and threat feeds with discovered thumbprints or issuers"
        ],
        "clearing_playbook": ["https://www.mandiant.com/resources/blog/code-signing-abuse-remediation-playbook"],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1553.002", "example": "Signed malware to bypass antivirus and EDR"},
            {"tactic": "Execution", "technique": "T1204", "example": "Signed dropper executed by victim"},
            {"tactic": "Persistence", "technique": "T1547", "example": "Signed malicious tool embedded into startup registry"}
        ],
        "watchlist": [
            "Thumbprints of recently issued certs from unknown CAs",
            "Signed malware discovered in threat intel platforms",
            "Malware samples linked to adversary-signed tools"
        ],
        "enhancements": [
            "Automate thumbprint matching across environments",
            "Enable integration between malware sandboxes and cert monitoring",
            "Correlate VirusTotal cert fields with internal telemetry"
        ],
        "summary": "Code signing certificates give adversaries the ability to make their malware appear legitimate and trusted. When obtained and used in operations, they enable stealthy delivery and execution paths that are harder to detect and block.",
        "remediation": "Revoke abused certs immediately and monitor for binaries using them. Investigate cert acquisition channels and limit cert trust scope internally.",
        "improvements": "Deploy centralized code signing oversight, enforce developer cert registration, and integrate certificate revocation checks into endpoint tools.",
        "mitre_version": "16.1"
    }
