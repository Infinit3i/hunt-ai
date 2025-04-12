def get_content():
    return {
        "id": "T1553.004",
        "url_id": "T1553/004",
        "title": "Subvert Trust Controls: Install Root Certificate",
        "description": "Adversaries may install a root certificate on a compromised system to avoid warnings when connecting to adversary-controlled web servers. This can allow adversaries to spoof legitimate services, intercept TLS/SSL traffic, or sign malicious code to evade detection.",
        "tags": ["Root Certificate", "Trust Exploitation", "Defense Evasion", "Windows", "macOS", "Linux"],
        "tactic": "Defense Evasion",
        "protocol": "",
        "os": "Linux, Windows, macOS",
        "tips": [
            "Monitor certificate store changes and additions.",
            "Compare installed certs with Microsoft's trusted root list.",
            "Use Sigcheck to identify non-standard root certs.",
            "Check for cloned cert metadata or reused chains."
        ],
        "data_sources": "Command: Command Execution, Process: Process Creation, Windows Registry: Windows Registry Key Creation, Windows Registry: Windows Registry Key Modification",
        "log_sources": [
            {"type": "Command", "source": "", "destination": ""},
            {"type": "Process", "source": "", "destination": ""},
            {"type": "Windows Registry", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Windows Registry", "location": "HKLM\\SOFTWARE\\Microsoft\\EnterpriseCertificates\\Root\\Certificates", "identify": "Installed root certs"},
            {"type": "Windows Registry", "location": "HKCU\\Software\\Microsoft\\SystemCertificates\\Root\\Certificates", "identify": "User-added root certs"}
        ],
        "destination_artifacts": [],
        "detection_methods": [
            "Certificate store monitoring",
            "Sigcheck analysis",
            "Registry key auditing",
            "Baseline comparison of root cert hashes"
        ],
        "apt": [
            "RTM",
            "Redaman",
            "Retefe",
            "osx.dok"
        ],
        "spl_query": [
            "index=windows_logs source=registry path=*\\Certificates\n| search action=add OR action=create"
        ],
        "hunt_steps": [
            "Review system root certificate store for anomalies.",
            "Run sigcheck -tuv to list and compare root certs.",
            "Check /Library/Keychains/System.keychain for suspicious entries (macOS)."
        ],
        "expected_outcomes": [
            "Discovery of unauthorized or non-standard root certificates",
            "Detection of certificate installation via registry or CLI"
        ],
        "false_positive": "Legitimate software or organizations may add internal CA certificates. Always compare against a trusted baseline and confirm usage context.",
        "clearing_steps": [
            "Manually remove unauthorized root certs via certmgr or system keychain.",
            "Delete certs from Registry locations or keychain storage.",
            "Use sigcheck to validate cleanup (Windows)."
        ],
        "clearing_playbook": [
            "https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-phishing"
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1557", "example": "Used for Adversary-in-the-Middle with fake HTTPS certs."}
        ],
        "watchlist": [
            "New registry entries under SystemCertificates\\Root",
            "Additions to macOS Keychains",
            "Certificates with reused issuer/subject fields"
        ],
        "enhancements": [
            "Alert on new root cert thumbprints",
            "Correlate cert additions with process execution paths"
        ],
        "summary": "Installing a root certificate enables adversaries to degrade system security by facilitating malicious HTTPS traffic interception and code signing trust abuse. It is used for stealth, persistence, and information theft.",
        "remediation": "Audit and remove non-standard root certs. Validate all cert store changes and restrict administrative privileges where possible.",
        "improvements": "Automate periodic dumping and diffing of system root certificates. Maintain certificate baseline profiles for system integrity checks.",
        "mitre_version": "16.1"
    }
