def get_content():
    return {
        "id": "T1649",
        "url_id": "T1649",
        "title": "Steal or Forge Authentication Certificates",
        "description": "Adversaries may steal or forge digital certificates used for authentication. These certificates, often issued by enterprise CAs such as AD CS or Entra ID, can be used in place of credentials to access systems. Techniques include extracting certificates from the Windows Certificate Store, accessing them via crypto APIs, or requesting/renewing certificates if enrollment rights exist. Adversaries may also create 'golden' certificates by compromising root or subordinate CA private keys. Abuse of certificates can enable lateral movement, persistence, and privilege escalation.",
        "tags": ["AD CS", "EKU", "SAN", "golden certificate", "device identity", "PKI", "cryptoAPI", "Valid Accounts"],
        "tactic": "Credential Access",
        "protocol": "",
        "os": "Identity Provider, Linux, Windows, macOS",
        "tips": [
            "Correlate certificate issuance logs with unusual account behavior.",
            "Monitor certificate store access with tools like Sysmon or Windows Event Logs.",
            "Detect abnormal certificate enrollment or renewal requests from unexpected endpoints or users."
        ],
        "data_sources": "Active Directory: Active Directory Credential Request, Active Directory: Active Directory Object Modification, Application Log: Application Log Content, Command: Command Execution, File: File Access, Logon Session: Logon Session Creation, Windows Registry: Windows Registry Key Access",
        "log_sources": [
            {"type": "Active Directory", "source": "CA Logs, Certificate Services, Event ID 4886/4887", "destination": ""},
            {"type": "Command", "source": "PowerShell, CertUtil, Certify, PSPKIAudit", "destination": ""},
            {"type": "File", "source": "CryptoAPI, DPAPI, Registry", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Certificates", "location": "Local certificate store, registry hives, AD CS share", "identify": "PFX, .CER, or .P12 certificate formats"},
            {"type": "Certificate APIs", "location": "CryptoAPI/CertOpenSystemStore()", "identify": "Programmatic access to machine/user certs"},
            {"type": "CA Logs", "location": "Enterprise CA logging", "identify": "Issued certificates, renewal history"}
        ],
        "destination_artifacts": [
            {"type": "Forged Certificates", "location": "Memory, encrypted storage", "identify": "Certificates with spoofed SANs, EKUs, or long lifetimes"},
            {"type": "Golden Certificates", "location": "Adversary-controlled systems", "identify": "Custom-generated certs using root CA private key"},
            {"type": "Abused Identities", "location": "AD/Entra environments", "identify": "User/machine accounts authenticated with illegitimate certs"}
        ],
        "detection_methods": [
            "Detect abnormal certificate enrollment patterns (e.g., users issuing machine-level certs)",
            "Monitor for usage of known tools like Certify, CertStealer, Mimikatz with certificate modules",
            "Look for access to certificate stores (Cert:\, registry, files) during off-hours",
            "Alert on accounts requesting multiple certificates in short succession"
        ],
        "apt": [
            "APT29",
            "UNC2452 (SolarWinds)",
            "APT41",
            "Groups abusing AD CS for lateral movement"
        ],
        "spl_query": "index=wineventlog OR index=sysmon\n| search (event_id=4886 OR event_id=4887 OR Image=*certutil.exe* OR command_line=*request*)\n| stats count by user, host, event_id, command_line",
        "spl_rule": "https://research.splunk.com/detections/tactics/credential-access/",
        "elastic_rule": "https://grep.app/search?f.repo=elastic%2Fdetection-rules&q=T1649",
        "sigma_rule": "https://grep.app/search?f.repo=SigmaHQ%2Fsigma&q=T1649",
        "hunt_steps": [
            "Search for issued certificates with unusual SANs (e.g., privileged users)",
            "Review CertSrv logs for irregular certificate requests from compromised endpoints",
            "Run Certify or PSPKIAudit to assess CA template and permission misconfigurations",
            "Investigate registry and disk access to `HKCU\\Software\\Microsoft\\SystemCertificates` and `.pfx` file paths",
            "Check if root/subordinate CA private keys have been accessed or exfiltrated"
        ],
        "expected_outcomes": [
            "Detection of unauthorized certificate issuance or theft",
            "Identified lateral movement using certificate-based authentication",
            "CA template misconfigurations remediated"
        ],
        "false_positive": "Certificate renewals and machine enrollments can appear suspicious in DevOps or lab environments. Cross-check with enrollment templates and role-based access.",
        "clearing_steps": [
            "Revoke compromised certificates",
            "Reset affected accounts and disable compromised templates",
            "Audit and rotate CA private keys if exposed",
            "Configure stricter CA issuance policies (e.g., manager approval, EKU validation)"
        ],
        "mitre_mapping": [
            {"tactic": "Credential Access", "technique": "T1649 (Steal or Forge Authentication Certificates)", "example": "APT29 abusing AD CS template misconfigurations to forge authentication certs"}
        ],
        "watchlist": [
            "Users issuing certificates outside of helpdesk/admin roles",
            "Unusual PowerShell execution involving certificate-related cmdlets",
            "Machines accessing multiple certificate-related resources rapidly"
        ],
        "enhancements": [
            "Deploy alerting for CertUtil usage with enrollment or export switches",
            "Use Sysmon to log access to `.pfx`, `.cer`, `.crt`, `.pem` file types",
            "Enable CA logging and enforce least privilege on certificate templates"
        ],
        "summary": "Adversaries may steal or forge authentication certificates from AD CS, Entra ID, or local certificate stores. These are used to bypass MFA, move laterally, or impersonate privileged identities.",
        "remediation": "Revoke compromised certs, audit CA configs, rotate sensitive keys, and harden enrollment permissions.",
        "improvements": "Improve visibility into certificate issuance and store access. Deploy certificate-based detection rules across the environment.",
        "mitre_version": "16.1"
    }
