def get_content():
    return {
        "id": "T1036.001",
        "url_id": "T1036/001",
        "title": "Masquerading: Invalid Code Signature",
        "tactic": "Defense Evasion",
        "data_sources": "Process Creation Logs, File System Logs, Endpoint Logs, Security Monitoring Tools",
        "protocol": "Code Signing Manipulation, Digital Certificate Abuse, Signature Spoofing",
        "os": "Windows, Linux, macOS",
        "objective": "Detect and mitigate adversaries using invalid or improperly signed code to evade security controls and masquerade as legitimate software.",
        "scope": "Identify suspicious executables and libraries that appear to be signed but have invalid or mismatched signatures.",
        "threat_model": "Adversaries manipulate digital signatures, modify executable metadata, or use expired or revoked certificates to trick security tools and users into trusting malicious files.",
        "hypothesis": [
            "Are there executables running with invalid or mismatched signatures?",
            "Are adversaries leveraging expired or revoked certificates to execute malicious payloads?",
            "Is there an increase in processes signed by untrusted or unknown publishers?"
        ],
        "log_sources": [
            {"type": "Process Creation Logs", "source": "Sysmon (Event ID 1, 11), Windows Security Logs (Event ID 4688)"},
            {"type": "File System Logs", "source": "Windows Event Logs (Event ID 4663), Linux Auditd, macOS Unified Logs"},
            {"type": "Endpoint Logs", "source": "EDR (CrowdStrike, Defender ATP, Carbon Black)"},
            {"type": "Security Monitoring Tools", "source": "SIEM, Host-based IDS Logs"}
        ],
        "detection_methods": [
            "Monitor for execution of binaries with invalid or revoked signatures.",
            "Detect processes running with unexpected or mismatched digital certificates.",
            "Identify modifications to code signing attributes or metadata."
        ],
        "spl_query": [
            "index=endpoint sourcetype=sysmon \n| search signature_status=invalid OR signature_status=revoked \n| stats count by host, user, process_name, signature_publisher"
        ],
        "hunt_steps": [
            "Run Queries in SIEM: Identify execution of unsigned or invalidly signed binaries.",
            "Analyze Process Creation Logs: Detect anomalies in digital certificate attributes.",
            "Monitor for Unexpected Signature Changes: Identify executables with altered signatures.",
            "Correlate with Threat Intelligence: Compare with known defense evasion techniques.",
            "Validate & Escalate: If malicious activity is found → Escalate to Incident Response."
        ],
        "expected_outcomes": [
            "Invalid Code Signature Detected: Block execution of improperly signed files and investigate affected hosts.",
            "No Malicious Activity Found: Improve detection models for invalid code signature-based defense evasion techniques."
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1036.001 (Invalid Code Signature)", "example": "Adversaries using expired or self-signed certificates to execute malicious payloads."},
            {"tactic": "Persistence", "technique": "T1547 (Boot or Logon Autostart Execution)", "example": "Malware maintaining persistence using fake digital certificates."}
        ],
        "watchlist": [
            "Flag executions of binaries with revoked, expired, or self-signed certificates.",
            "Monitor for anomalies in digital signature verification results.",
            "Detect unauthorized modifications to code signing attributes."
        ],
        "enhancements": [
            "Deploy endpoint security tools that enforce strict code signing verification.",
            "Implement behavioral analytics to detect execution of untrusted binaries.",
            "Improve correlation between signature mismatches and known threat actor techniques."
        ],
        "summary": "Document detected malicious invalid code signature-based defense evasion activity and affected systems.",
        "remediation": "Block execution of improperly signed binaries, revoke compromised certificates, and enhance monitoring.",
        "improvements": "Refine detection models and improve analysis of invalid code signature-based defense evasion techniques."
    }
