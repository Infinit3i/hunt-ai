def get_content():
    return {
        "id": "T1567.002",
        "url_id": "T1567.002",
        "title": "Exfiltration Over Web Service: Exfiltration to Cloud Storage",
        "description": "Adversaries may exfiltrate data to cloud storage platforms such as Dropbox, Google Drive, OneDrive, or similar services. These platforms offer ubiquitous access, encrypted transfers, and seamless integration with legitimate user workflows, making them an attractive target for data theft and exfiltration.\n\nBecause corporate environments often allow traffic to such services, adversaries can blend in with normal business activity. Adversaries may automate the upload process using APIs, tools like `rclone`, or manually via GUI interaction. In some cases, data can be staged and split into smaller archives to further obfuscate detection.",
        "tags": ["cloud storage", "dropbox", "gdrive", "rclone", "data exfiltration", "T1567"],
        "tactic": "Exfiltration",
        "protocol": "HTTPS",
        "os": "Linux, Windows, macOS",
        "tips": [
            "Look for unusual outbound traffic patterns to cloud domains (e.g., upload-heavy sessions).",
            "Detect unauthorized or suspicious use of cloud storage synchronization tools.",
            "Use CASB or DLP solutions to inspect content uploads for sensitive material."
        ],
        "data_sources": "Command: Command Execution, File: File Access, Network Traffic: Network Connection Creation, Network Traffic: Network Traffic Content, Network Traffic: Network Traffic Flow",
        "log_sources": [
            {"type": "Network Traffic", "source": "Proxy, Firewall, CASB, DPI systems"},
            {"type": "Endpoint Activity", "source": "Sysmon, EDR solutions, command-line monitoring"},
            {"type": "Cloud Access Logs", "source": "Google Workspace, Microsoft 365, Dropbox for Business"}
        ],
        "source_artifacts": [
            {"type": "Sensitive Documents", "location": "Desktop, Temp folders, Network shares", "identify": "File types such as .docx, .pdf, .csv, .bak"}
        ],
        "destination_artifacts": [
            {"type": "Cloud Uploads", "location": "Dropbox, Google Drive, OneDrive", "identify": "File copies, sync logs, timestamps"}
        ],
        "detection_methods": [
            "Analyze network flows to cloud storage for upload-heavy sessions.",
            "Detect use of cloud CLI tools or scripts (e.g., rclone, curl, wget) accessing cloud APIs.",
            "Identify processes interacting with known cloud sync folders outside of business hours."
        ],
        "apt": [],
        "spl_query": [
            "index=proxy OR index=network sourcetype=firewall_logs OR sourcetype=proxy \n| search uri_domain IN (dropbox.com, drive.google.com, onedrive.live.com) AND http_method=POST \n| stats count by src_ip, uri_domain, http_method"
        ],
        "hunt_steps": [
            "Run SIEM queries to identify abnormal uploads to cloud storage endpoints.",
            "Check endpoint telemetry for use of cloud sync tools or large file compression activity.",
            "Correlate upload timestamps with user logins and command executions.",
            "Validate if the uploads match business-approved accounts or systems."
        ],
        "expected_outcomes": [
            "Cloud Storage Exfiltration Detected: Block access to involved services, isolate the host, and investigate further.",
            "No Malicious Activity Found: Refine monitoring thresholds and improve behavioral baselines."
        ],
        "false_positive": "Legitimate use of cloud services for data sharing and backup can generate similar traffic. Validate usage context and user roles before escalating.",
        "clearing_steps": [
            "Revoke cloud access tokens or API keys used for exfiltration.",
            "Delete or quarantine exfiltrated files from the cloud platform if accessible.",
            "Perform full disk and memory forensic analysis on involved endpoints."
        ],
        "mitre_mapping": [
            {"tactic": "Exfiltration", "technique": "T1567.002 (Exfiltration to Cloud Storage)", "example": "Stolen HR documents uploaded to attacker-controlled Dropbox account using rclone."}
        ],
        "watchlist": [
            "Flag outbound HTTPS uploads to cloud storage domains from unauthorized machines.",
            "Alert on use of cloud sync tools or browser logins from atypical IPs or geolocations.",
            "Monitor for excessive file access followed by network transfer spikes."
        ],
        "enhancements": [
            "Use DLP to restrict sensitive data uploads to external cloud platforms.",
            "Deploy behavioral analytics to detect abnormal upload behavior or application usage.",
            "Integrate cloud access security brokers (CASBs) for visibility and control."
        ],
        "summary": "This technique involves adversaries exfiltrating stolen data to legitimate cloud storage services like Dropbox or Google Drive. It is stealthy due to encrypted channels and business-friendly domains. Detection requires visibility into network flows, endpoint actions, and cloud service interactions.",
        "remediation": "Block access to unauthorized cloud services, rotate credentials, and conduct host and cloud artifact reviews.",
        "improvements": "Strengthen access controls to cloud storage, monitor for unauthorized sync tools, and apply contextual DLP policies.",
        "mitre_version": "16.1"
    }
