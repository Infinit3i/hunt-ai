def get_content():
    return {
        "id": "T1560.001",
        "url_id": "T1560/001",
        "title": "Data Compression",
        "tactic": "Exfiltration",
        "data_sources": "Network Traffic, File Transfer",
        "protocol": "HTTP/HTTPS, FTP, SFTP, SMB, RDP, VPN",
        "os": "Windows, Linux, macOS",
        "objective": "Detect and mitigate unauthorized data compression activities, which may indicate that an adversary is staging data for exfiltration.",
        "scope": "Identify unusual compression of large files or sensitive data. Detect patterns where users or processes are compressing multiple files before exfiltration.",
        "threat_model": "Adversaries often compress large datasets before exfiltration to reduce size, evade detection, or encrypt files within an archive.",
        "hypothesis": [
            "Are there unusual compression activities from endpoints or servers?",
            "Is a system compressing sensitive directories before uploading to external locations?",
            "Are compressed file formats appearing in large outbound data flows?"
        ],
        "log_sources": [
            {"type": "File System Activity", "source": "Sysmon (Event ID 1 - Process Creation, Event ID 11 - File Creation)"},
            {"type": "Network Traffic", "source": "NetFlow, Zeek (Bro), Firewall Logs, IDS/IPS"},
            {"type": "File Transfer Logs", "source": "FTP, SFTP, SMB, HTTP logs from security appliances"},
            {"type": "EDR / Endpoint Logs", "source": "CrowdStrike, Defender ATP detecting unusual file compression"}
        ],
        "detection_methods": [
            "Monitor execution of compression tools (zip, rar, tar, 7z, PowerShell Compress-Archive).",
            "Detect large ZIP, RAR, 7z, tar, or gzip files appearing in outbound transfers.",
            "Identify suspicious process behavior associated with file compression."
        ],
        "expected_outcomes": [
            "Unauthorized Data Compression Detected: Investigate whether data compression is linked to exfiltration attempts. Alert SOC teams and initiate containment actions. Block further outbound transfers of suspicious compressed files.",
            "No Malicious Activity Found: Improve behavioral detection of file compression and transfers. Strengthen access controls on who can create ZIP, RAR, or 7z files."
        ],
        "mitre_mapping": [
            {"tactic": "Exfiltration", "technique": "T1048 (Exfiltration Over Alternative Protocol)", "example": "Attackers may transfer compressed files over HTTP/S, FTP, or RDP."},
            {"tactic": "Impact", "technique": "T1486 (Data Encrypted for Impact)", "example": "Ransomware may encrypt compressed files before demanding payment."},
            {"tactic": "Defense Evasion", "technique": "T1070.004 (Indicator Removal on Host)", "example": "Attackers may delete logs to erase traces of data compression."},
            {"tactic": "Persistence", "technique": "T1543.003 (Create or Modify System Process)", "example": "Adversaries may create a scheduled task to automate exfiltration."},
            {"tactic": "Command & Control", "technique": "T1102 (Web Service C2 Channel)", "example": "Data may be staged in external web services (e.g., Dropbox, Google Drive)."}
        ]
    }
