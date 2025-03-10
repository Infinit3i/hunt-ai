def get_content():
    return {
        "id": "T1001.002",
        "url_id": "T1001/002",
        "title": "Data Obfuscation: Steganography",
        "description": "Adversaries may use steganography to hide malicious data within image, audio, or video files. By embedding commands or data within multimedia files, adversaries can bypass traditional",
        "tactic": "Command and Control",
        "data_sources": "Suricata, zeek, Firewall, Proxy, Sysmon",
        "protocol": "HTTP, HTTPS, DNS, TCP, UDP",
        "os": "Mac, Linux, Windows",
        "log_sources": [
            {"type": "Suricata"},
            {"type": "Zeek "},
            {"type": "Firewall", "source": "Palo Alto, Fortinet, Cisco ASA"},
            {"type": "Proxy ", "source": "Zscaler, Bluecoat, McAfee Web Gateway"},
            {"type": "Sysmon", "source": "Sysmon (Event ID 1, 3), EDR (CrowdStrike, Defender ATP)"}
        ],
        "detection_methods": [
            "Monitor for unusual image, audio, or video file sizes in transit.",
            "Detect anomalies in network traffic containing embedded data.",
            "Identify modified file headers or unexpected metadata in transmitted files."
        ],
        "spl_query": [
            "index=network sourcetype=firewall_logs \n| search payload=*stego* OR payload=*hidden_data* OR payload=*encoded_image* \n| stats count by src_ip, dest_ip, payload"
        ],
        "hunt_steps": [
            "Run Queries in SIEM: Identify network traffic carrying steganographic payloads.",
            "Analyze File Metadata: Inspect unusual file modifications and hidden data.",
            "Monitor for Suspicious File Transfers: Track repeated or high-entropy file movements.",
            "Correlate with Threat Intelligence: Compare with known C2 techniques leveraging steganography.",
            "Validate & Escalate: If malicious activity is found → Escalate to Incident Response."
        ],
        "expected_outcomes": [
            "Steganography Detected: Block affected files and investigate the source.",
            "No Malicious Activity Found: Improve detection methods for hidden data obfuscation."
        ],
        "mitre_mapping": [
            {"tactic": "Command and Control", "technique": "T1001.002 (Steganography)", "example": "C2 commands embedded in images sent over HTTP."},
            {"tactic": "Exfiltration", "technique": "T1048 (Exfiltration Over Alternative Protocol)", "example": "Sensitive data hidden within an audio file and transmitted via FTP."},
            {"tactic": "Defense Evasion", "technique": "T1070.004 (Indicator Removal on Host)", "example": "Malware deleting modified steganographic files post-execution."}
        ],
        "watchlist": [
            "Flag outbound traffic containing files with anomalous entropy.",
            "Monitor for frequent file modifications with hidden data.",
            "Detect anomalies in multimedia file transfers."
        ],
        "enhancements": [
            "Implement file carving techniques to analyze hidden data.",
            "Deploy machine learning models to detect steganographic payloads.",
            "Improve correlation between file modifications and known malware behavior."
        ],
        "summary": "Document detected steganographic attempts and affected systems.",
        "remediation": "Block steganographic communication channels, revoke compromised access, and enhance network and file monitoring.",
        "improvements": "Refine detection models and improve analysis of steganographic obfuscation techniques."
    }
