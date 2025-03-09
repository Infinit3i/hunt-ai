def get_content():
    return {
        "id": "T1021.003",
        "url_id": "T1021/003",
        "title": "Lateral Movement: Distributed Component Object Model (DCOM)",
        "tactic": "Lateral Movement",
        "data_sources": "Authentication Logs, Process Creation Logs, Network Traffic Logs, Security Monitoring Tools",
        "protocol": "DCOM, RPC, SMB",
        "os": "Windows",
        "objective": "Detect and mitigate adversaries leveraging DCOM for lateral movement and remote code execution.",
        "scope": "Identify unauthorized DCOM connections, remote object execution, and suspicious privilege escalations.",
        "threat_model": "Adversaries abuse DCOM objects to execute commands remotely on target machines by leveraging COM-based interactions over the network.",
        "hypothesis": [
            "Are there unauthorized DCOM activations on remote systems?",
            "Are adversaries leveraging DCOM to execute malicious commands remotely?",
            "Is there an increase in privilege escalations associated with DCOM activity?"
        ],
        "log_sources": [
            {"type": "Authentication Logs", "source": "Windows Event Logs (Event ID 4624, 4672, 4688)"},
            {"type": "Process Creation Logs", "source": "Sysmon (Event ID 1, 11), Windows Security Logs (Event ID 4688)"},
            {"type": "Network Traffic Logs", "source": "Zeek (Bro), Suricata, Wireshark, NetFlow"},
            {"type": "Security Monitoring Tools", "source": "SIEM, EDR (CrowdStrike, Defender ATP, Carbon Black)"}
        ],
        "detection_methods": [
            "Monitor for DCOM-related process executions on remote systems.",
            "Detect unusual network traffic patterns related to DCOM-based remote activations.",
            "Identify suspicious privilege escalations involving DCOM activation."
        ],
        "spl_query": [
            "index=auth_logs sourcetype=windows_security \n| search EventID=4688 OR EventID=4624 \n| stats count by src_ip, dest_ip, user, process_name"
        ],
        "hunt_steps": [
            "Run Queries in SIEM: Identify unauthorized DCOM activations.",
            "Analyze Process Creation Logs: Detect anomalies in DCOM-based remote executions.",
            "Monitor for Unusual DCOM Traffic: Identify suspicious remote COM object activations.",
            "Correlate with Threat Intelligence: Compare with known adversary tactics abusing DCOM.",
            "Validate & Escalate: If malicious activity is found → Escalate to Incident Response."
        ],
        "expected_outcomes": [
            "DCOM-Based Lateral Movement Detected: Block unauthorized DCOM access and investigate affected hosts.",
            "No Malicious Activity Found: Improve detection models for DCOM-based lateral movement techniques."
        ],
        "mitre_mapping": [
            {"tactic": "Lateral Movement", "technique": "T1021.003 (Distributed Component Object Model - DCOM)", "example": "Adversaries using DCOM objects to execute commands remotely."},
            {"tactic": "Privilege Escalation", "technique": "T1548 (Abuse Elevation Control Mechanism)", "example": "Attackers leveraging DCOM to escalate privileges on compromised systems."}
        ],
        "watchlist": [
            "Flag DCOM executions from unexpected or untrusted users.",
            "Monitor for anomalies in DCOM object activations and privilege escalations.",
            "Detect unauthorized use of remote COM object execution."
        ],
        "enhancements": [
            "Deploy Group Policy restrictions on DCOM access for non-administrators.",
            "Implement network segmentation to restrict unnecessary DCOM usage.",
            "Improve correlation between DCOM-based lateral movement and known threat actor techniques."
        ],
        "summary": "Document detected malicious DCOM lateral movement activity and affected systems.",
        "remediation": "Disable unnecessary DCOM access, enforce strong authentication policies, and enhance monitoring.",
        "improvements": "Refine detection models and improve analysis of DCOM-based lateral movement techniques."
    }
