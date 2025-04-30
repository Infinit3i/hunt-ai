def get_content():
    return {
        "id": "T1021.004",
        "url_id": "T1021/004",
        "title": "Lateral Movement: SSH Hijacking",
        "tactic": "Lateral Movement",
        "protocol": "SSH, OpenSSH, Secure Shell",
        "os": "Windows, Linux, macOS",
        "description": "Adversaries may use SSH hijacking to move laterally within an environment. SSH hijacking involves an attacker stealing or hijacking SSH keys to gain unauthorized access to remote systems. Adversaries may abuse SSH keys to maintain persistence, escalate privileges, or exfiltrate data over encrypted channels.",
        "tips": [],
        "data_sources": "Sysmon, Authentication Logs, Process Creation Logs, Network Traffic Logs, Security Monitoring Tools",
        "log_sources": [
            {"type": "Authentication Logs", "source": "/var/log/auth.log, Windows Event Logs (Event ID 4648, 4624)"},
            {"type": "Process Creation Logs", "source": "Sysmon (Event ID 1, 11), Linux Auditd"},
            {"type": "Network Traffic Logs", "source": "Zeek (Bro), Suricata, Wireshark"},
            {"type": "Security Monitoring Tools", "source": "SIEM, Host-based IDS Logs"}
        ],
        "detection_methods": [
            "Monitor for SSH login attempts using stolen or hijacked credentials.",
            "Detect abnormal SSH activity from unusual geographic locations or user accounts.",
            "Identify new or unauthorized SSH key additions to known hosts."
        ],
        "spl_query": [
            "index=auth_logs sourcetype=linux_secure OR sourcetype=windows_security \n| search event_id=4624 OR event_id=4648 \n| stats count by src_ip, dest_ip, user"
        ],
        "hunt_steps": [
            "Run Queries in SIEM: Identify suspicious SSH authentication attempts.",
            "Analyze Process Creation Logs: Detect anomalies in SSH-related process executions.",
            "Monitor for Unusual SSH Traffic: Identify SSH sessions initiated from compromised hosts.",
            "Correlate with Threat Intelligence: Compare with known threat actors using SSH hijacking.",
            "Validate & Escalate: If malicious activity is found → Escalate to Incident Response."
        ],
        "expected_outcomes": [
            "SSH Hijacking Detected: Block unauthorized SSH access and investigate affected hosts.",
            "No Malicious Activity Found: Improve detection models for SSH-based lateral movement techniques."
        ],
        "mitre_mapping": [
            {"tactic": "Lateral Movement", "technique": "T1021.004 (SSH Hijacking)", "example": "Adversaries using stolen SSH keys to access remote systems."},
            {"tactic": "Defense Evasion", "technique": "T1078 (Valid Accounts)", "example": "Malware leveraging compromised SSH credentials to maintain persistence."}
        ],
        "watchlist": [
            "Flag SSH connections from untrusted or unexpected IP addresses.",
            "Monitor for anomalies in SSH authentication patterns.",
            "Detect unauthorized modification of SSH keys in `.ssh/authorized_keys`."
        ],
        "enhancements": [
            "Deploy multi-factor authentication (MFA) for SSH access.",
            "Implement behavioral analytics to detect abnormal SSH session activity.",
            "Improve correlation between SSH hijacking and known adversary tactics."
        ],
        "summary": "Document detected SSH hijacking activity and affected systems.",
        "remediation": "Block unauthorized SSH access, revoke compromised credentials, and enhance monitoring.",
        "improvements": "Refine detection models and improve analysis of SSH-based lateral movement techniques."
    }
