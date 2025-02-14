def get_content():
    return {
        "id": "T1021.001",
        "url_id": "T1021/001",
        "title": "Remote Services: Remote Desktop Protocol",
        "tactic": "lateral_movement",
        "data_sources": "Authentication Logs, Network Traffic Logs, Process Monitoring, Windows Event Logs",
        "protocol": "RDP (TCP/3389)",
        "os": "Windows",
        "objective": "Detect unauthorized or suspicious RDP access attempts that may indicate lateral movement.",
        "scope": "Monitor for unusual RDP authentication patterns, new RDP sessions from unknown hosts, and excessive failed logins.",
        "threat_model": "Adversaries may abuse RDP to move laterally within a network, gaining access to remote systems by using stolen credentials or brute-force attacks.",
        "hypothesis": [
            "Are there unauthorized RDP sessions being established?",
            "Are multiple failed RDP login attempts occurring in a short timeframe?",
            "Is RDP being used from uncommon source locations or outside business hours?",
            "Are new RDP connections occurring from hosts that don't usually initiate them?"
        ],
        "log_sources": [
            {"type": "Authentication Logs", "source": "Windows Security 4624, 4625, 4776", "destination": "Windows Security 4624, 4625"},
            {"type": "Network Traffic", "source": "Firewall Logs on the initiating machine showing outbound RDP (TCP/3389) attempts", "destination": "Firewall Logs on the destination machine receiving inbound RDP connections"},
            {"type": "Process Monitoring", "source": "Sysmon (Event ID 1 - Process Creation) on the source machine where the RDP client is executed", "destination": "Sysmon (Event ID 1, 3 - Network Connection) on the destination machine processing RDP sessions"},
            {"type": "EDR Logs", "source": "EDR solutions (e.g., CrowdStrike, Defender ATP, Carbon Black) logging RDP execution from the initiating machine", "destination": "EDR solutions detecting RDP session initiation on the target system"}
        ],
        "detection_methods": [
            "Monitor for successful RDP logins (Event ID 4624, Logon Type 10) from unusual source IPs.",
            "Detect excessive failed RDP login attempts (Event ID 4625) which may indicate brute force attempts.",
            "Analyze firewall logs for unexpected RDP traffic from external IPs or uncommon subnets.",
            "Use behavioral analytics to detect rare RDP session initiation patterns.",
            "Correlate RDP activity with account usage to detect compromised credentials."
        ],
        "spl_query": [
            "index=windows EventCode=4624 LogonType=10 | stats count by user, src_ip, dest_ip",
            "index=windows EventCode=4625 LogonType=10 | stats count by user, src_ip | where count > 5",
            "index=network protocol=RDP | stats count by src_ip, dest_ip"
        ],
        "hunt_steps": [
            "Analyze RDP login events (4624) to identify unauthorized access.",
            "Investigate excessive failed RDP logins (4625) for potential brute-force attacks.",
            "Review firewall logs for RDP traffic originating from unexpected locations.",
            "Correlate RDP activity with recent account logins to detect compromised credentials.",
            "Monitor new RDP sessions on critical servers that do not usually allow RDP access."
        ],
        "expected_outcomes": [
            "Unauthorized RDP access detected: Investigate the source and disable unauthorized sessions.",
            "Brute-force attempts identified: Block the source IP and enforce account lockout policies.",
        ],
        "false_positive": "Improve baseline detection rules and update monitoring policies.",
        "clearing_steps": [
            "Terminate unauthorized RDP sessions.",
            "Reset passwords for compromised accounts.",
            "Block RDP access from unapproved external IPs.",
            "Harden RDP access controls (e.g., enable MFA, restrict to VPN users)."
        ],
        "mitre_mapping": [
            {"tactic": "Lateral Movement", "technique": "T1021.001 (Remote Desktop Protocol)", "example": "Adversary uses RDP to move laterally by logging into another system with stolen credentials."}
        ],
        "watchlist": [
            "Monitor for RDP sessions initiated from unknown or foreign IP addresses.",
            "Alert on multiple failed RDP logins in a short timeframe.",
            "Flag first-time RDP usage on systems that do not typically use it."
        ],
        "enhancements": [
            "Enable RDP session recording for forensic analysis.",
            "Restrict RDP access to specific administrative users and approved IP ranges.",
            "Use behavioral analytics to detect anomalies in RDP session usage."
        ],
        "summary": "Detect and prevent unauthorized RDP access to mitigate lateral movement risks.",
        "remediation": "Investigate unauthorized RDP usage, enforce access controls, and strengthen authentication measures.",
        "improvements": "Enhance RDP detection capabilities with anomaly-based monitoring and behavioral analytics."
    }
