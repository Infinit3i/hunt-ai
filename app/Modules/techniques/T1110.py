def get_content():
    """
    Returns structured content for the Brute-Force Credential Access (T1110) method.
    """
    return {
        "id": "T1110",
        "url_id": "T1110",
        "title": "Brute-Force Credential Access",
        "tactic": "Credential Access",
        "data_sources": "Authentication Logs, Windows Event Logs, Network Traffic",
        "protocol": "Various (RDP, SMB, SSH, HTTP, etc.)",
        "os": "Windows, Linux, macOS",
        "objective": "Adversaries may attempt to gain unauthorized access to accounts by systematically guessing passwords.",
        "scope": "Monitor authentication logs and network traffic for repeated failed login attempts.",
        "threat_model": "Attackers systematically attempt different username and password combinations to gain unauthorized access.",
        "hypothesis": [
            "Are multiple failed login attempts occurring in rapid succession?",
            "Are login attempts originating from unusual geographic locations?",
            "Are known compromised credentials being used in authentication attempts?"
        ],
        "tips": [
            "Monitor for Event ID 4625 (failed logon attempts) and 4768 (TGT request failures).",
            "Analyze network traffic for high-volume authentication attempts.",
            "Implement account lockout policies to prevent brute-force attacks."
        ],
        "log_sources": [
            {"type": "Windows Event Logs", "source": "Security.evtx", "destination": "System.evtx"},
            {"type": "Network Traffic", "source": "Firewall Logs", "destination": "Authentication Systems"},
            {"type": "Authentication Logs", "source": "Domain Controller", "destination": "SIEM"}
        ],
        "source_artifacts": [
            {"type": "Authentication Logs", "location": "Domain Controller", "identify": "Failed login attempts"}
        ],
        "destination_artifacts": [
            {"type": "Firewall Logs", "location": "Perimeter Network", "identify": "High-volume authentication requests"}
        ],
        "detection_methods": [
            "Analyze failed authentication attempts over time.",
            "Monitor for anomalous login attempts from different geographic regions.",
            "Correlate failed logins with known breached credentials."
        ],
        "apt": ["G0016", "G0032"],
        "spl_query": [
            "index=windows EventCode=4625 | stats count by Account_Name, Source_Network_Address",
            "index=firewall_logs action=blocked | search authentication failure | table Source_IP, Destination"
        ],
        "hunt_steps": [
            "Identify high-frequency failed login attempts.",
            "Correlate login attempts with known compromised credential databases.",
            "Investigate login sources and determine legitimacy."
        ],
        "expected_outcomes": [
            "Unauthorized access attempts detected and mitigated.",
            "False positives minimized with improved detection baselines."
        ],
        "false_positive": "Users may mistype their passwords multiple times, triggering failed login alerts.",
        "clearing_steps": [
            "Disable compromised accounts and enforce password changes.",
            "Update firewall rules to block repeated brute-force attempts from malicious IPs."
        ],
        "mitre_mapping": [
            {"tactic": "Credential Access", "technique": "T1556 (Modify Authentication Process)", "example": "Attackers attempt to bypass authentication by modifying login mechanisms."}
        ],
        "watchlist": [
            "Monitor for repeated authentication failures in a short time frame.",
            "Detect multiple login attempts from different locations for the same account."
        ],
        "enhancements": [
            "Implement Multi-Factor Authentication (MFA) to prevent brute-force attacks.",
            "Enforce account lockout policies after multiple failed login attempts."
        ],
        "summary": "Adversaries may attempt to gain unauthorized access by brute-forcing credentials.",
        "remediation": "Implement MFA, strong password policies, and lockout mechanisms to prevent brute-force attacks.",
        "improvements": "Improve monitoring for failed login attempts and correlate with known threat intelligence sources."
    }
