def get_content():
    return {
        "id": "T1566.004",
        "url_id": "T1566/004",
        "title": "Phishing: Spearphishing Voice",
        "tactic": "Initial Access",
        "data_sources": "Network Traffic, Call Logs, User Reports",
        "protocol": "VoIP, PSTN",
        "os": "N/A",
        "objective": "Adversaries use voice phishing (vishing) techniques to manipulate victims into disclosing credentials or downloading malware.",
        "scope": "Monitor for suspicious or unexpected phone calls attempting to elicit sensitive information or direct users to malicious sites.",
        "threat_model": "Attackers impersonate trusted entities over the phone, coercing victims into providing credentials or executing malicious actions.",
        "hypothesis": [
            "Are there reports of unsolicited calls requesting sensitive information?",
            "Are users being directed to fake login portals via voice calls?",
            "Are employees being pressured into performing unauthorized actions over the phone?"
        ],
        "log_sources": [
            {"type": "Network Traffic", "source": "VoIP Call Logs", "destination": "Phone Records"},
            {"type": "User Reports", "source": "Help Desk Complaints", "destination": "Security Team"}
        ],
        "detection_methods": [
            "Monitor for unusual incoming call patterns, particularly targeting high-value employees.",
            "Detect multiple failed login attempts following reported phishing calls.",
            "Analyze employee-reported phishing attempts and correlate with security incidents."
        ],
        "apt": ["Cobalt Group", "FIN7"],
        "spl_query": [
            "index=call_logs source=voip_logs caller_id=* target_employee=* vishing_attempt=*"
        ],
        "hunt_steps": [
            "Gather reports of suspicious calls from employees or help desk records.",
            "Correlate reports with login attempts, financial transactions, or data access logs.",
            "Analyze call metadata for patterns indicating potential phishing campaigns.",
            "Escalate confirmed phishing attempts to security response teams."
        ],
        "expected_outcomes": [
            "Spearphishing voice attacks identified and mitigated.",
            "Security awareness training adjusted based on attack trends.",
            "Improved detection of social engineering tactics over voice communication."
        ],
        "false_positive": "Legitimate business calls may resemble vishing attempts, requiring careful verification.",
        "clearing_steps": [
            "Notify affected employees and reset compromised credentials.",
            "Blacklist known attacker phone numbers and update security policies.",
            "Conduct post-incident reviews and refine detection measures."
        ],
        "mitre_mapping": [
            {"tactic": "Credential Access", "technique": "T1110 (Brute Force)", "example": "Attackers use credentials obtained via vishing to access accounts."},
            {"tactic": "Execution", "technique": "T1204.002 (User Execution - Malicious Link)", "example": "Vishing victims directed to fake login portals."}
        ],
        "watchlist": [
            "Monitor VoIP logs for high-frequency calls from unrecognized numbers.",
            "Flag multiple call attempts to the same organization within a short period.",
            "Train employees to report suspicious calls promptly."
        ],
        "enhancements": [
            "Implement caller ID verification and call screening for high-risk users.",
            "Conduct regular security awareness training on vishing threats.",
            "Integrate call monitoring with SIEM platforms to detect anomalies."
        ],
        "summary": "Spearphishing via voice (vishing) is a social engineering technique used by adversaries to extract credentials or persuade victims to perform malicious actions over the phone.",
        "remediation": "Encourage security-conscious communication practices, implement robust call verification methods, and educate employees on social engineering risks.",
        "improvements": "Enhance automated vishing detection through AI-based voice analysis and anomaly detection in call patterns."
    }
