def get_content():
    return {
        "id": "T1598.004",
        "url_id": "T1598/004",
        "title": "Phishing for Information: Spearphishing Voice",
        "description": "Adversaries may use voice communications to elicit sensitive information that can be used during targeting. Spearphishing for information is an attempt to trick targets into divulging information, frequently credentials or other actionable information. In this scenario, adversaries use phone calls to elicit sensitive information from victims. Known as voice phishing (or 'vishing'), these communications can be manually executed by adversaries, hired call centers, or even automated via robocalls.",
        "tags": ["spearphishing", "vishing", "reconnaissance", "callback phishing", "voice phishing"],
        "tactic": "Reconnaissance",
        "protocol": "Voice",
        "os": "",
        "tips": [
            "Educate users to verify unknown callers and never provide credentials over the phone.",
            "Establish internal callback procedures for sensitive requests.",
            "Log and analyze unexpected calls to security or IT help desks."
        ],
        "data_sources": "Application Log",
        "log_sources": [
            {"type": "Application Log", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Call Records", "location": "VoIP systems", "identify": "Unusual call origin or timing"}
        ],
        "destination_artifacts": [
            {"type": "Call Records", "location": "PBX or Help Desk Systems", "identify": "Requests for sensitive access"}
        ],
        "detection_methods": [
            "Analyze logs from help desk ticketing systems for suspicious or repeated password reset requests.",
            "Monitor internal communications or reports referencing suspicious calls.",
            "Use voice analytics for detection of known vishing patterns."
        ],
        "apt": [
            "Octo Tempest", "DEV-0537", "TELCO BPO Campaign"
        ],
        "spl_query": [
            'index=helpdesk_logs\n| search "password reset" OR "account access" OR "verification"\n| stats count by caller_id, subject'
        ],
        "hunt_steps": [
            "Review recent help desk tickets for urgency-based requests.",
            "Identify VoIP or call logs with spoofed caller IDs.",
            "Correlate incidents with known callback phishing campaigns."
        ],
        "expected_outcomes": [
            "Detection of phishing via voice vectors.",
            "Identification of accounts that may have been socially engineered."
        ],
        "false_positive": "Legitimate urgent IT support calls may mimic vishing indicators. Verify call sources and request context.",
        "clearing_steps": [
            "Reset any compromised credentials.",
            "Audit user account activity for anomalies.",
            "Notify users of potential social engineering attacks.",
            "Update internal procedures to address phone-based phishing."
        ],
        "clearing_playbook": [
            "https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-phishing"
        ],
        "mitre_mapping": [
            {"tactic": "Credential Access", "technique": "T1556", "example": "Collected credentials may be used in account compromise attempts"}
        ],
        "watchlist": [
            "Repeated calls from same external numbers",
            "Callback numbers included in phishing emails",
            "Helpdesk tickets with voice-based support escalation"
        ],
        "enhancements": [
            "Integrate voice analytics and caller ID spoofing detection.",
            "Enhance user training on social engineering by voice."
        ],
        "summary": "Voice-based spearphishing (vishing) aims to elicit sensitive information from targets by impersonating trusted parties or exploiting urgency. This can include calls directing victims to dial malicious numbers or requests for access credentials under false pretenses.",
        "remediation": "Educate users about vishing tactics, implement robust verification procedures, and enhance logging of all sensitive phone interactions.",
        "improvements": "Use ML-driven analysis of voice communications, expand call logging infrastructure, and perform routine simulation exercises to test employee response.",
        "mitre_version": "16.1"
    }
