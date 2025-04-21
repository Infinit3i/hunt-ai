def get_content():
    return {
        "id": "T1656",
        "url_id": "T1656",
        "title": "Impersonation",
        "description": "Adversaries may impersonate trusted individuals or organizations to deceive targets into taking specific actions. This commonly occurs through phishing, spearphishing, or email fraud where the attacker pretends to be a colleague, executive, or vendor. Impersonation may support objectives like financial theft, data access, or further compromise of additional entities.",
        "tags": ["impersonation", "social-engineering", "BEC", "phishing", "reconnaissance", "deception"],
        "tactic": "Defense Evasion",
        "protocol": "",
        "os": "Linux, Office Suite, SaaS, Windows, macOS",
        "tips": [
            "Educate employees about suspicious language and impersonation tactics",
            "Use anti-spoofing email defenses like DMARC, SPF, and DKIM",
            "Conduct regular simulated phishing tests for high-risk staff"
        ],
        "data_sources": "Application Log: Application Log Content",
        "log_sources": [
            {"type": "Application Log", "source": "Email Security Gateway", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Phishing Email", "location": "Inbox", "identify": "Display name spoofing, altered domains"},
            {"type": "Fake Domain", "location": "Email headers", "identify": "Impersonated vendor or executive address"},
            {"type": "Language Triggers", "location": "Subject/body", "identify": "Keywords like 'urgent', 'wire', 'payment'"}
        ],
        "destination_artifacts": [
            {"type": "Compromised Credentials", "location": "Login portals", "identify": "Harvested via phishing links"},
            {"type": "Unauthorized Fund Transfers", "location": "Finance systems", "identify": "Fraudulent requests processed"},
            {"type": "Secondary Targets", "location": "Supply chain or internal systems", "identify": "Pivoting after initial trust abuse"}
        ],
        "detection_methods": [
            "Analyze headers for domain spoofing or look-alike domains",
            "Monitor inbox rule creation and automatic forwarding",
            "Scan email contents for urgency-based social engineering phrases",
            "Flag anomalous user logins after successful phishing campaigns"
        ],
        "apt": [
            "Lazarus Group", "Scattered Spider", "APT41", "Octo Tempest", "Cadet Blizzard"
        ],
        "spl_query": "index=email OR index=auth_logs \n| search subject=*urgent* OR subject=*payment* OR sender_domain IN (*spoofed*, *lookalike*) \n| stats count by src_user, subject, sender_domain",
        "spl_rule": "https://research.splunk.com/detections/tactics/defense-evasion/",
        "elastic_rule": "https://grep.app/search?f.repo=elastic%2Fdetection-rules&q=T1656",
        "sigma_rule": "https://grep.app/search?f.repo=SigmaHQ%2Fsigma&q=T1656",
        "hunt_steps": [
            "Correlate suspicious sender addresses with known vendors or executives",
            "Check for look-alike domain registrations tied to recent emails",
            "Investigate inbox rules redirecting to external accounts",
            "Analyze finance-related email requests for timing, sender, and wording anomalies"
        ],
        "expected_outcomes": [
            "Detected and blocked phishing or impersonation attempts",
            "Alerted finance teams to fraudulent payment requests",
            "Secured exposed user accounts targeted by impersonation"
        ],
        "false_positive": "Legitimate vendor communication or urgent business requests may resemble impersonation campaigns. Cross-verify with known contacts or out-of-band communications.",
        "clearing_steps": [
            "Notify affected users and reset credentials",
            "Revoke unauthorized inbox rules or forwarding",
            "Engage with vendors if impersonated domain was used"
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1656 (Impersonation)", "example": "Use of a fake executive identity to authorize payment"},
            {"tactic": "Impact", "technique": "T1657 (Financial Theft)", "example": "Impersonation campaign resulting in wire fraud"},
            {"tactic": "Reconnaissance", "technique": "T1589 (Gather Victim Identity Information)", "example": "Harvesting executive roles before impersonation"}
        ],
        "watchlist": [
            "Monitor inbox rule creation activity for VIP users",
            "Track recent domain registrations similar to internal brands",
            "Watch for finance system access from new IPs tied to email impersonation"
        ],
        "enhancements": [
            "Enable DMARC/DKIM/SPF enforcement across all domains",
            "Automate impersonation pattern detection using NLP-based classifiers",
            "Integrate threat intel around recently registered phishing domains"
        ],
        "summary": "Impersonation is a common defense evasion tactic where adversaries mimic trusted entities to gain access or elicit actions like wire transfers. It is often part of broader fraud campaigns, including business email compromise and credential harvesting.",
        "remediation": "Reset impacted user credentials, remove forwarding rules, notify affected external contacts, and report spoofed domains for takedown.",
        "improvements": "Build automated impersonation detection workflows and improve high-value personnel awareness through social engineering training.",
        "mitre_version": "16.1"
    }
