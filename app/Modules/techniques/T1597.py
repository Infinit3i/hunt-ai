def get_content():
    return {
        "id": "T1597",
        "url_id": "T1597",
        "title": "Search Closed Sources",
        "description": "Adversaries may search and gather information about victims from closed (e.g., paid, private, or otherwise not freely available) sources that can be used during targeting. These sources include commercial data aggregators, threat intelligence portals, or blackmarket/dark web forums. Accessing this information may assist in planning further actions such as phishing, infrastructure mimicry, and account compromise.",
        "tags": ["closed-source intelligence", "paid data", "blackmarket", "reconnaissance"],
        "tactic": "Reconnaissance",
        "protocol": "",
        "os": "",
        "tips": [
            "Regularly monitor commercial and underground sources for mentions of your organization.",
            "Implement dark web monitoring and breach alert services.",
            "Tag decoy entries (e.g., honeytokens) to detect use of purchased internal data."
        ],
        "data_sources": "",
        "log_sources": [],
        "source_artifacts": [
            {"type": "Leaked Credentials", "location": "Dark Web Forums", "identify": "Credential reuse in login attempts"},
            {"type": "Target Profiles", "location": "Threat Intel Feeds", "identify": "Industry-specific attack insights"}
        ],
        "destination_artifacts": [
            {"type": "Phishing Kits or Campaign Content", "location": "Adversary Infrastructure", "identify": "Email templates or payloads matching internal branding"}
        ],
        "detection_methods": [
            "Monitor for abnormal credential use or access attempts aligned with known data leaks.",
            "Correlate reconnaissance timing with major breach disclosures or vendor report access.",
            "Use deception entries to detect access via underground or private sources."
        ],
        "apt": [
            "EXOTIC LILY"
        ],
        "spl_query": [
            'index=auth_logs OR index=darkweb_monitoring\n| search leaked_data="true"\n| stats count by user, src_ip, method'
        ],
        "hunt_steps": [
            "Trace IPs interacting with honeypots for signs of leaked data testing.",
            "Cross-reference actor infrastructure with observed interest in threat intel feeds.",
            "Monitor for campaigns resembling recent vendor report disclosures."
        ],
        "expected_outcomes": [
            "Detection of adversary reconnaissance via data purchased from private or underground sources.",
            "Understanding of which internal assets are exposed through non-public channels."
        ],
        "false_positive": "Some leaked data reuse may stem from credential stuffing tools or penetration tests. Validate IPs and toolsets involved.",
        "clearing_steps": [
            "Reset exposed credentials and revoke session tokens.",
            "Work with breach monitoring services to track and mitigate future leaks.",
            "Update detection rules for TTPs seen in underground chatter or commercial exposure."
        ],
        "clearing_playbook": [
            "https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-data-exfiltration"
        ],
        "mitre_mapping": [
            {"tactic": "Credential Access", "technique": "T1078", "example": "Use of purchased valid accounts for system access"},
            {"tactic": "Initial Access", "technique": "T1133", "example": "Use of infrastructure details to exploit externally facing systems"}
        ],
        "watchlist": [
            "Email addresses or IPs found in third-party breach disclosures",
            "TTPs overlapping with vendor report indicators",
            "Sudden attacks matching internal asset configurations"
        ],
        "enhancements": [
            "Place false credentials in data broker systems to detect malicious reuse.",
            "Utilize threat intel partners to detect early targeting activity.",
            "Conduct proactive red teaming simulating closed-source reconnaissance."
        ],
        "summary": "Closed source reconnaissance involves gathering technical or organizational data from non-public platforms such as paid threat intelligence services or underground forums. Adversaries use this information to tailor campaigns and increase success probabilities in further intrusion stages.",
        "remediation": "Purge or rotate exposed credentials, update detection coverage, and engage with vendors or law enforcement to pursue takedowns where applicable.",
        "improvements": "Use honeypot assets to detect adversary queries, refine detection of suspicious reconnaissance behaviors, and establish baselines for legitimate use of intelligence sources.",
        "mitre_version": "16.1"
    }
