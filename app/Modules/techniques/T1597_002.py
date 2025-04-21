def get_content():
    return {
        "id": "T1597.002",
        "url_id": "T1597/002",
        "title": "Search Closed Sources: Purchase Technical Data",
        "description": "Adversaries may purchase technical information about victims from commercial data aggregators, dark web markets, or cybercriminal forums. This information can aid in reconnaissance or enable further stages such as phishing, infrastructure mimicry, or account takeover. Purchased data might include employee contact lists, credentials, internal architecture details, and more.",
        "tags": ["closed-source intelligence", "dark web", "data brokerage", "cybercrime"],
        "tactic": "Reconnaissance",
        "protocol": "",
        "os": "",
        "tips": [
            "Limit data exposure to third-party aggregators.",
            "Periodically monitor data broker and dark web sources for leaks.",
            "Implement email and credential leak detection tools."
        ],
        "data_sources": "",
        "log_sources": [],
        "source_artifacts": [
            {"type": "Credentials", "location": "Dark Web Dumps", "identify": "Usernames/passwords tied to internal systems"},
            {"type": "Employee Contact Info", "location": "Data Broker Listings", "identify": "Corporate role-specific email lists or phone numbers"}
        ],
        "destination_artifacts": [
            {"type": "Infrastructure Details", "location": "Purchased Intelligence Packages", "identify": "IP ranges, DNS names, architecture references"}
        ],
        "detection_methods": [
            "Monitor for use of previously breached or leaked credentials.",
            "Leverage threat intelligence sources that monitor dark web forums.",
            "Correlate sudden use of old credentials with known leak timelines."
        ],
        "apt": [
            "DEV-0537"
        ],
        "spl_query": [
            'index=authentication_logs\n| search result="failure"\n| stats count by user, src_ip\n| where count > 5\n| lookup leaked_credentials user OUTPUT breach_date\n| where isnotnull(breach_date)'
        ],
        "hunt_steps": [
            "Scan for brute-force or spray attempts using leaked credential patterns.",
            "Validate any third-party notifications about data exposure.",
            "Use OSINT or vendor feeds to identify purchased breach bundles linked to your org."
        ],
        "expected_outcomes": [
            "Identification of adversary attempts to exploit purchased credentials or contact data.",
            "Threat intel enrichment showing your organization is being targeted using closed-source data."
        ],
        "false_positive": "High-volume credential reuse tools may trigger detection on legitimate user behavior. Validate with known breach data.",
        "clearing_steps": [
            "Force reset exposed credentials.",
            "Notify affected personnel of exposure.",
            "Engage dark web monitoring services to flag further activity."
        ],
        "clearing_playbook": [
            "https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-identity-theft"
        ],
        "mitre_mapping": [
            {"tactic": "Initial Access", "technique": "T1078", "example": "Purchased credentials are used to authenticate directly"},
            {"tactic": "Resource Development", "technique": "T1588", "example": "Infrastructure details enable development of mimicry or impersonation assets"}
        ],
        "watchlist": [
            "Old credentials being used again after breach reports",
            "External IPs conducting password sprays with breached usernames",
            "References to your company in dark web monitoring tools"
        ],
        "enhancements": [
            "Partner with breach intelligence and surface web OSINT vendors.",
            "Add honeytokens to data sources to track data leaks or sales.",
            "Establish DLP and SIEM triggers around reused breached data."
        ],
        "summary": "Adversaries may purchase sensitive information such as credentials, employee details, or infrastructure blueprints from dark web forums or commercial data providers. This intelligence fuels more targeted phishing, impersonation, or access attempts.",
        "remediation": "Reset exposed assets, monitor for targeted follow-ups, and partner with threat intel vendors to track future resale or use.",
        "improvements": "Develop red team simulations using mock data exposures to test detection. Regularly audit what information is available from third parties or OSINT brokers.",
        "mitre_version": "16.1"
    }
