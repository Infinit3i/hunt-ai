def get_content():
    return {
        "id": "T1589",
        "url_id": "T1589",
        "title": "Gather Victim Identity Information",
        "description": "Adversaries may gather information about the victim's identity that can be used during targeting. Information about identities may include a variety of details, including personal data (ex: employee names, email addresses, security question responses, etc.) as well as sensitive details such as credentials or multi-factor authentication (MFA) configurations. Adversaries may gather this information in various ways, such as direct elicitation via Phishing for Information. Information about users could also be enumerated via other active means such as probing and analyzing responses from authentication services that may reveal valid usernames in a system or permitted MFA methods associated with those usernames. Information about victims may also be exposed to adversaries via online or other accessible data sets. Gathering this information may reveal opportunities for other forms of reconnaissance, establishing operational resources, and/or initial access.",
        "tags": ["identity", "reconnaissance", "targeting", "phishing", "authentication"],
        "tactic": "Reconnaissance",
        "protocol": "HTTPS, LDAP, DNS, API",
        "os": "Any",
        "tips": [
            "Use rate-limiting and CAPTCHA mechanisms on login and signup forms",
            "Obfuscate or protect public access to staff pages and directories",
            "Monitor authentication systems for enumeration indicators"
        ],
        "data_sources": "Web Credential, Command, Network Traffic, Application Log, Cloud Service",
        "log_sources": [
            {"type": "Web Credential", "source": "", "destination": ""},
            {"type": "Command", "source": "", "destination": ""},
            {"type": "Network Traffic", "source": "", "destination": ""},
            {"type": "Application Log", "source": "", "destination": ""},
            {"type": "Cloud Service", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Clipboard Data", "location": "Memory or browser extensions", "identify": "Copied identity attributes from public sources"},
            {"type": "Event Logs", "location": "Windows Security Logs", "identify": "Unusual authentications from uncommon IPs"}
        ],
        "destination_artifacts": [
            {"type": "Network Connections", "location": "Proxy or web gateway logs", "identify": "Targeted access to staff directories or endpoints"},
            {"type": "Sysmon Logs", "location": "Event ID 1", "identify": "Execution of recon or credential enumeration tools"}
        ],
        "detection_methods": [
            "Detect excessive requests to MFA/SSPR-related URLs",
            "Alert on IPs performing multiple login attempts with different usernames",
            "Analyze web referer and user-agent strings for scripting and automation"
        ],
        "apt": ["Lazarus Group", "TA453", "Ocean Lotus", "Siamesekitten", "FIN13", "Star Blizzard"],
        "spl_query": [
            "index=web sourcetype=proxy url=*login* OR url=*autodiscover*\n| stats count by src_ip, url",
            "index=sysmon EventCode=1 OR EventCode=3 CommandLine=*username* OR CommandLine=*login*\n| stats count by CommandLine, ParentImage"
        ],
        "hunt_steps": [
            "Search for enumeration patterns across login interfaces",
            "Identify repeat failed attempts using similar usernames",
            "Correlate metadata like referer and user-agent to scraping activity"
        ],
        "expected_outcomes": [
            "Awareness of adversary reconnaissance prior to credential phishing",
            "Detection of enumeration and exposure attempts across identity vectors"
        ],
        "false_positive": "User password reset flows and IT admin scripts might mimic some of this behavior. Verify via user validation and audit logs.",
        "clearing_steps": [
            "Flush clipboard and browser autofill entries",
            "Clear temporary identity enumeration tools from disk",
            "Rotate credentials or MFA tokens exposed in public dumps"
        ],
        "clearing_playbook": ["https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-phishing"],
        "mitre_mapping": [
            {"tactic": "Resource Development", "technique": "T1586", "example": "Use gathered names and emails to build impersonation identities"},
            {"tactic": "Initial Access", "technique": "T1566", "example": "Send tailored phishing based on gathered identity details"}
        ],
        "watchlist": [
            "Access to internal staff directory endpoints from unusual IPs",
            "Use of login endpoints without full authentication attempts",
            "Patterns consistent with MFA probing"
        ],
        "enhancements": [
            "Apply deception identities to trap identity enumeration attempts",
            "Integrate honeypot login endpoints for attribution collection"
        ],
        "summary": "This technique covers the adversary's collection of user identity details including names, emails, credentials, and MFA configuration, which are foundational for phishing, impersonation, and broader targeting campaigns.",
        "remediation": "Limit identity exposure on public sites. Use detection and deception to capture adversary reconnaissance attempts.",
        "improvements": "Leverage behavior analytics to detect unusual identity queries and auto-flag accounts following enumeration-like activity.",
        "mitre_version": "16.1"
    }
