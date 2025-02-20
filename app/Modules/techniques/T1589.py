def get_content():
    """
    Returns structured content for the Gather Victim Identity Information (T1589) technique.
    """
    return {
        "id": "T1589",
        "url_id": "T1589",
        "title": "Gather Victim Identity Information",
        "tactic": "Reconnaissance",
        "data_sources": "Network Traffic, Web Logs, OSINT Sources",
        "protocol": "HTTP, Social Media APIs, DNS",
        "os": "Platform Agnostic",
        "objective": "Adversaries gather victim identity information, such as user accounts, email addresses, and personal details, for further exploitation.",
        "scope": "Monitor and analyze identity-related data collection activities.",
        "threat_model": "Attackers gather user credentials, employee directories, or leaked personal information to craft social engineering attacks or gain unauthorized access.",
        "hypothesis": [
            "Are adversaries collecting employee emails for phishing campaigns?",
            "Is there an unusual pattern of identity-related queries in web traffic logs?",
            "Are adversaries using OSINT techniques to gather personal information?"
        ],
        "tips": [
            "Monitor for large-scale data scraping activities on public-facing resources.",
            "Track access to corporate directories and HR portals.",
            "Analyze web server logs for enumeration patterns."
        ],
        "log_sources": [
            {"type": "Web Logs", "source": "Access Logs", "destination": "SIEM"},
            {"type": "Network Traffic", "source": "Proxy Logs", "destination": "SIEM"},
            {"type": "OSINT", "source": "Public Databases", "destination": "Threat Intelligence Platforms"}
        ],
        "source_artifacts": [
            {"type": "Email Harvesting", "location": "Corporate Email Directories", "identify": "Leaked Employee Emails"},
            {"type": "Social Media Scraping", "location": "Public Profiles", "identify": "Employee Personal Information"}
        ],
        "destination_artifacts": [
            {"type": "Compromised Credentials", "location": "Dark Web Forums", "identify": "Leaked User Accounts"}
        ],
        "detection_methods": [
            "Monitor network traffic for suspicious reconnaissance activity.",
            "Analyze large-scale data scraping patterns.",
            "Track access attempts to HR and employee-related databases."
        ],
        "apt": ["G0019", "G0022"],
        "spl_query": [
            "index=web_logs URI=*login* OR URI=*userlist* | stats count by src_ip, user_agent",
            "index=network_traffic dest_port=80 OR dest_port=443 | search user_agent=*scraper*"
        ],
        "hunt_steps": [
            "Investigate suspicious spikes in login page access.",
            "Correlate web scraping activity with threat intelligence sources.",
            "Review network logs for repeated enumeration queries."
        ],
        "expected_outcomes": [
            "Potential reconnaissance activity identified and mitigated.",
            "No malicious activity found, improving baseline detection."
        ],
        "false_positive": "Automated web crawlers and legitimate research activities may exhibit similar patterns.",
        "clearing_steps": [
            "Block IPs associated with reconnaissance activity.",
            "Update access controls on corporate directories and sensitive portals."
        ],
        "mitre_mapping": [
            {"tactic": "Reconnaissance", "technique": "T1591 (Gather Victim Org Information)", "example": "Adversaries research target organizations before launching attacks."}
        ],
        "watchlist": [
            "Monitor access to corporate directories and HR systems.",
            "Detect patterns of email or user enumeration."
        ],
        "enhancements": [
            "Implement rate limiting on web portals to prevent automated scraping.",
            "Strengthen API security and access control mechanisms."
        ],
        "summary": "Attackers gather victim identity information to craft targeted attacks or gain unauthorized access.",
        "remediation": "Block unauthorized access to sensitive user information and enhance monitoring of OSINT data collection.",
        "improvements": "Enhance logging capabilities and deploy behavioral analytics to detect reconnaissance activities."
    }
