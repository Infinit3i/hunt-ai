def get_content():
    return {
        "id": "T1056.003",
        "url_id": "T1056.003",
        "title": "Input Capture: Web Portal Capture",
        "description": "Adversaries may install code on externally facing portals, such as a VPN login page, to capture and transmit credentials of users who attempt to log into the service. For example, a compromised login page may log provided user credentials before logging the user in to the service. This variation on input capture may be conducted post-compromise using legitimate administrative access as a backup measure to maintain network access through External Remote Services and Valid Accounts, or as part of the initial compromise by exploitation of the externally facing web service.",
        "tags": ["Collection", "Credential Access"],
        "tactic": "Collection",
        "protocol": "",
        "os": "Linux, Windows, macOS",
        "tips": [
            "Monitor for changes to files in the web directory for login pages.",
            "Check for unauthorized updates to web server content, particularly login pages."
        ],
        "data_sources": "File: File Modification",
        "log_sources": [
            {"type": "File", "source": "File Modification", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Injected Code", "location": "Externally facing login portals", "identify": "Compromised login page"}
        ],
        "destination_artifacts": [
            {"type": "Captured Credentials", "location": "Captured user input", "identify": "User login credentials"}
        ],
        "detection_methods": [
            "Monitor web server logs for suspicious access patterns to login pages.",
            "Use file integrity monitoring to detect unauthorized changes to web server content, especially login forms."
        ],
        "apt": ["CrowdStrike IceApple May 2022", "Volexity Ivanti Zero-Day Exploitation January 2024"],
        "spl_query": [
            "| index=web_logs sourcetype=access | search '/login' AND 'POST' AND 'username'"
        ],
        "hunt_steps": [
            "Identify any unusual activity on externally facing login portals.",
            "Look for unauthorized changes to login pages or unusual access to files in web directories."
        ],
        "expected_outcomes": [
            "Detection of altered login portals designed to capture user credentials."
        ],
        "false_positive": "False positives may occur from legitimate updates or changes to the login portal. Ensure the changes are authorized and typical.",
        "clearing_steps": [
            "Remove any malicious code injected into the login portal.",
            "Restore the compromised web portal to a secure, unaltered version."
        ],
        "mitre_mapping": [
            {"tactic": "Collection", "technique": "T1056.003", "example": "Compromised login portal captures credentials."}
        ],
        "watchlist": [
            "Monitor for external login attempts that may be associated with phishing or exploitation.",
            "Watch for unusual traffic patterns directed to login pages."
        ],
        "enhancements": [
            "Implement web application firewalls (WAF) to detect and block malicious activity on login pages."
        ],
        "summary": "Web Portal Capture involves adversaries modifying externally facing login portals to capture user credentials. This technique is often part of post-compromise activity or the initial exploitation of a vulnerable web service.",
        "remediation": "Restore the web portal to its secure version and remove any malicious code injected for credential capture.",
        "improvements": "Increase monitoring of web traffic to detect suspicious login page activity, and strengthen web application security.",
        "mitre_version": "1.0"
    }
