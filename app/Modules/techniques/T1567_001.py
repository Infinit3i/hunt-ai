def get_content():
    return {
        "id": "T1567.001",
        "url_id": "T1567.001",
        "title": "Exfiltration Over Web Service: Exfiltration to Code Repository",
        "description": "Adversaries may exfiltrate data to publicly accessible or private code repositories (such as GitHub, GitLab, Bitbucket) using APIs or other repository upload methods. These platforms often support encrypted HTTPS-based data transfers, giving adversaries an additional layer of obfuscation. If these services are already in use in the environment, the activity may blend in with legitimate developer workflows.\n\nExfiltration may occur via automated scripts using access tokens, `git push` commands, or APIs such as `https://api.github.com`. These uploads can include sensitive files, credentials, source code, or exfiltrated surveillance data staged earlier in the attack lifecycle.",
        "tags": ["code exfiltration", "git", "github", "gitlab", "api exfiltration", "T1567"],
        "tactic": "Exfiltration",
        "protocol": "HTTPS",
        "os": "Linux, Windows, macOS",
        "tips": [
            "Monitor for abnormal usage of `git` or other version control commands on non-developer endpoints.",
            "Inspect traffic to code repository APIs for suspicious payload sizes or frequency.",
            "Detect unexpected token usage in shell histories or access logs."
        ],
        "data_sources": "Command: Command Execution, File: File Access, Network Traffic: Network Traffic Content, Network Traffic: Network Traffic Flow",
        "log_sources": [
            {"type": "Network Traffic", "source": "Proxy, Firewall, CASB, DPI solutions"},
            {"type": "Endpoint Telemetry", "source": "Sysmon, Auditd, EDR solutions"},
            {"type": "Version Control Logs", "source": "GitHub Enterprise, GitLab Logs, Bitbucket Audits"}
        ],
        "source_artifacts": [
            {"type": "Sensitive Data", "location": "Endpoint file system or dumped credentials", "identify": "Filetypes like .txt, .csv, .docx, .db, .key"}
        ],
        "destination_artifacts": [
            {"type": "Git Commits", "location": "Remote repo on GitHub or similar", "identify": "Unexpected commit hashes or repositories"}
        ],
        "detection_methods": [
            "Identify large outbound HTTPS transfers to known code repository APIs.",
            "Monitor use of `git push` from machines or user accounts not typically associated with code development.",
            "Correlate access token usage with unusual activity timestamps or IP geolocations."
        ],
        "apt": [],
        "spl_query": [
            "index=network sourcetype=proxy OR sourcetype=firewall_logs \n| search uri_domain IN (github.com, gitlab.com, bitbucket.org, api.github.com) AND http_method=POST \n| stats count by src_ip, uri_domain, http_method"
        ],
        "hunt_steps": [
            "Run SIEM queries targeting suspicious uploads to Git-based domains.",
            "Review endpoints for unauthorized `git` configuration or access token files.",
            "Correlate upload activity with recent sensitive file access or archive creation.",
            "Check commit metadata for non-standard authors or timestamps."
        ],
        "expected_outcomes": [
            "Code Repository Exfiltration Detected: Block repository access, revoke tokens, isolate host, and triage data loss.",
            "No Malicious Activity Found: Update detection logic to better distinguish developer vs. suspicious code repo use."
        ],
        "false_positive": "Legitimate developer activity in CI/CD workflows may resemble exfiltration. Confirm the user's role, context, and repository ownership before escalation.",
        "clearing_steps": [
            "Revoke exposed credentials or API tokens.",
            "Notify affected code repository maintainers and request removal of sensitive content.",
            "Conduct forensic review of the upload system and command history."
        ],
        "mitre_mapping": [
            {"tactic": "Exfiltration", "technique": "T1567.001 (Exfiltration to Code Repository)", "example": "Sensitive documents uploaded to a GitHub repository using a stolen token."}
        ],
        "watchlist": [
            "Flag outbound API POSTs to code repo domains from non-developer endpoints.",
            "Monitor excessive use of `git push` with large payloads.",
            "Alert on token authentication from new geographic locations or unknown user agents."
        ],
        "enhancements": [
            "Apply DLP to detect sensitive strings in API or git traffic.",
            "Restrict token-based access to code repos via user group policies.",
            "Deploy script detection on endpoints to catch automated exfil attempts."
        ],
        "summary": "This technique describes adversaries using code repositories such as GitHub or GitLab to exfiltrate stolen data. The encrypted and popular nature of these services makes them useful for stealthy data theft. Monitoring for unusual access patterns is critical.",
        "remediation": "Block access to unauthorized repositories, revoke access tokens, and initiate full data loss investigation.",
        "improvements": "Enhance visibility into repository uploads, restrict repository access based on job roles, and use behavioral analytics to flag misuse.",
        "mitre_version": "16.1"
    }
