def get_content():
    return {
        "id": "T1189",
        "url_id": "T1189",
        "title": "Drive-by Compromise",
        "description": "Adversaries may gain access to a system through a user visiting a website over the normal course of browsing. With this technique, the user's web browser is typically targeted for exploitation.",
        "tags": [],
        "tactic": "Initial Access",
        "protocol": "HTTP/HTTPS",
        "os": "Windows, Linux, macOS",
        "tips": [
            "Enable browser exploit protection features.",
            "Restrict scripting languages and plug-ins where possible.",
            "Use DNS filtering or proxies to block known malicious domains."
        ],
        "data_sources": "Application Log, File, Network Traffic, Process",
        "log_sources": [
            {"type": "Web Proxy Logs", "source": "URL Filtering, Suspicious Domains Accessed"},
            {"type": "Network Traffic Analysis", "source": "Malicious Payload Delivery, Command and Control (C2) Communications"},
            {"type": "Endpoint Monitoring", "source": "Execution of Unexpected Binaries from Internet Cache"},
            {"type": "Browser Logs", "source": "Exploit Execution, Unauthorized Downloads"}
        ],
        "detection_methods": [
            "Monitor for visits to known malicious domains or sites hosting exploit kits.",
            "Detect unexpected file downloads from web browsers, especially executables.",
            "Analyze network traffic for indicators of exploit delivery frameworks.",
            "Monitor process execution triggered by browser activity, especially scripting engines."
        ],
        "apt": ["Fancy Bear", "Equation Group", "APT32"],
        "spl_query": [
            "index=proxy_logs sourcetype=squid Accessed_URL=*exploit* OR Accessed_URL=*driveby*",
            "index=network sourcetype=firewall Blocked_URL=*driveby*"
        ],
        "hunt_steps": [
            "Identify users who have visited high-risk domains known for exploit delivery.",
            "Analyze web proxy logs for drive-by download patterns.",
            "Monitor browser activity logs for unauthorized script execution.",
            "Check endpoint telemetry for unexpected binary execution originating from browser cache.",
            "Correlate findings with known threat intelligence sources."
        ],
        "expected_outcomes": [
            "Drive-by Compromise Detected: Implement security measures to mitigate future exploitation.",
            "No Malicious Activity Found: Continue monitoring and improve detection signatures."
        ],
        "false_positive": "Legitimate downloads from trusted websites may trigger alerts. Whitelist known good sources.",
        "clearing_steps": [
            "Remove unauthorized downloaded files and executables.",
            "Patch vulnerable browsers and plugins to prevent exploit execution.",
            "Implement browser security controls to restrict unauthorized script execution.",
            "Block access to high-risk domains at the network level."
        ],
        "mitre_mapping": [
            {"tactic": "Execution", "technique": "T1204.002 (User Execution - Malicious File)", "example": "User executes malicious payload delivered via drive-by download."},
            {"tactic": "Defense Evasion", "technique": "T1070.004 (Indicator Removal on Host)", "example": "Attackers delete evidence of the compromised browser process."},
            {"tactic": "Command and Control", "technique": "T1071.001 (Application Layer Protocol - Web Protocols)", "example": "Malware communicates with attacker-controlled C2 server over HTTP/HTTPS."}
        ],
        "watchlist": [
            "Monitor for connections to domains hosting known exploit kits.",
            "Alert on unexpected execution of binaries originating from browser cache.",
            "Detect unauthorized browser extensions or plugins executing scripts."
        ],
        "enhancements": [
            "Enforce browser security policies to restrict unauthorized script execution.",
            "Utilize endpoint protection solutions to block malicious file downloads.",
            "Regularly update and patch browsers and plugins to mitigate known vulnerabilities."
        ],
        "summary": "Drive-by compromise is an initial access technique where adversaries exploit browser vulnerabilities or deliver malicious payloads through compromised websites.",
        "remediation": "Educate users on phishing awareness, implement web filtering, and enforce strict browser security settings.",
        "improvements": "Enhance SIEM alerts for suspicious web activity and integrate web threat intelligence feeds."
    }
