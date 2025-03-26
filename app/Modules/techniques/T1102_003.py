def get_content():
    return {
        "id": "T1102.003",
        "url_id": "T1102/003",
        "title": "Web Service: One-Way Communication",
        "description": "Adversaries may use an existing, legitimate external Web service as a means for sending commands to a compromised system without receiving return output over the Web service channel.",
        "tags": ["command and control", "one-way c2", "web service", "covert channel", "encryption", "social media abuse"],
        "tactic": "command-and-control",
        "protocol": "HTTPS",
        "os": "Linux, Windows, macOS",
        "tips": [
            "Enable deep packet inspection (DPI) on outbound traffic to detect uncommon payload patterns",
            "Track and alert on abnormal use of social media or unusual domains",
            "Use behavioral analytics to detect systems pulling data from suspicious URLs"
        ],
        "data_sources": "Network Traffic",
        "log_sources": [
            {"type": "Network Traffic", "source": "endpoint", "destination": "external web service"},
            {"type": "Network Traffic", "source": "proxy", "destination": ""},
            {"type": "Network Traffic", "source": "firewall", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "DNS Cache", "location": "C:\\Windows\\System32\\ipconfig /displaydns", "identify": "Lookups to social media or uncommon domains"},
            {"type": "Process List", "location": "Running processes using netstat or tasklist", "identify": "Processes with network activity to known services"},
            {"type": "Windows Defender Logs", "location": "C:\\ProgramData\\Microsoft\\Windows Defender\\Scans\\History\\", "identify": "Possible detection of web beaconing malware"}
        ],
        "destination_artifacts": [
            {"type": "Network Connections", "location": "Proxy logs or EDR telemetry", "identify": "Outbound POST requests to web services"},
            {"type": "Windows Error Reporting (WER)", "location": "C:\\ProgramData\\Microsoft\\Windows\\WER\\", "identify": "App crashes potentially caused by injected commands"},
            {"type": "Browser History", "location": "C:\\Users\\<user>\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History", "identify": "Access to hidden URLs on social media or pastebins"}
        ],
        "detection_methods": [
            "Monitor outbound connections to popular web services for encoded or suspicious payloads",
            "Flag use of social media APIs from internal endpoints not authorized to do so",
            "Detect repeatable access patterns to static web content"
        ],
        "apt": [
            "The Dukes", "APT29", "EvilNum", "Gamaredon", "Metamorfo", "Periscope"
        ],
        "spl_query": [
            'index=proxy OR index=network \n| search uri_path="/api" OR uri_path="/paste" OR uri_path="/data" \n| stats count by src_ip, uri_domain, uri_path, user',
            'index=network sourcetype="stream:http" method=POST \n| where uri_domain IN ("twitter.com","pastebin.com","github.com") \n| stats count by uri_path, src_ip'
        ],
        "hunt_steps": [
            "Identify systems connecting to web services without receiving responses",
            "Correlate network indicators with known C2 URLs used by malware families",
            "Use threat intel to enrich beaconing behavior to web services"
        ],
        "expected_outcomes": [
            "Detection of outbound command polling to external web services",
            "Uncovered compromised hosts using one-way communication channels",
            "Reduced dwell time by identifying stealth C2 operations"
        ],
        "false_positive": "Legitimate applications that check for updates or pull content from public web services (e.g., GitHub, Twitter) may exhibit similar patterns. Validate domain reputation and usage context.",
        "clearing_steps": [
            "Block communication to the identified malicious web services via firewall or proxy",
            "Terminate compromised processes and isolate affected systems",
            "Re-image system if persistence is detected or unknown binaries are found"
        ],
        "mitre_mapping": [
            {"tactic": "defense-evasion", "technique": "T1140", "example": "Decrypting payload retrieved from social media"},
            {"tactic": "persistence", "technique": "T1053.005", "example": "Scheduled polling via task or cron to web service"},
            {"tactic": "collection", "technique": "T1119", "example": "Screen capture or clipboard monitoring sent via one-way post"}
        ],
        "watchlist": [
            "Outbound HTTPS POSTs to GitHub, Pastebin, Twitter APIs",
            "Abnormal access to pastebins or direct raw content links",
            "Frequent polling intervals in outbound connections"
        ],
        "enhancements": [
            "Enable TLS decryption with user consent in secure corporate environments",
            "Use proxy-layer analytics to detect encoded or compressed payloads",
            "Deploy deception URLs and monitor access attempts"
        ],
        "summary": "This technique uses legitimate web services such as GitHub or Twitter to push C2 commands to compromised hosts without returning output, making it stealthy and difficult to detect through traditional signature-based methods.",
        "remediation": "Block known malicious URLs, implement SSL inspection where feasible, and limit access to social media and paste services from corporate endpoints.",
        "improvements": "Correlate with threat intel feeds in real time. Monitor API access tokens and app registrations tied to social platforms.",
        "mitre_version": "16.1"
    }
