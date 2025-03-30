def get_content():
    return {
        "id": "T1505.003",
        "url_id": "T1505/003",
        "title": "Server Software Component: Web Shell",
        "description": "Adversaries may deploy web shells to backdoor web servers and maintain persistent access. A web shell is a malicious script hosted on an accessible web server that allows remote execution of commands, potentially leading to full system compromise. These shells can be simple one-liners (e.g., PHP eval) or more complex interactive interfaces such as China Chopper. Web shells may not initiate outbound connections, making detection more challenging.",
        "tags": ["webshell", "php", "persistence", "ChinaChopper", "T1505.003"],
        "tactic": "Persistence",
        "protocol": "HTTP/HTTPS",
        "os": "Linux, Windows, macOS, Network",
        "tips": [
            "Regularly audit web directories for unexpected scripts or modified files.",
            "Monitor web server logs for abnormal patterns such as POST requests to static pages.",
            "Implement web application firewalls (WAFs) with custom rules to detect eval/exec patterns.",
            "Limit write permissions for web directories to only necessary services or accounts."
        ],
        "data_sources": "Application Log, File, Network Traffic, Process",
        "log_sources": [
            {"type": "Application Log", "source": "Application Log Content", "destination": ""},
            {"type": "File", "source": "File Creation", "destination": ""},
            {"type": "File", "source": "File Modification", "destination": ""},
            {"type": "Network Traffic", "source": "Network Traffic Content", "destination": "Network Traffic Flow"},
            {"type": "Process", "source": "Process Creation", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Web File", "location": "/var/www/html/", "identify": "Unexpected PHP, ASPX, JSP files"},
            {"type": "Web Server Logs", "location": "/var/log/nginx/access.log", "identify": "Frequent POST to static-looking files"},
            {"type": "Process", "location": "", "identify": "Web server processes spawning cmd.exe, powershell.exe, or bash"}
        ],
        "destination_artifacts": [
            {"type": "File", "location": "/tmp, /var/tmp, or C:\\Temp", "identify": "Artifacts dropped by web shell"},
            {"type": "Network", "location": "External connections", "identify": "Outbound exfiltration from shell"},
            {"type": "Log", "location": "SIEM or WAF logs", "identify": "Detection of eval, exec or obfuscated web content"}
        ],
        "detection_methods": [
            "Monitor for web server processes creating child shell processes (cmd, bash).",
            "Detect usage of suspicious eval or exec functions in web scripts.",
            "Use file integrity monitoring (FIM) on web directories.",
            "Inspect inbound POST requests to pages not designed to receive input."
        ],
        "apt": ["APT34", "APT39", "APT40", "Deep Panda", "Iranian Threat Actors", "Emissary Panda", "OceanLotus", "Kimsuky", "Moses Staff"],
        "spl_query": [
            'index=web_logs sourcetype=apache:access\n| search method=POST status=200\n| stats count by uri, client_ip\n| where count > 20',
            'index=os_logs sourcetype=sysmon\n| search ParentImage="*httpd*" OR "*nginx*" AND (Image="*cmd.exe" OR "*bash")\n| stats count by host, Image, ParentImage',
            'index=file_monitor sourcetype=ossec\n| search file_path="*/var/www/*" AND action=modified\n| stats count by file_path'
        ],
        "hunt_steps": [
            "Scan for known web shell signatures using tools like YARA.",
            "Check for recent file modifications in web directories.",
            "Correlate POST requests to modified files.",
            "Look for web server processes spawning shells."
        ],
        "expected_outcomes": [
            "Detection of backdoor scripts embedded in legitimate-looking web files.",
            "Identification of remote command execution over HTTP(S).",
            "Reduction in persistence options for adversaries.",
            "Prevention of lateral movement via web server compromise."
        ],
        "false_positive": "Legitimate administration scripts or development environments may mimic some web shell behaviors. Confirm functionality and file origin before flagging.",
        "clearing_steps": [
            "Remove web shell files from server.",
            "Restore web directory from clean backup.",
            "Audit user access and reset compromised credentials.",
            "Patch exploited vulnerabilities and harden server configuration."
        ],
        "clearing_playbook": ["https://www.cisa.gov/news-events/alerts/2020/04/22/malicious-web-shells"],
        "mitre_mapping": [
            {"tactic": "Persistence", "technique": "T1505", "example": "Deploying PHP web shell on a vulnerable server"},
            {"tactic": "Command and Control", "technique": "T1059", "example": "Remote shell access via POST to web interface"},
            {"tactic": "Execution", "technique": "T1059.003", "example": "cmd.exe triggered via ASP web shell"}
        ],
        "watchlist": [
            "POST requests to static extensions like .jpg or .html",
            "Web directories with unexpected writable permissions",
            "Shell process spawned by web services",
            "Frequent access from single IP to one script"
        ],
        "enhancements": [
            "Deploy WAFs with anomaly-based rules",
            "Use immutable infrastructure or containerization for web apps",
            "Enable FIM and SIEM integrations",
            "Whitelist approved web scripts using AppLocker or equivalent"
        ],
        "summary": "Web shells provide adversaries with direct backdoor access to servers over web protocols. By embedding minimalistic but powerful scripts in web content, attackers can execute commands, upload tools, and maintain access without raising alerts from outbound connection monitoring tools.",
        "remediation": "Remove web shell artifacts, audit affected infrastructure for further compromise, and patch any exploited vulnerabilities. Harden web application code, enforce least privilege, and monitor all web-facing assets.",
        "improvements": "Establish baselines for web directory contents and traffic patterns. Conduct regular red teaming to validate WAF and detection rule coverage.",
        "mitre_version": "16.1"
    }
