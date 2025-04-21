def get_content():
    return {
        "id": "T1589.001",
        "url_id": "T1589/001",
        "title": "Gather Victim Identity Information: Credentials",
        "description": "Adversaries may gather credentials that can be used during targeting. Account credentials gathered by adversaries may be those directly associated with the target victim organization or attempt to take advantage of the tendency for users to use the same passwords across personal and business accounts. Adversaries may gather credentials from potential victims in various ways, such as direct elicitation via Phishing for Information. Adversaries may also compromise sites then add malicious content designed to collect website authentication cookies from visitors. Where multi-factor authentication (MFA) based on out-of-band communications is in use, adversaries may compromise a service provider to gain access to MFA codes and one-time passwords (OTP). Credential information may also be exposed to adversaries via leaks to online or other accessible data sets. Adversaries may purchase credentials from dark web markets or through access to Telegram channels that distribute logs from infostealer malware. Gathering this information may reveal opportunities for other forms of reconnaissance, establishing operational resources, and/or initial access.",
        "tags": ["reconnaissance", "credentials", "infostealer", "initial-access"],
        "tactic": "Reconnaissance",
        "protocol": "HTTPS, API, Telegram, Dark Web",
        "os": "Any",
        "tips": [
            "Monitor paste sites and dark web for leaked credentials",
            "Harden credential management practices across developer platforms",
            "Use honeytokens and credential canaries in repositories"
        ],
        "data_sources": "Web Credential, Command, Application Log, Cloud Storage, Internet Scan",
        "log_sources": [
            {"type": "Web Credential", "source": "", "destination": ""},
            {"type": "Command", "source": "", "destination": ""},
            {"type": "Application Log", "source": "", "destination": ""},
            {"type": "Cloud Storage", "source": "", "destination": ""},
            {"type": "Internet Scan", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Memory Dumps", "location": "C:\\Users\\<user>\\AppData\\Local\\Temp", "identify": "Stored credentials or token memory artifacts"},
            {"type": "Clipboard Data", "location": "RAM", "identify": "Sensitive copied credentials"}
        ],
        "destination_artifacts": [
            {"type": "Sysmon Logs", "location": "Event ID 1, 3", "identify": "Credential dump tool execution or upload"},
            {"type": "Windows Defender Logs", "location": "Threat Detected", "identify": "Credential harvester or token stealer signatures"}
        ],
        "detection_methods": [
            "Detect suspicious access to secrets in version control or cloud buckets",
            "Alert on credential input harvesting in browser extensions or JS scripts",
            "Monitor Telegram channels or threat intel feeds for stealer logs"
        ],
        "apt": ["APT40", "LAPSUS$", "StellarParticle", "Chimera", "ITG18"],
        "spl_query": [
            "index=defender sourcetype=alerts threat_name=*credential* OR threat_name=*stealer*\n| stats count by Computer, FileName",
            "index=sysmon EventCode=1 OR EventCode=3 CommandLine=*trufflehog* OR CommandLine=*gitrob*\n| stats count by CommandLine, Image"
        ],
        "hunt_steps": [
            "Identify presence of known credential scraping tools",
            "Search GitHub, GitLab, or cloud buckets for exposed secrets",
            "Review proxy logs for traffic to dark web paste sites"
        ],
        "expected_outcomes": [
            "Discovery of exposed or harvested credentials in repositories or memory",
            "Detection of infostealer activity or outbound token exfiltration"
        ],
        "false_positive": "Developers using tools to validate credentials or internal red team exercises—correlate with internal tool inventory.",
        "clearing_steps": [
            "Purge compromised credentials and rotate them in affected services",
            "Reimage or clean endpoints infected with info-stealers",
            "Clear temporary files and credential-storing memory"
        ],
        "clearing_playbook": ["https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-phishing"],
        "mitre_mapping": [
            {"tactic": "Initial Access", "technique": "T1078", "example": "Use valid credentials found in infostealer logs"},
            {"tactic": "Resource Development", "technique": "T1586", "example": "Compromise and use leaked credentials to seed new infrastructure"}
        ],
        "watchlist": [
            "Use of trufflehog, gitrob, or credential dumpers",
            "Token or credential artifacts on public GitHub",
            "Traffic to domains known to sell or dump logs"
        ],
        "enhancements": [
            "Enable developer commit hooks to scan for secrets",
            "Monitor dark web forums and Telegram groups for credential posts"
        ],
        "summary": "This technique encompasses how adversaries collect usernames, passwords, cookies, or authentication tokens through phishing, credential harvesting, malware, breach leaks, or direct extraction. These credentials are then used to facilitate account compromise, impersonation, or lateral movement.",
        "remediation": "Apply password managers, enforce MFA, and rotate secrets across all environments regularly. Audit exposed repositories and reset credentials immediately.",
        "improvements": "Automate secret scanning in CI/CD pipelines, and feed threat intel from stealer malware back into your credential detection pipeline.",
        "mitre_version": "16.1"
    }
