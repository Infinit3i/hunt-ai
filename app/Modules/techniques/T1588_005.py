def get_content():
    return {
        "id": "T1588.005",
        "url_id": "T1588/005",
        "title": "Obtain Capabilities: Exploits",
        "description": "Adversaries may buy, steal, or download exploits that can be used during targeting. An exploit takes advantage of a bug or vulnerability in order to cause unintended or unanticipated behavior to occur on computer hardware or software. Rather than developing their own exploits, an adversary may find/modify exploits from online or purchase them from exploit vendors. In addition to downloading free exploits from the internet, adversaries may purchase exploits from third-party entities. These include criminal marketplaces, exploit kits, individuals, or legitimate vulnerability research firms. Adversaries may also steal and repurpose exploits from third-party entities or adversaries. Monitoring exploit forums enables them to gain early access before public disclosure.",
        "tags": ["resource-development", "exploit-acquisition", "underground-market", "exploit-kit", "cve"],
        "tactic": "Resource Development",
        "protocol": "HTTPS, FTP, TOR, I2P",
        "os": "Any",
        "tips": [
            "Monitor download activity from known exploit repositories",
            "Track TOR/I2P usage in enterprise networks",
            "Use threat intelligence to profile exploit kit distribution points"
        ],
        "data_sources": "Internet Scan, Cloud Service, Malware Repository, Command, File, Web Credential, Application Log",
        "log_sources": [
            {"type": "Internet Scan", "source": "", "destination": ""},
            {"type": "Cloud Service", "source": "", "destination": ""},
            {"type": "Malware Repository", "source": "", "destination": ""},
            {"type": "Command", "source": "", "destination": ""},
            {"type": "File", "source": "", "destination": ""},
            {"type": "Web Credential", "source": "", "destination": ""},
            {"type": "Application Log", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "File Access Times (MACB Timestamps)", "location": "%TEMP%, /tmp", "identify": "Downloaded or compiled exploit code"},
            {"type": "Browser History", "location": "Forensics browser SQLite DB", "identify": "Visits to exploit database or TOR forums"}
        ],
        "destination_artifacts": [
            {"type": "Network Connections", "location": "Firewall/proxy logs", "identify": "Access to exploit markets, GitHub PoCs"},
            {"type": "Sysmon Logs", "location": "Event ID 1", "identify": "Execution of known exploit scripts (e.g. Python, Metasploit)"}
        ],
        "detection_methods": [
            "Detect access to known exploit forums, repositories, and dark web markets",
            "Monitor execution of known exploit toolkits (e.g., Cobalt Strike, Metasploit)",
            "Alert on changes to common exploit payload directories"
        ],
        "apt": ["GRU Unit 29155", "DarkHotel", "Muzabi"],
        "spl_query": [
            "index=proxy sourcetype=web url=*exploit-db.com* OR url=*0day.today* OR url=*packetstormsecurity*\n| stats count by src_ip, url",
            "index=sysmon EventCode=1 CommandLine=*exploit* OR CommandLine=*payload* OR CommandLine=*msfvenom*\n| stats count by Computer, CommandLine"
        ],
        "hunt_steps": [
            "Correlate web access logs with known exploit repository domains",
            "Identify unusual file downloads that match known payloads",
            "Track compiled artifacts containing shellcode signatures"
        ],
        "expected_outcomes": [
            "Early detection of adversaries acquiring weaponized code",
            "Ability to pivot from artifact to suspected campaign phase"
        ],
        "false_positive": "Legitimate red team or security researchers may trigger some queries. Confirm context and environment.",
        "clearing_steps": [
            "Purge exploit scripts or binaries from staging systems",
            "Scrub TOR/I2P toolkits and associated cache/residue",
            "Reset credentials if credentials were used during purchase or transfer"
        ],
        "clearing_playbook": ["https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-phishing"],
        "mitre_mapping": [
            {"tactic": "Execution", "technique": "T1203", "example": "Use exploit to trigger code execution on client software"},
            {"tactic": "Initial Access", "technique": "T1190", "example": "Deploy exploit against public-facing application"},
            {"tactic": "Privilege Escalation", "technique": "T1068", "example": "Escalate access via local vulnerability"}
        ],
        "watchlist": [
            "TOR/I2P traffic linked to exploit kit infrastructure",
            "Downloads of ZIPs or archives with exploit-style naming",
            "Repository scraping scripts run by internal assets"
        ],
        "enhancements": [
            "Use sandboxing to detonate and analyze suspicious archives",
            "Employ exploit detection YARA rules in endpoint defense",
            "Enrich logs with threat intel on exploit actors/vendors"
        ],
        "summary": "This technique tracks the acquisition of exploits by adversaries via download, purchase, or theft. These exploits may be weaponized immediately or stored for later use in campaigns involving privilege escalation, initial access, or evasion.",
        "remediation": "Block access to known exploit sites. Flag abnormal tool usage by non-security roles. Use DLP for payload types.",
        "improvements": "Implement behavioral detection for exploit prep tools. Add exploit PoC signatures to EDR baselines.",
        "mitre_version": "16.1"
    }
