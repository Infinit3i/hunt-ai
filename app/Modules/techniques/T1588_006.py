def get_content():
    return {
        "id": "T1588.006",
        "url_id": "T1588/006",
        "title": "Obtain Capabilities: Vulnerabilities",
        "description": "Adversaries may acquire information about vulnerabilities that can be used during targeting. A vulnerability is a weakness in computer hardware or software that can, potentially, be exploited by an adversary to cause unintended or unanticipated behavior to occur. Adversaries may find vulnerability information by searching open databases or gaining access to closed vulnerability databases. An adversary may monitor vulnerability disclosures/databases to understand the state of existing, as well as newly discovered, vulnerabilities. There is usually a delay between when a vulnerability is discovered and when it is made public. An adversary may target the systems of those known to conduct vulnerability research (including commercial vendors). Knowledge of a vulnerability may cause an adversary to search for an existing exploit or to attempt to develop one themselves.",
        "tags": ["resource-development", "vulnerability-research", "exploit-dev", "cve"],
        "tactic": "Resource Development",
        "protocol": "HTTPS, API, DNS",
        "os": "Any",
        "tips": [
            "Monitor outbound traffic to known CVE databases and forums",
            "Implement decoy CVEs and monitor access for adversary enumeration",
            "Use honeypots to detect early probing of newly disclosed vulnerabilities"
        ],
        "data_sources": "Internet Scan, Application Log, Cloud Service, Web Credential, Command",
        "log_sources": [
            {"type": "Internet Scan", "source": "", "destination": ""},
            {"type": "Application Log", "source": "", "destination": ""},
            {"type": "Cloud Service", "source": "", "destination": ""},
            {"type": "Web Credential", "source": "", "destination": ""},
            {"type": "Command", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "File Access Times (MACB Timestamps)", "location": "/tmp/, %temp%", "identify": "Downloaded vulnerability databases or proof-of-concept scripts"},
            {"type": "Browser History", "location": "SQLite Web History", "identify": "Access to NVD, ExploitDB, GitHub PoC repositories"}
        ],
        "destination_artifacts": [
            {"type": "Network Connections", "location": "Firewall, proxy", "identify": "Connections to vulnerability intel or underground markets"},
            {"type": "Sysmon Logs", "location": "Event ID 1", "identify": "Scripts accessing CVE APIs or scraping vulnerability dumps"}
        ],
        "detection_methods": [
            "Alert on programmatic downloads from known CVE or exploit repositories",
            "Detect signs of local storage or parsing of vulnerability feeds",
            "Monitor researcher-like behavior from non-research user accounts"
        ],
        "apt": ["GRU Unit 74455", "APT41"],
        "spl_query": [
            "index=proxy sourcetype=web url=*exploit-db.com* OR url=*cvedetails.com* OR url=*nvd.nist.gov*\n| stats count by src_ip, url",
            "index=sysmon EventCode=1 CommandLine=*exploit* OR CommandLine=*cve* OR CommandLine=*nmap* AND (CommandLine=*script* OR CommandLine=*search*)\n| stats count by Computer, CommandLine"
        ],
        "hunt_steps": [
            "Trace script-based access to CVE databases and repositories",
            "Correlate with any abnormal scan or port sweep activity",
            "Identify user agents accessing underground vulnerability markets"
        ],
        "expected_outcomes": [
            "Awareness of adversary reconnaissance on vulnerabilities prior to exploitation",
            "Indicators of adversarial intent to build or acquire exploit capabilities"
        ],
        "false_positive": "Security researchers or automated scanners may resemble this behavior. Validate user behavior and environment type.",
        "clearing_steps": [
            "Remove downloaded PoCs or vulnerability databases",
            "Clear browsing and application logs linked to exploit enumeration",
            "Revoke access to underground market accounts or forums"
        ],
        "clearing_playbook": ["https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-phishing"],
        "mitre_mapping": [
            {"tactic": "Execution", "technique": "T1203", "example": "Use PoC code to exploit client-side application"},
            {"tactic": "Initial Access", "technique": "T1190", "example": "Exploit public-facing service with acquired CVE"}
        ],
        "watchlist": [
            "Repeated access to CVE sites from non-research workstations",
            "Download of vulnerability packs or scripts with exploit keywords",
            "Underground forum traffic over encrypted or hidden channels"
        ],
        "enhancements": [
            "Enrich detection rules with CVE references and exploit classification",
            "Leverage deception CVEs to identify threat actors pre-exploitation"
        ],
        "summary": "This technique reflects adversary acquisition or monitoring of vulnerability information from public and private sources. It serves as a precursor to exploit development or infrastructure compromise using recently exposed weaknesses.",
        "remediation": "Patch systems quickly upon CVE disclosure. Preemptively monitor exploit traffic after public disclosure. Track systems known to leak vulnerability data.",
        "improvements": "Incorporate vulnerability prioritization and exploitability ranking into detection alerts. Feed external CVE telemetry into threat hunting pipelines.",
        "mitre_version": "16.1"
    }
