def get_content():
    return {
        "id": "T1590",
        "url_id": "T1590",
        "title": "Gather Victim Network Information",
        "description": "Adversaries may gather information about the victim's networks that can be used during targeting. Information about networks may include a variety of details, including administrative data (ex: IP ranges, domain names, etc.) as well as specifics regarding its topology and operations. Adversaries may gather this information in various ways, such as direct collection actions via Active Scanning or Phishing for Information. Information about networks may also be exposed to adversaries via online or other accessible data sets. Gathering this information may reveal opportunities for other forms of reconnaissance, establishing operational resources, and/or initial access.",
        "tags": ["reconnaissance", "network-info", "targeting"],
        "tactic": "Reconnaissance",
        "protocol": "TCP/IP, DNS, WHOIS",
        "os": "Windows, Linux, macOS",
        "tips": [
            "Correlate scanning activity with external threat intelligence sources",
            "Enforce logging and alerting on domain and WHOIS queries",
            "Utilize deception environments to detect enumeration attempts"
        ],
        "data_sources": "Network Traffic, Domain Name, Internet Scan, DNS, Command",
        "log_sources": [
            {"type": "Network Traffic", "source": "", "destination": ""},
            {"type": "Domain Name", "source": "", "destination": ""},
            {"type": "Internet Scan", "source": "", "destination": ""},
            {"type": "DNS", "source": "", "destination": ""},
            {"type": "Command", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "DNS Cache", "location": "/etc/resolv.conf", "identify": "Cached lookups for victim domain"},
            {"type": "Command History", "location": "~/.zsh_history", "identify": "Usage of reconnaissance tools like whois, dig, etc."}
        ],
        "destination_artifacts": [
            {"type": "Network Connections", "location": "Firewall Logs", "identify": "External enumeration or scanning"},
            {"type": "Sysmon Logs", "location": "Event ID 1, 3", "identify": "Execution and connection attempts of recon tools"}
        ],
        "detection_methods": [
            "Monitor for unusual scanning or enumeration traffic",
            "Alert on domain registration lookups from endpoints",
            "Detect passive DNS scraping via DNS log aggregation"
        ],
        "apt": ["UNC2165", "APT40", "APT27"],
        "spl_query": [
            "index=sysmon EventCode=1 Image=*whois* OR *nmap* OR *dig*\n| stats count by Image, CommandLine, Hostname",
            "index=network sourcetype=firewall action=allowed dest_port=53 OR dest_port=80\n| stats count by src_ip, dest_ip"
        ],
        "hunt_steps": [
            "Identify unusual spikes in DNS, whois, or scanning activity",
            "Correlate recon-related tool usage with source systems",
            "Compare destination IPs against threat intelligence blocklists"
        ],
        "expected_outcomes": [
            "Detection of early-stage reconnaissance for infrastructure mapping",
            "Insight into adversary interest in target domains and services"
        ],
        "false_positive": "Vulnerability scans by internal teams or routine asset discovery scripts—check against approved tool inventories.",
        "clearing_steps": [
            "Delete scan output files and logs from recon tools",
            "Clear command history: history -c; rm ~/.bash_history",
            "Purge temporary DNS and firewall logs if necessary"
        ],
        "clearing_playbook": ["https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-phishing"],
        "mitre_mapping": [
            {"tactic": "Resource Development", "technique": "T1583", "example": "Purchase domains based on discovered network info"},
            {"tactic": "Initial Access", "technique": "T1199", "example": "Leverage trusted relationships exposed via recon"}
        ],
        "watchlist": [
            "Execution of whois, dig, and nmap tools",
            "External DNS queries for internal domains",
            "Outbound connections to passive DNS services"
        ],
        "enhancements": [
            "Integrate threat intelligence feeds into DNS/firewall analysis",
            "Use ML-based anomaly detection for recon behavior patterns"
        ],
        "summary": "This parent technique covers adversary behavior involving the collection of victim network information such as IP ranges, domain names, and infrastructure layout. Such activity is typically used in the earliest phases of an attack lifecycle to inform future steps like phishing, infrastructure mimicry, or direct exploitation.",
        "remediation": "Deploy DNS monitoring, restrict domain data exposure, and block unauthorized recon tools on endpoints.",
        "improvements": "Automate detection of common recon tool behavior, implement deception endpoints to observe attacker scanning tactics.",
        "mitre_version": "16.1"
    }
