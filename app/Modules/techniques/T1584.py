def get_content():
    return {
        "id": "T1584",
        "url_id": "1584",
        "title": "Compromise Infrastructure",
        "description": 'Adversaries may compromise third-party infrastructure that can be used during targeting. Infrastructure solutions include physical or cloud servers, domains, network devices, and third-party web and DNS services. Instead of buying, leasing, or renting infrastructure, an adversary may compromise infrastructure and use it during other phases of the adversary lifecycle.(Citation: Mandiant APT1)(Citation: ICANNDomainNameHijacking)(Citation: Talos DNSpionage Nov 2018)(Citation: FireEye EPS Awakens Part 2) Additionally, adversaries may compromise numerous machines to form a botnet they can leverage. Use of compromised infrastructure allows adversaries to stage, launch, and execute operations while blending in with traffic that is seen as normal or trusted, potentially incorporating digital certificates. Adversaries may also compromise infrastructure to support proxy/proxyware services.(Citation: amnesty_nso_pegasus)(Citation: Sysdig Proxyjacking) By using compromised infrastructure, adversaries may make attribution more difficult, and in some cases they may even compromise the infrastructure of other adversaries prior to targeting.(Citation: NSA NCSC Turla OilRig)',
        "tags": [
            "resource-development",
            "infrastructure-compromise",
            "third-party"
        ],
        "tactic": "Resource Development",
        "protocol": "N/A",
        "os": "N/A",
        "tips": [
            "Monitor domain registrant and resolution information for anomalous or unauthorized changes.",
            "Use internet scanning to discover suspicious or compromised infrastructure that may be staging adversary C2 software.",
            "Leverage threat intelligence to identify known compromised or high-risk hosting providers.",
            "Correlate logs from domain registrars and DNS service providers to detect unusual updates or modifications."
        ],
        "data_sources": "Domain Name: Active DNS, Domain Name: Domain Registration, Domain Name: Passive DNS, Internet Scan: Response Content, Internet Scan: Response Metadata",
        "log_sources": [
            {
                "type": "Domain Name",
                "source": "Registrar and DNS Logs",
                "destination": "SIEM"
            },
            {
                "type": "Internet Scan",
                "source": "Scanning/Recon Tools",
                "destination": "SIEM"
            }
        ],
        "source_artifacts": [
            {
                "type": "Server/Host",
                "location": "Compromised third-party infrastructure",
                "identify": "Used for staging, launching attacks, or proxying malicious traffic"
            },
            {
                "type": "Domain",
                "location": "Hijacked or compromised domain registration",
                "identify": "Used for malicious hosting, phishing, or redirection"
            }
        ],
        "destination_artifacts": [
            {
                "type": "Service",
                "location": "Compromised infrastructure service (e.g., DNS, hosting, cloud instance)",
                "identify": "Abused to deliver malicious payloads, C2, or exfiltration"
            },
            {
                "type": "Botnet",
                "location": "Multiple compromised hosts",
                "identify": "Leveraged to conduct large-scale or distributed malicious operations"
            }
        ],
        "detection_methods": [
            "Monitor domain ownership or DNS records for unauthorized changes",
            "Scan the internet for known malicious response patterns associated with adversary tools",
            "Track newly provisioned or altered infrastructure with suspicious or abnormal usage patterns",
            "Correlate known indicators of compromise (IOCs) with third-party hosting or domain registrars"
        ],
        "apt": [
            "APT1",
            "Turla",
            "OilRig",
            "APT40"
        ],
        "spl_query": [
            "index=network_dns (action=update OR action=modify) \n| stats count by domain, registrar, user \n| where count > 1"
        ],
        "hunt_steps": [
            "Collect DNS, registrar, and hosting provider logs for your organization’s domains and related infrastructure.",
            "Identify unauthorized or suspicious domain record changes (e.g., nameservers, A records).",
            "Look for anomalies in scanning results that indicate the presence of known malicious services or certificates.",
            "Correlate any suspicious infrastructure changes with potential adversary campaigns or TTPs."
        ],
        "expected_outcomes": [
            "Detection of compromised or hijacked third-party infrastructure leveraged by adversaries.",
            "Identification of unusual or unauthorized modifications to domain registration or DNS records.",
            "Improved visibility into adversary infrastructure staging and deployment."
        ],
        "false_positive": "Legitimate domain ownership changes, DNS record updates, or hosting provider migrations may appear suspicious. Proper baselining and verification are necessary.",
        "clearing_steps": [
            "Reclaim control of compromised domains, servers, or hosting accounts.",
            "Reset or rotate credentials for compromised services and restore DNS records to authorized settings.",
            "Notify relevant registrars or hosting providers about suspicious activity and request remediation.",
            "Conduct forensic analysis to identify any additional unauthorized modifications or malicious artifacts."
        ],
        "mitre_mapping": [
            {
                "tactic": "Command and Control",
                "technique": "Proxy (T1090)",
                "example": "Adversaries may compromise infrastructure to act as proxies for malicious traffic."
            },
            {
                "tactic": "Initial Access",
                "technique": "Phishing (T1566)",
                "example": "Adversaries may use compromised domains or servers to host phishing campaigns."
            }
        ],
        "watchlist": [
            "Domains frequently updating NS or A records outside normal patch cycles",
            "Cloud or hosting accounts with unusual login activity or resource provisioning",
            "DNS providers or domain registrars with known security issues or frequent breaches"
        ],
        "enhancements": [
            "Deploy domain monitoring solutions that alert on WHOIS or DNS changes to critical assets.",
            "Implement multi-factor authentication and strong credential policies for domain and hosting accounts.",
            "Use TLS certificates with short lifetimes and track certificate transparency logs for anomalies."
        ],
        "summary": "By compromising third-party infrastructure, adversaries can leverage existing services and reputations to stage attacks, hide malicious traffic, and evade attribution.",
        "remediation": "Reclaim or reset compromised infrastructure assets, restore legitimate DNS records, implement strict access controls, and monitor for further unauthorized changes.",
        "improvements": "Adopt proactive scanning for malicious infrastructure, integrate domain/hosting logs with SIEM, and maintain robust threat intelligence to identify new or compromised assets quickly."
    }
