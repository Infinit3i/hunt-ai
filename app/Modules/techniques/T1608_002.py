def get_content():
    return {
        "id": "T1608.002",
        "url_id": "T1608/002",
        "title": "Stage Capabilities: Upload Tool",
        "description": "Adversaries may upload legitimate tools to adversary-controlled or third-party infrastructure in preparation for use during a campaign. Unlike custom malware, these tools are often public, open-source, or commercial software not inherently malicious (e.g., PsExec). However, once uploaded, they may be used for malicious purposes.\n\nTools may be uploaded to attacker-owned infrastructure acquired through [Acquire Infrastructure](https://attack.mitre.org/techniques/T1583) or compromised systems via [Compromise Infrastructure](https://attack.mitre.org/techniques/T1584). Staging may also occur on legitimate services such as GitHub, Heroku, or other Platform-as-a-Service (PaaS) platforms.\n\nIn many cases, the tool may be used later for [Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105), where it is downloaded by a compromised system directly from the uploaded location. This approach enables flexibility and reduces the need to embed tools directly into payloads, aiding stealth and modularity in attacker operations.",
        "tags": ["PsExec", "tool staging", "ingress", "downloadable tools", "github", "heroku"],
        "tactic": "Resource Development",
        "protocol": "HTTPS",
        "os": "PRE",
        "tips": [
            "Monitor known attacker infrastructure and repositories for newly uploaded tools.",
            "Track usage of commonly abused admin tools such as PsExec, Rubeus, Mimikatz, and Impacket variants.",
            "Use domain reputation and sandbox analysis on tools sourced from less-known repositories or cloud links."
        ],
        "data_sources": "Internet Scan: Response Content",
        "log_sources": [
            {"type": "Web Proxy", "source": "", "destination": "Cloud Service"},
            {"type": "Endpoint Monitoring", "source": "", "destination": ""},
            {"type": "DNS", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Admin Tool Binary", "location": "Attacker Workstation", "identify": "Staged binary for later download"},
            {"type": "Tool Archive", "location": "GitHub Repo", "identify": "ZIP or tar.gz file uploaded by attacker"},
            {"type": "Script Wrapper", "location": "Heroku/PaaS", "identify": "Entry script to invoke tool logic or download"}
        ],
        "destination_artifacts": [
            {"type": "Deployed Binary", "location": "Cloud Application or GitHub", "identify": "Direct download link to binary or repository"},
            {"type": "Cloud-hosted Script", "location": "PaaS-hosted app", "identify": "Entry point that facilitates download/execution"},
            {"type": "Web Application", "location": "Exposed subdomain", "identify": "Delivery site hosting staged tooling"}
        ],
        "detection_methods": [
            "Monitor GitHub, Heroku, and paste sites for unusual or known adversary uploads.",
            "Track endpoint traffic initiating download from domains or IPs tied to threat actor tool repos.",
            "Leverage threat intelligence to pivot from known tool hashes or filenames."
        ],
        "apt": [
            "UNC3890: Uploaded tools to attacker-controlled GitHub repositories to deliver payloads to targets.",
            "Lazarus Group: Used self-hosted tools uploaded to compromised infrastructure for ingress transfer.",
            "TG-3390: Relied on third-party hosting of tooling to avoid direct detection of malicious payloads."
        ],
        "spl_query": "index=network_traffic sourcetype=proxy \n| search uri_path IN [\"*.zip\", \"*.exe\", \"*.tar.gz\"] \n| stats count by uri_domain, uri_path, http_method \n| where count > 3",
        "spl_rule": "https://research.splunk.com/detections/tactics/resource-development/",
        "elastic_rule": "https://github.com/elastic/detection-rules/search?q=tool+upload",
        "sigma_rule": "https://github.com/SigmaHQ/sigma/search?q=ingress+tool",
        "hunt_steps": [
            "Enumerate cloud-hosted binaries with open permissions or exposed endpoints.",
            "Match binary hashes or tool names against known red-team and attacker toolkits.",
            "Trace tools downloaded via ingress tool transfer back to original hosting infrastructure."
        ],
        "expected_outcomes": [
            "Identify adversary-controlled infrastructure hosting legitimate tools for abuse.",
            "Link tool uploads to known adversary campaigns or behavior patterns.",
            "Reveal staging environments before exploitation begins."
        ],
        "false_positive": "Legitimate developers often upload binaries to GitHub or cloud platforms. False positives are likely when assessing open-source tools used across IT operations.",
        "clearing_steps": [
            "Request takedown of malicious tool repos from hosting providers.",
            "Blacklist known URLs or domains staging adversary-used binaries.",
            "Alert internal users if tools are being downloaded from unapproved or new repositories."
        ],
        "mitre_mapping": [
            {"tactic": "Resource Development", "technique": "T1608.002", "example": "UNC3890 uploaded reconnaissance tools to GitHub for distribution to compromised environments."}
        ],
        "watchlist": [
            "Staged tools in newly created GitHub repos with no forks or stars.",
            "Files hosted on PaaS services like Heroku, App Engine, or Vercel with uncommon extensions.",
            "Downloads of PsExec, Mimikatz, or SharpHound from untrusted sources."
        ],
        "enhancements": [
            "Incorporate passive DNS and CTI scanning for malicious tool hosting platforms.",
            "Use YARA rules on downloads to catch known tool signatures in binaries.",
            "Add monitoring rules for uncommon ingress tool transfer activity by new internal users."
        ],
        "summary": "Adversaries may upload legitimate tools (such as PsExec or SharpHound) to adversary-controlled or public infrastructure in preparation for future operations. These tools are later used for lateral movement, discovery, or credential access, without needing custom malware.",
        "remediation": "Review all external tools used internally. Vet new tools from third-party sources. Implement endpoint and perimeter controls for known staging platforms.",
        "improvements": "Automate passive scraping of cloud repos for staged tools. Flag low-reputation repositories or links shared in suspicious traffic. Correlate tool downloads with adversary TTPs.",
        "mitre_version": "16.1"
    }
