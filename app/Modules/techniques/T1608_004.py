def get_content():
    return {
        "id": "T1608.004",
        "url_id": "T1608/004",
        "title": "Stage Capabilities: Drive-by Target",
        "description": "Adversaries may stage malicious web content intended to compromise users through drive-by interaction. These resources are typically set up prior to [Drive-by Compromise](https://attack.mitre.org/techniques/T1189) and are delivered to users through normal browsing behaviors. Malicious payloads are delivered without additional user interaction after landing on the site. \n\nStaging may involve adversary-controlled or compromised infrastructure, where scripts such as [JavaScript](https://attack.mitre.org/techniques/T1059/007) are injected into pages or advertisements. Examples include modifying forum posts, abusing publicly writable cloud-hosted script files, or hosting fake ads via [Malvertising](https://attack.mitre.org/techniques/T1583/008). \n\nIn some campaigns, these malicious resources include fingerprinting logic (e.g., [Gather Victim Host Information](https://attack.mitre.org/techniques/T1592)) to check browser attributes before attempting exploitation. Adversaries may also register lookalike domains (homoglyphs, typosquatting, alternate TLDs) to increase success and trust. Strategic Web Compromise (watering hole) attacks frequently target communities with shared interests, such as government or industry groups.",
        "tags": ["watering hole", "malvertising", "javascript injection", "strategic compromise", "drive-by"],
        "tactic": "Resource Development",
        "protocol": "",
        "os": "PRE",
        "tips": [
            "Conduct regular domain monitoring to detect cloned or typo-squatted domains.",
            "Evaluate third-party ad networks and embedded scripts for anomalous behavior.",
            "Deploy browser-based endpoint protection to inspect and analyze scripts on landing pages."
        ],
        "data_sources": "Internet Scan: Response Content",
        "log_sources": [
            {"type": "Web Proxy", "source": "Egress Gateway", "destination": ""},
            {"type": "DNS", "source": "Recursive Resolver", "destination": ""},
            {"type": "Browser", "source": "Endpoint", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Malicious Ad", "location": "Webpage Ad Slot", "identify": "Injected or redirecting JavaScript payload"},
            {"type": "HTML File", "location": "Website Source", "identify": "Obfuscated drive-by code"},
            {"type": "Redirect URL", "location": "Landing Page Script", "identify": "Links to exploit server or payload host"}
        ],
        "destination_artifacts": [
            {"type": "Exploit Kit", "location": "Drive-by Landing Page", "identify": "Browser-targeting payloads"},
            {"type": "Profiling Script", "location": "Pre-exploitation Script Block", "identify": "Evaluates browser before serving payload"},
            {"type": "Cloud Hosted File", "location": "Public S3 Bucket or Blob", "identify": "Injected script linked into third-party site"}
        ],
        "detection_methods": [
            "Scan embedded third-party scripts and ads for obfuscation or unexpected behavior.",
            "Monitor domain registration activity for lookalike or typo-squatted domains.",
            "Use behavioral analytics to detect unusual browser activity or redirection chains."
        ],
        "apt": [
            "SocGholish: Delivered fake browser updates via drive-by compromises of legitimate websites.",
            "OceanLotus (APT32): Compromised high-profile sites for strategic web compromise targeting Vietnamese users.",
            "FIN7: Leveraged malvertising and watering hole tactics to stage malware lures."
        ],
        "spl_query": "index=web_logs uri_path=* \n| search uri_path IN [\"*.js\", \"*.html\"] user_agent IN [\"*Chrome*\", \"*Firefox*\"] \n| regex uri_path=\".*(update|download|setup).*\" \n| stats count by uri_path, user_agent, referrer, src_ip",
        "spl_rule": "https://research.splunk.com/detections/tactics/resource-development/",
        "elastic_rule": "https://github.com/elastic/detection-rules/search?q=watering+hole",
        "sigma_rule": "https://github.com/SigmaHQ/sigma/search?q=T1608.004",
        "hunt_steps": [
            "Identify suspicious JavaScript injected into compromised websites.",
            "Correlate web logs for users landing on uncommon domains with known redirect behavior.",
            "Check domains registered shortly before the campaign and linked via ads or emails."
        ],
        "expected_outcomes": [
            "Detection of malicious scripts on websites targeting specific communities.",
            "Attribution of redirected drive-by compromise attempts to staged infrastructure.",
            "Correlation of phishing or SEO lures to drive-by target sites."
        ],
        "false_positive": "Ad networks and JavaScript-based analytics often use obfuscation techniques that resemble malicious drive-by payloads.",
        "clearing_steps": [
            "Blacklist identified malicious domains and redirect paths.",
            "Report compromised third-party websites to hosting providers.",
            "Scrape landing pages and scripts for forensic review of payloads."
        ],
        "mitre_mapping": [
            {"tactic": "Resource Development", "technique": "T1608.004", "example": "SocGholish used strategic web compromise with injected JavaScript into legitimate news websites to deliver malware."}
        ],
        "watchlist": [
            "New domain registrations mimicking popular or official sites.",
            "Cloud-hosted scripts from writable storage buckets.",
            "Unusual HTTP GET requests with long query parameters or base64 strings."
        ],
        "enhancements": [
            "Leverage WAFs to detect drive-by exploitation attempts in incoming web traffic.",
            "Deploy honeypot environments with simulated browsing activity to catch staged attacks.",
            "Use browser isolation solutions to sandbox all unknown traffic before user interaction."
        ],
        "summary": "Drive-by targeting involves staging malicious content that is served through compromised or adversary-controlled websites to compromise users through normal browsing behavior. These setups enable seamless delivery of malware or exploits, often tailored to specific audiences.",
        "remediation": "Coordinate with hosting providers to remove malicious scripts. Block IPs or domains used for drive-by redirection and payload hosting. Educate users on safe browsing habits and keep browsers patched.",
        "improvements": "Partner with ad providers to ensure auditing of embedded third-party scripts. Enforce allowlisting for script execution in sensitive environments. Track and profile abnormal user-agent behavior across web gateways.",
        "mitre_version": "16.1"
    }
