def get_content():
    return {
        "id": "T1608.006",
        "url_id": "T1608/006",
        "title": "Stage Capabilities: SEO Poisoning",
        "description": "Adversaries may manipulate search engine optimization (SEO) mechanisms to lure victims toward staged malicious content. This often includes stuffing keywords into legitimate or compromised websites to increase their visibility in search engine results. The keywords may reflect trending topics, seasonal interests, or common searches related to the target demographic. \n\nSEO poisoning is commonly used in support of Drive-by Compromise and Supply Chain Compromise, where malicious sites are promoted via search rankings to entice user clicks. Tactics include placing hidden keyword-laden text, purchasing backlinks, or redirecting traffic based on browser/user-agent detection to evade security tools while influencing crawlers.\n\nThis technique may also extend to internal or niche platform searches, such as GitHub or developer documentation platforms, where adversaries game the ranking mechanisms to promote weaponized repositories or lure users to malicious forks. SEO poisoning can be difficult to detect due to the dynamic and context-specific nature of ranking manipulation.",
        "tags": ["seo", "drive-by", "lure", "resource development", "ranking manipulation", "malvertising"],
        "tactic": "Resource Development",
        "protocol": "",
        "os": "PRE",
        "tips": [
            "Correlate unusual traffic spikes to unknown or suspicious domains.",
            "Inspect keyword density and hidden text in newly registered or updated sites.",
            "Analyze redirection behavior based on geolocation, browser, or user-agent."
        ],
        "data_sources": "Internet Scan: Response Content",
        "log_sources": [
            {"type": "Web Content", "source": "Proxy Logs", "destination": ""},
            {"type": "DNS", "source": "Recursive Resolver", "destination": ""},
            {"type": "Endpoint", "source": "Browser Telemetry", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Web Page", "location": "HTML/DOM", "identify": "Stuffed keywords, hidden links"},
            {"type": "Search Result", "location": "Google/Bing/GitHub", "identify": "Top-ranked sites with embedded payloads"},
            {"type": "HTTP Header", "location": "Cloaked Content", "identify": "User-agent redirects, referrer-based redirection"}
        ],
        "destination_artifacts": [
            {"type": "Landing Page", "location": "Infected Domain", "identify": "Drive-by scripts, download links"},
            {"type": "Search Engine Result", "location": "SERP", "identify": "Fraudulently promoted entries"},
            {"type": "Developer Platform", "location": "Repository Listings", "identify": "Malicious forks or mirrors"}
        ],
        "detection_methods": [
            "Monitor for keyword stuffing in unexpected pages.",
            "Detect mass backlink purchases or unusual cross-linking behavior.",
            "Analyze redirect chains and cloaking behavior in HTTP headers."
        ],
        "apt": [
            "Gootloader: SEO poisoning with keyword-laden blog posts leading to malicious download links.",
            "SocGholish: Hosted JavaScript-based malware via high-ranking websites compromised through SEO poisoning.",
            "Ransomware as a Service (various): Used SEO tactics to push fake download pages for installers."
        ],
        "spl_query": "index=proxy_logs uri_path=* AND (referrer_domain=*google.* OR referrer_domain=*bing.*) \n| search uri_path IN [list of known SEO bait paths] \n| stats count by uri_path, user_agent, src_ip",
        "spl_rule": "https://research.splunk.com/detections/tactics/resource-development/",
        "elastic_rule": "https://github.com/elastic/detection-rules/search?q=seo+poisoning",
        "sigma_rule": "https://github.com/SigmaHQ/sigma/search?q=T1608.006",
        "hunt_steps": [
            "Identify newly created domains with sudden traffic spikes.",
            "Search for blog or static site pages with high keyword density targeting niche topics.",
            "Use browser sandboxing to trace redirect chains from high-ranking search results.",
            "Correlate referrer headers with known engines when malware is downloaded."
        ],
        "expected_outcomes": [
            "Detection of SEO-poisoned sites promoting payloads.",
            "Identification of campaigns manipulating search results.",
            "Attribution of resource development infrastructure."
        ],
        "false_positive": "Legitimate SEO practices (like trending keyword optimization or link farming) may appear similar.",
        "clearing_steps": [
            "Block access to identified malicious domains.",
            "Submit poisoned URLs to search engines for takedown or demotion.",
            "Educate users to avoid downloading executables from non-official search results."
        ],
        "mitre_mapping": [
            {"tactic": "Resource Development", "technique": "T1608.006", "example": "Gootloader promoting download links through SEO-optimized posts on compromised blogs."}
        ],
        "watchlist": [
            "Newly registered domains with SEO-tuned content.",
            "Redirect chains from search engine referrals.",
            "Blog or forum posts with irrelevant keyword stuffing."
        ],
        "enhancements": [
            "Deploy honeypot domains with beacon links to identify SEO poisoning attempts.",
            "Monitor for mass-indexed sites via Google Search Console.",
            "Detect JavaScript fingerprinting logic used for cloaking."
        ],
        "summary": "SEO Poisoning allows adversaries to manipulate search results to promote access to staged malicious infrastructure. This technique plays a critical role in resource development for drive-by campaigns and malware delivery.",
        "remediation": "Monitor for keyword manipulation and use domain categorization to block newly abused SEO sites. Incorporate DNS reputation feeds.",
        "improvements": "Enhance crawlers to simulate different user agents and uncover cloaked payloads. Analyze search trends against malware telemetry for correlation.",
        "mitre_version": "16.1"
    }
