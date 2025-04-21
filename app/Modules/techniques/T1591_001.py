def get_content():
    return {
        "id": "T1591.001",
        "url_id": "T1591/001",
        "title": "Gather Victim Org Information: Determine Physical Locations",
        "description": "Adversaries may gather the victim's physical location(s) that can be used during targeting. This includes addresses of headquarters, data centers, remote offices, or field assets, which may reveal legal jurisdictions or geographic exposure.",
        "tags": ["reconnaissance", "physical-targeting", "geo-osint", "external", "pre-attack"],
        "tactic": "Reconnaissance",
        "protocol": "HTTP",
        "os": "Windows, Linux, macOS",
        "tips": [
            "Use IP geolocation and WHOIS data to track external access attempts tied to physical location mapping.",
            "Scrub location metadata from public documents and images (e.g., EXIF data).",
            "Monitor social media and press releases for potential leak of office locations."
        ],
        "data_sources": "Web Credential, Domain Name, Application Log, Internet Scan, User Account, Persona, Image, Network Traffic",
        "log_sources": [
            {"type": "Network Traffic", "source": "", "destination": ""},
            {"type": "Domain Name", "source": "", "destination": ""},
            {"type": "Image", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Browser History", "location": "%APPDATA%\\Local\\Google\\Chrome\\User Data\\Default", "identify": "Visited maps, address lookups, or location check-ins"},
            {"type": "Image", "location": "User shared folders, media libraries", "identify": "EXIF metadata showing coordinates of corporate offices"}
        ],
        "destination_artifacts": [],
        "detection_methods": [
            "Correlate image uploads with embedded location data (EXIF)",
            "Monitor for WHOIS lookups tied to IP ranges of known facilities",
            "Detect frequent visits to facility-related URLs or real estate platforms"
        ],
        "apt": ["APT33", "Iranian Threat Actor Group", "Charming Kitten"],
        "spl_query": [
            'index=web_logs uri="*contact-us*" OR uri="*locations*"\n| stats count by src_ip, uri',
            'index=proxy_logs uri="*map*" OR uri="*offices*"\n| stats count by src_ip, user_agent',
            'index=image_logs exif_location_latitude!="null"\n| stats count by src_user, file_name'
        ],
        "hunt_steps": [
            "Review image repositories for geotagged files associated with enterprise branding",
            "Search proxy logs for patterns in traffic toward facility location pages",
            "Look for WHOIS data queries to address blocks or ASN prefixes"
        ],
        "expected_outcomes": [
            "Identification of physical facility data exposure",
            "Detection of potential adversary focus on critical sites",
            "Correlation between location data interest and broader reconnaissance"
        ],
        "false_positive": "Internal users accessing company contact or map pages can trigger similar logs. Validate context by source IP or user behavior.",
        "clearing_steps": [
            "Flush browser cache and clear map search histories",
            "Strip location metadata from image files using tools like exiftool:\nCommand: `exiftool -gps:all= -xmp:geotag= -overwrite_original <file>`"
        ],
        "clearing_playbook": ["https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-phishing"],
        "mitre_mapping": [
            {"tactic": "Reconnaissance", "technique": "T1593", "example": "Search Open Websites/Domains"},
            {"tactic": "Initial Access", "technique": "T1566", "example": "Phishing"},
            {"tactic": "Resource Development", "technique": "T1587", "example": "Develop Capabilities"}
        ],
        "watchlist": [
            "Public images containing corporate facility geolocation",
            "Social media mentions of office openings or relocations",
            "Frequent access to location-specific map links"
        ],
        "enhancements": [
            "Automate geolocation detection in uploaded media",
            "Create alerts for WHOIS/IP block queries tied to known regions"
        ],
        "summary": "This technique involves the passive or active collection of a target organization’s physical site locations, which may be used to inform legal risks, physical intrusions, or geographically coordinated attacks.",
        "remediation": "Ensure operational security practices include removal of geolocation metadata. Avoid publishing detailed site locations without access controls.",
        "improvements": "Integrate geolocation stripping into file upload workflows. Deploy honeypots with fake site addresses to detect reconnaissance.",
        "mitre_version": "16.1"
    }
