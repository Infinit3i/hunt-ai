def get_content():
    return {
        "id": "T1567.003",
        "url_id": "T1567.003",
        "title": "Exfiltration Over Web Service: Exfiltration to Text Storage Sites",
        "description": "Adversaries may exfiltrate data by uploading it to public text storage sites such as `pastebin.com`. These platforms are typically used by developers for code sharing, but adversaries can exploit them for covert data exfiltration.\n\nUnlike code repositories, text storage sites often do not require authentication or have limited monitoring. Some offer encryption and anonymity features, making them attractive for storing and retrieving sensitive data. While these platforms are also used for hosting malicious payloads, this technique focuses on data *exfiltration* rather than payload delivery.\n\nDue to the ubiquitous and legitimate use of such services, identifying malicious uploads can be difficult, especially when HTTPS is used for transport.",
        "tags": ["exfiltration", "pastebin", "public sites", "https", "obfuscation", "data theft"],
        "tactic": "Exfiltration",
        "protocol": "HTTPS",
        "os": "Linux, Windows, macOS",
        "tips": [
            "Inspect outbound HTTPS traffic to pastebin.com and similar services.",
            "Correlate with process behavior, e.g., command-line tools accessing text storage APIs.",
            "Flag automated POST requests to known text dump endpoints outside of development environments."
        ],
        "data_sources": "Network Traffic: Network Traffic Content, Network Traffic: Network Traffic Flow",
        "log_sources": [
            {"type": "Network Traffic", "source": "Proxy Logs, Firewall Logs, Packet Capture", "destination": ""},
            {"type": "Application Log", "source": "Browser Logs, CLI tool logs (curl, wget)", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Staged Data", "location": "Temp directories, memory, encoded format", "identify": "Sensitive files encoded and prepared for upload"}
        ],
        "destination_artifacts": [
            {"type": "Pastebin Post", "location": "Remote paste site", "identify": "Exfiltrated content posted under adversary-controlled user or anonymously"}
        ],
        "detection_methods": [
            "Monitor HTTP POST requests to common pastebin-like domains (e.g., pastebin.com, hastebin.com, paste.ee).",
            "Flag excessive or automated uploads from non-developer endpoints.",
            "Use SSL decryption (if allowed) to inspect traffic payloads."
        ],
        "apt": [],
        "spl_query": [
            "index=network sourcetype=proxy \n| search uri_domain=pastebin.com OR uri_domain=paste.ee OR uri_domain=hastebin.com \n| stats count by src_ip, uri_path, http_method"
        ],
        "hunt_steps": [
            "Identify devices making HTTP POST requests to paste sites.",
            "Cross-reference with endpoint processes or scripts responsible for those requests.",
            "Correlate with file access events (e.g., sensitive doc or archive read before upload).",
            "Look for encoded or encrypted blobs being transmitted."
        ],
        "expected_outcomes": [
            "Text Site Exfiltration Detected: Block domain, analyze staging tool used, notify IR.",
            "No Malicious Activity Found: Improve detection thresholds and validate alert logic."
        ],
        "false_positive": "Developers or analysts may legitimately use these platforms. Whitelist trusted usage (e.g., developer laptops, known curl scripts).",
        "clearing_steps": [
            "Remove uploaded pastes from public platforms if accessible.",
            "Revoke any credentials used by uploading scripts.",
            "Isolate system that performed the upload and conduct forensic review."
        ],
        "mitre_mapping": [
            {"tactic": "Exfiltration", "technique": "T1567.003 (Exfiltration to Text Storage Sites)", "example": "Attacker posts stolen database dump to pastebin.com."}
        ],
        "watchlist": [
            "Monitor for HTTPS POST requests to paste platforms from non-developer endpoints.",
            "Alert on frequent paste uploads within short time windows.",
            "Flag attempts to upload large payloads or encoded content (base64, hex)."
        ],
        "enhancements": [
            "Implement DNS filtering to restrict access to paste sites.",
            "Use browser extensions or DLP to prevent uploads to unauthorized domains.",
            "Deploy behavioral analysis to detect scripts posting to paste services."
        ],
        "summary": "Attackers may upload sensitive data to text dump websites to exfiltrate it without triggering traditional C2 detection. Monitoring usage patterns and applying behavioral analytics are key to detecting such misuse.",
        "remediation": "Block access to unapproved paste sites, investigate origin of upload, and contain compromised endpoints.",
        "improvements": "Expand telemetry on paste usage, integrate threat intelligence feeds with paste service abuse indicators.",
        "mitre_version": "16.1"
    }
