def get_content():
    return {
        "id": "T1027.006",
        "url_id": "T1027/006",
        "title": "Obfuscated Files or Information: HTML Smuggling",
        "description": "Adversaries may use HTML and JavaScript features to smuggle malicious files past security controls.",
        "tags": ["html smuggling", "blob", "data URL", "js obfuscation", "evasion"],
        "tactic": "Defense Evasion",
        "protocol": "HTTP",
        "os": "Linux, Windows, macOS",
        "tips": [
            "Look for excessive use of JavaScript Blob, msSaveOrOpenBlob, and base64 Data URLs.",
            "Correlate file downloads with script execution in browser contexts.",
            "Use sandboxed detonation environments to detect payloads constructed dynamically in-memory."
        ],
        "data_sources": "File: File Creation",
        "log_sources": [
            {"type": "File", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Browser History", "location": "AppData\\Local\\Microsoft\\Edge\\User Data", "identify": "URLs leading to HTML payloads"},
            {"type": "Clipboard Data", "location": "Memory", "identify": "Encoded strings copied to memory during execution"},
            {"type": "Memory Dumps", "location": "RAM", "identify": "Blob content assembled in-browser"}
        ],
        "destination_artifacts": [
            {"type": "Prefetch Files", "location": "C:\\Windows\\Prefetch", "identify": "Downloaded payloads executed"},
            {"type": "Event Logs", "location": "Microsoft-Windows-Sysmon/Operational", "identify": "File creation from browser processes"},
            {"type": "Link Files (.lnk)", "location": "Recent folder", "identify": "Shortcut to payload launched by user"}
        ],
        "detection_methods": [
            "Monitor browser downloads with embedded JavaScript and Data URL patterns.",
            "Use network sandboxing and behavioral emulation for inbound HTML files.",
            "Detect large JavaScript blobs or unexpected use of `msSaveOrOpenBlob`, `download`, or dynamic `a.href` creation."
        ],
        "apt": [
            "NOBELIUM", "Black Basta"
        ],
        "spl_query": [
            'index=web_logs extension="html" OR extension="hta"\n| search blob OR msSaveBlob OR download\n| stats count by uri, src_ip, user',
            'index=process_creation parent_process_name="browser.exe" process_name="cmd.exe" OR process_name="powershell.exe"\n| table _time, user, parent_process_name, process_name, command_line'
        ],
        "hunt_steps": [
            "Search web proxy logs for `.html` or `.hta` downloads containing suspicious blob or Data URL usage.",
            "Correlate file creation events with browser activity that immediately spawns processes.",
            "Detonate suspect HTML files in sandbox to identify dynamic payload generation."
        ],
        "expected_outcomes": [
            "Detection of HTML file constructing and saving payloads via JavaScript",
            "Revealed use of blob-based or embedded base64 payloads",
            "Execution of malicious payload triggered from HTML smuggling vector"
        ],
        "false_positive": "Some legitimate websites and applications use `Blob`, `download`, or inline Data URLs. Behavioral context is key.",
        "clearing_steps": [
            "Delete downloaded HTML and payload files from disk and quarantine browser cache",
            "Block HTML MIME-type downloads from untrusted sources",
            "Update web proxies and antivirus to detect smuggling patterns"
        ],
        "mitre_mapping": [
            {"tactic": "Execution", "technique": "T1059.005", "example": "Payload launched by obfuscated HTML"},
            {"tactic": "Defense Evasion", "technique": "T1140", "example": "Payload decoded and executed on victim device"}
        ],
        "watchlist": [
            "JavaScript files with large embedded blobs or base64 content",
            "Downloads from uncommon or untrusted domains",
            "Use of `a.download`, `msSaveOrOpenBlob`, or base64 blobs inside HTML"
        ],
        "enhancements": [
            "Deploy secure email and web gateway filtering rules for HTML content",
            "Trigger sandbox detonation for emails with HTML attachments",
            "Use browser instrumentation tools to monitor download behaviors"
        ],
        "summary": "HTML Smuggling bypasses traditional detection by using legitimate browser features to dynamically construct and save malicious payloads on the victim's device.",
        "remediation": "Block risky content types at the perimeter, enable advanced threat protection on web and email gateways, and educate users not to open suspicious HTML attachments.",
        "improvements": "Enhance proxy and AV rules with YARA signatures for blob obfuscation and JavaScript dropper patterns. Monitor browser behavior linked to file writes.",
        "mitre_version": "16.1"
    }
