def get_content():
    return {
        "id": "T1539",
        "url_id": "T1539",
        "title": "Steal Web Session Cookie",
        "description": "Adversaries may steal web session cookies to impersonate authenticated users on web applications and services. These cookies, often stored in browsers or process memory, can grant access without requiring re-authentication or even bypass MFA protections. Threat actors can obtain them via local system access, memory scraping, malicious JavaScript, or adversary-in-the-middle proxies like Evilginx2 or Muraena.",
        "tags": ["credential access", "cookies", "browser memory", "evilginx2", "T1539", "session hijack", "phishing", "JavaScript"],
        "tactic": "Credential Access",
        "protocol": "",
        "os": "Linux, Office Suite, SaaS, Windows, macOS",
        "tips": [
            "Scan memory dumps from browsers for cookie artifacts.",
            "Monitor file access to cookie storage paths like Chrome/Firefox profiles.",
            "Audit outbound requests to unusual hosts from browsers."
        ],
        "data_sources": "File: File Access, Process: Process Access",
        "log_sources": [
            {"type": "EDR", "source": "Browser process", "destination": ""},
            {"type": "File System", "source": "Local host", "destination": ""},
            {"type": "Process Monitoring", "source": "Endpoint agent", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Cookie Files", "location": "Local file system", "identify": "Chrome: `Cookies` file, Firefox: `cookies.sqlite`"},
            {"type": "Memory Dumps", "location": "Process memory", "identify": "LSASS/browser process memory scans"}
        ],
        "destination_artifacts": [
            {"type": "HTTP Requests", "location": "Proxy logs or IDS", "identify": "Header contains valid session cookie"},
            {"type": "Phishing Site Payloads", "location": "JavaScript injection", "identify": "Exfil of `document.cookie` values"}
        ],
        "detection_methods": [
            "Monitor access to browser session files (Cookies, cookies.sqlite).",
            "Detect process injection or memory scraping targeting browser processes.",
            "Alert on abnormal HTTP traffic using stolen session tokens."
        ],
        "apt": [
            "Scattered Spider",  # Cookie-based access used for MFA bypass
            "EvilNum",           # Known to use JavaScript stealers
            "QakBot",            # Extracts session data from browsers
            "COLDRIVER",         # Known for credential harvesting & session hijacks
            "InkySquid",         # Conducted cookie-based session impersonation
            "TajMahal",          # Malware observed extracting cookie data
            "LuminousMoth",      # Cookie extraction included in toolkit
            "CookieMiner",       # Specifically designed to steal cookies on macOS
        ],
        "spl_query": [
            'index=edr process_name="chrome.exe" OR process_name="firefox.exe"\n| search process_command_line="*Cookies*" OR file_path="*cookies.sqlite*"\n| stats count by host, user, file_path',
            'index=sysmon event_id=10 image="*evilginx*" OR image="*muraena*"\n| stats count by user, command_line',
            'index=proxy_logs user_agent="*Mozilla*" AND http_header="*cookie*"\n| stats values(http_header) by src_ip, uri_path'
        ],
        "hunt_steps": [
            "Look for suspicious reads of browser cookie files.",
            "Analyze memory dumps or EDR telemetry from browser processes.",
            "Inspect JavaScript execution logs in browsers or proxies for cookie access.",
            "Check for usage of adversary-in-the-middle tools like Evilginx2."
        ],
        "expected_outcomes": [
            "Identification of unauthorized session token access.",
            "Detection of attempts to bypass MFA or hijack accounts.",
            "Evidence of cookie-theft tooling usage (e.g., via YARA or process memory)."
        ],
        "false_positive": "Legitimate system monitoring tools or backup utilities may access browser cookies. Validate with process lineage and context.",
        "clearing_steps": [
            "Purge browser session storage across all endpoints.",
            "Terminate suspicious sessions from identity provider dashboards.",
            "Reset compromised accounts and enforce re-authentication."
        ],
        "mitre_mapping": [
            {"tactic": "Credential Access", "technique": "T1539", "example": "Scattered Spider used session cookies to bypass MFA and maintain access to Microsoft 365 accounts."}
        ],
        "watchlist": [
            "Access to Chrome's 'Cookies' file or Firefox's 'cookies.sqlite'",
            "Browser memory access by unauthorized tools",
            "Login attempts using cookie tokens with no password input"
        ],
        "enhancements": [
            "Enable short session durations with token rotation.",
            "Use secure, HttpOnly cookie flags to prevent JavaScript access.",
            "Detect Evilginx2/Ngrok domain patterns in phishing attempts."
        ],
        "summary": "Cookie theft enables stealthy account access, bypassing authentication barriers. Monitoring file, memory, and HTTP indicators is critical to detecting adversarial abuse of session tokens.",
        "remediation": "Restrict access to session storage. Enable session binding to IP/device. Train users against phishing and browser exploit traps.",
        "improvements": "Implement behavioral analytics on cookie usage patterns. Enable real-time revocation for anomalous session tokens.",
        "mitre_version": "16.1"
    }
