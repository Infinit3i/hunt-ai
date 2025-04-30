def get_content():
    return {
        "id": "T1027.017",
        "url_id": "T1027/017",
        "title": "SVG Smuggling",
        "description": "Adversaries may smuggle data and files past content filters by hiding malicious payloads inside of seemingly benign SVG files.",
        "tags": ["svg", "smuggling", "html smuggling", "obfuscation", "javascript", "payload"],
        "tactic": "defense-evasion",
        "protocol": "HTTP, HTTPS",
        "os": "Windows, Linux, macOS",
        "tips": [
            "Inspect SVG files for embedded script tags or obfuscated JavaScript.",
            "Treat downloads of .svg files from unknown or suspicious sources as potential threats.",
            "Correlate SVG activity with follow-on execution from scripting interpreters like PowerShell or wscript.exe."
        ],
        "data_sources": "File, Command, Network Traffic",
        "log_sources": [
            {"type": "File", "source": "", "destination": ""},
            {"type": "Command", "source": "", "destination": ""},
            {"type": "Network Traffic", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Browser History", "location": "%APPDATA%\\Browser\\", "identify": "Downloaded SVG from suspicious origin"},
            {"type": "Recent Files", "location": "%USERPROFILE%\\Downloads\\", "identify": "Suspicious .svg file present"}
        ],
        "destination_artifacts": [
            {"type": "Process List", "location": "RAM", "identify": "Execution of scripting engines from SVG trigger"}
        ],
        "detection_methods": [
            "Monitor for downloads of .svg files followed by script execution.",
            "Scan SVGs for embedded <script> tags containing eval, atob, or suspicious JavaScript functions."
        ],
        "apt": [],
        "spl_query": [
            "index=(sourcetype=\"WinEventLog:Microsoft-Windows-Sysmon/Operational\" OR sourcetype=\"linux_audit\" OR sourcetype=\"osquery\") (file_name=\".svg\" OR file_path=\"\\Downloads\\.svg\" OR file_path=\"/tmp/.svg\") \n | join type=inner file_path [ search index=* process_name IN (\"powershell.exe\", \"wscript.exe\", \"cmd.exe\", \"mshta.exe\", \"bash\", \"curl\", \"wget\") | stats min(_time) as proc_time by file_path, process_name, host ] \n| eval time_diff=proc_time - _time \n| where time_diff >= 0 AND time_diff < 120 \n | table _time, host, user, file_path, file_name, process_name, command_line, time_diff \n | sort _time",
            "file_name=\".svg\" \n | rex field=_raw \"\" \n| search js_payload=\"eval\" OR js_payload=\"atob\" OR js_payload=\"window.location\" OR js_payload=\"document.write\" \n| table _time, file_name, js_payload"
        ],
        "hunt_steps": [
            "Look for SVG files in user download folders.",
            "Parse SVGs to detect embedded JavaScript.",
            "Correlate SVG interaction with script execution."
        ],
        "expected_outcomes": [
            "Detection of SVGs used to stage or redirect to payloads."
        ],
        "false_positive": "Some SVG files may use scripts legitimately for interactive graphics. Validate context and source.",
        "clearing_steps": [
            "del /f /q %USERPROFILE%\\Downloads\\*.svg",
            "taskkill /f /im mshta.exe",
            "Clear browser caches and history."
        ],
        "clearing_playbook": [
            "https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-malware"
        ],
        "mitre_mapping": [
            {"tactic": "defense-evasion", "technique": "T1059.005", "example": "JavaScript"},
            {"tactic": "defense-evasion", "technique": "T1027.002", "example": "Encoded Files or Information"}
        ],
        "watchlist": [
            "SVG files embedded with JavaScript that initiate download or execution",
            "Browser processes executing command-line tools shortly after SVG interaction"
        ],
        "enhancements": [
            "Sandbox suspicious SVGs for behavior analysis.",
            "Implement deep content inspection for embedded scripts in SVG/XML."
        ],
        "summary": "SVG Smuggling enables adversaries to bypass security controls by embedding malicious scripts within seemingly benign image files, often leading to second-stage payload delivery.",
        "remediation": "Restrict execution of embedded SVG scripts and block suspicious file types from untrusted sources.",
        "improvements": "Combine file origin tracking with process correlation to detect suspicious SVG activity.",
        "mitre_version": "17.0"
    }
