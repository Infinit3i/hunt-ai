def get_content():
    return {
        "id": "T1137",
        "url_id": "T1137",
        "title": "Office Application Startup",
        "tactic": "Persistence",
        "data_sources": "Windows Registry, File Monitoring, Process Monitoring",
        "protocol": "N/A",
        "os": "Windows, macOS",
        "objective": "Detect and mitigate persistence mechanisms leveraging Microsoft Office applications to execute malicious code.",
        "scope": "Monitor Office-related registry keys, startup templates, and add-ins for unauthorized modifications.",
        "threat_model": "Adversaries may abuse Office application startup mechanisms to achieve persistence on a compromised system.",
        "hypothesis": [
            "Are Office add-ins or templates being modified unexpectedly?",
            "Are unauthorized macros executing on startup?",
            "Are registry keys related to Office applications being modified?"
        ],
        "log_sources": [
            {"type": "Registry Monitoring", "source": "Sysmon (Event ID 13)"},
            {"type": "Process Monitoring", "source": "Sysmon (Event ID 1)"},
            {"type": "File Monitoring", "source": "Windows Security Logs (Event ID 4663)"}
        ],
        "detection_methods": [
            "Monitor Office startup registry keys for changes.",
            "Detect execution of Office applications with unusual parameters.",
            "Identify suspicious Office add-ins or templates being loaded."
        ],
        "spl_query": "index=windows (EventCode=13 OR EventCode=1 OR EventCode=4663) OfficeStartup=modified",
        "sigma_rule": "https://grep.app/search?f.repo=SigmaHQ%2Fsigma&q=T1137",
        "hunt_steps": [
            "Identify unauthorized Office startup modifications.",
            "Correlate with known attack behaviors (e.g., malicious add-ins).",
            "Investigate suspicious execution of Office applications."
        ],
        "expected_outcomes": [
            "Persistence via Office startup detected and mitigated.",
            "No unauthorized modifications found, improving baseline detections."
        ],
        "mitre_mapping": [
            {"tactic": "Persistence", "technique": "T1137 (Office Application Startup)", "example": "Malicious Office add-in executing at startup."}
        ],
        "watchlist": [
            "Monitor Office add-in locations and registry keys.",
            "Alert on unusual process executions linked to Office applications."
        ],
        "enhancements": [
            "Restrict user access to Office startup registry keys.",
            "Enable logging of Office application execution parameters."
        ],
        "summary": "Track unauthorized Office startup modifications.",
        "remediation": "Remove unauthorized Office add-ins and templates.",
        "improvements": "Enhance monitoring of Office execution and persistence techniques."
    }
