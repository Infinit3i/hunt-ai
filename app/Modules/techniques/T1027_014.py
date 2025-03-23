def get_content():
    return {
        "id": "T1027.014",
        "url_id": "T1027/014",
        "title": "Obfuscated Files or Information: Polymorphic Code",
        "description": "Adversaries may utilize polymorphic code (also known as metamorphic or mutating code) to evade detection. Polymorphic code is a type of software capable of changing its runtime footprint during code execution. With each execution of the software, the code is mutated into a different version of itself that achieves the same purpose or objective as the original. This functionality enables the malware to evade traditional signature-based defenses, such as antivirus and antimalware tools.",
        "tags": ["Obfuscation", "Polymorphic Code", "Malware", "Defense Evasion"],
        "tactic": "Defense Evasion",
        "protocol": "",
        "os": "Linux, Windows, macOS",
        "tips": [],
        "data_sources": "Application Log: Application Log Content, File: File Creation, File: File Metadata",
        "log_sources": [
            {"type": "Application Log", "source": "Application Log Content", "destination": ""},
            {"type": "File", "source": "File Creation", "destination": ""},
            {"type": "File", "source": "File Metadata", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "File", "location": "File Metadata", "identify": "Polymorphic Code"}
        ],
        "destination_artifacts": [
            {"type": "File", "location": "File Metadata", "identify": "Polymorphic Code"}
        ],
        "detection_methods": ["Monitor for polymorphic code behaviors during execution and file creation"],
        "apt": ["BendyBear", "TruKno", "Ye Yint Min Thu Htut", "Active Defense Team", "DBS Bank"],
        "spl_query": [],
        "hunt_steps": ["Search for polymorphic code patterns in system logs and memory dumps"],
        "expected_outcomes": ["Detection of mutated versions of the same malicious code"],
        "false_positive": "Legitimate code mutations or updates may trigger false positives",
        "clearing_steps": ["Remove polymorphic files and revert to known good versions of software"],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1027", "example": "Polymorphic code used to evade signature-based detection"}
        ],
        "watchlist": ["Monitor for abnormal code mutation behaviors or sudden changes in file signatures"],
        "enhancements": ["Use machine learning models to detect polymorphic behaviors in code execution"],
        "summary": "Polymorphic code changes its appearance during execution to evade detection by traditional security measures.",
        "remediation": "Utilize advanced signature-based and behavioral detection systems to track polymorphic code executions.",
        "improvements": "Enhance detection with heuristic analysis for anomalous file and code execution patterns",
        "mitre_version": "16.1"
    }
