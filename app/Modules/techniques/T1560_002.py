def get_content():
    return {
        "id": "T1560.002",
        "url_id": "1560/002",
        "title": "Archive Collected Data: Archive via Library",
        "description": "An adversary may compress or encrypt data that is collected prior to exfiltration using 3rd party libraries. Many libraries exist that can archive data, including Python rarfile, libzip, and zlib. Most libraries include functionality to encrypt and/or compress data. Some archival libraries are preinstalled on systems, such as bzip2 on macOS and Linux, and zip on Windows. Note that the libraries are different from the utilities. The libraries can be linked against when compiling, while the utilities require spawning a subshell, or a similar execution mechanism.",
        "tags": ["archive", "compression", "encryption", "exfiltration"],
        "tactic": "Collection",
        "protocol": "File",
        "os": "Linux, Windows, macOS",
        "tips": [
            "Monitor processes for accesses to known archival libraries.",
            "Detect writing of files with extensions and/or headers associated with compressed or encrypted file types.",
            "Focus detection efforts on follow-on exfiltration activity."
        ],
        "data_sources": "File: File Creation, Script: Script Execution",
        "log_sources": [
            {"type": "File", "source": "File Creation", "destination": "Log Analysis"},
            {"type": "Script", "source": "Script Execution", "destination": "Security Monitoring"}
        ],
        "source_artifacts": [
            {"type": "File", "location": "/var/log/archive.log", "identify": "Compressed data logs"}
        ],
        "destination_artifacts": [
            {"type": "File", "location": "/tmp/encrypted.zip", "identify": "Encrypted archive"}
        ],
        "detection_methods": ["File signature analysis", "Process monitoring", "Network traffic analysis"],
        "apt": ["Turla", "Lazarus Group", "APT29"],
        "spl_query": [
            "index=* source=*file_creation.log* \n| search archive OR compress OR encrypt"
        ],
        "hunt_steps": [
            "Identify unusual compression activities.",
            "Analyze system logs for use of known archival libraries.",
            "Monitor network activity for exfiltration of archived files."
        ],
        "expected_outcomes": [
            "Detection of unauthorized file archiving.",
            "Identification of malicious data compression attempts."
        ],
        "false_positive": "Legitimate use of compression libraries by administrators and software installers.",
        "clearing_steps": [
            "Remove unauthorized archive files.",
            "Block the use of suspicious compression tools.",
            "Monitor access to archival libraries more strictly."
        ],
        "mitre_mapping": [
            {"tactic": "Exfiltration", "technique": "T1041", "example": "Exfiltration Over C2 Channel"}
        ],
        "watchlist": ["Unusual file compression activities", "Unexpected use of archiving libraries"],
        "enhancements": ["Use advanced heuristics to detect custom encryption techniques."],
        "summary": "Adversaries may use libraries to compress or encrypt collected data before exfiltration to evade detection.",
        "remediation": "Monitor and block unauthorized usage of archival libraries, ensure encrypted files are inspected for threats.",
        "improvements": "Enhance monitoring by integrating machine learning models for anomaly detection in archival behavior."
    }
