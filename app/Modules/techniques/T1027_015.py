def get_content():
    return {
        "id": "T1027.015",
        "url_id": "T1027/015",
        "title": "Compression",
        "description": "Adversaries may use compression to obfuscate their payloads or files.",
        "tags": ["obfuscation", "compression", "zip", "rar", "gzip", "evade detection"],
        "tactic": "defense-evasion",
        "protocol": "",
        "os": "Windows, Linux, macOS",
        "tips": [
            "Inspect ZIP and RAR archives for embedded or concatenated payloads.",
            "Use entropy analysis to detect compressed shellcode or binaries.",
            "Monitor for self-extracting archive execution or double extensions."
        ],
        "data_sources": "File",
        "log_sources": [
            {"type": "File", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "File Access Times (MACB Timestamps)", "location": "%TEMP%", "identify": "Compressed archive dropped before payload execution"},
            {"type": "Event Logs", "location": "Security.evtx", "identify": "File creation or process execution logs related to archive tools"}
        ],
        "destination_artifacts": [
            {"type": "Memory Dumps", "location": "Volatile Memory", "identify": "Decompressed shellcode or binaries in memory"}
        ],
        "detection_methods": [
            "Monitor creation or access of ZIP, RAR, and 7z files with suspicious names or in uncommon paths.",
            "Look for high entropy files that deviate from expected patterns for archive contents."
        ],
        "apt": [
            "Higaisa", "Leviathan", "Mofang", "Molerats", "TA2541", "Threat Group-3390"
        ],
        "spl_query": [
            "index=* sourcetype=WinEventLog:* (file_name=*.zip OR file_name=*.rar OR file_name=*.7z) \n| stats count by file_name, user, host"
        ],
        "hunt_steps": [
            "Identify compressed files delivered through email or downloads.",
            "Analyze decompressed contents in sandbox or manually for indicators of malware."
        ],
        "expected_outcomes": [
            "Detection of compressed payloads being staged or executed."
        ],
        "false_positive": "Legitimate users may handle compressed files frequently. Correlate with context like user behavior or origin.",
        "clearing_steps": [
            "del /f /q %TEMP%\\*.zip",
            "del /f /q %TEMP%\\*.rar",
            "Clear recent downloads and clear shellbag artifacts if user interaction is proven malicious."
        ],
        "clearing_playbook": [
            "https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-malware"  
        ],
        "mitre_mapping": [
            {"tactic": "defense-evasion", "technique": "T1027.002", "example": "Encrypted/Encoded File"},
            {"tactic": "execution", "technique": "T1204.002", "example": "Malicious File"}
        ],
        "watchlist": [
            "Archives containing executable content in temp directories",
            "Self-extracting archives from unknown sources"
        ],
        "enhancements": [
            "Enable advanced heuristics in endpoint protection to scan inside compressed files.",
            "Use automated sandboxes to trigger decompression behavior."
        ],
        "summary": "Compression is used to obscure the true nature of files and evade static detection, often in tandem with phishing or exploit delivery.",
        "remediation": "Educate users on risks of opening unknown compressed files and enforce filtering of suspicious archive attachments.",
        "improvements": "Improve endpoint logging and correlation to detect decompression followed by code execution.",
        "mitre_version": "16.1"
    }
