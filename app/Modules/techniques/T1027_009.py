def get_content():
    return {
        "id": "T1027.009",
        "url_id": "T1027/009",
        "title": "Obfuscated Files or Information: Embedded Payloads",
        "tactic": "Defense Evasion",
        "data_sources": "File: File Creation, File: File Metadata",
        "protocol": "",
        "os": "Linux, Windows, macOS",
        "objective": "Conceal malicious payloads inside seemingly benign files to avoid detection",
        "scope": "Files such as executables, scripts, or documents containing hidden or injected payloads",
        "threat_model": "Adversaries embed payloads to evade static analysis, signature detection, and trust controls",
        "hypothesis": [
            "A benign binary was modified to carry an embedded secondary payload",
            "A run-only script contains additional malicious content hidden within its structure",
            "A document contains embedded executables or encoded payloads for later execution"
        ],
        "log_sources": [
            {"type": "File", "source": "", "destination": ""}
        ],
        "detection_methods": [
            "Entropy-based anomaly detection in file contents",
            "Behavioral sandboxing of suspicious files",
            "Scanning overlays or nested file content"
        ],
        "spl_query": [
            'index=sysmon EventCode=11 TargetFilename="*.exe" OR TargetFilename="*.dll"\n| eval size_mb=len/1024/1024\n| where size_mb > 10\n| stats values(TargetFilename) as Files by Computer',
            'index=main sourcetype=windows* (process_name="powershell.exe" OR process_name="wscript.exe")\n| search CommandLine="*-EncodedCommand*" OR CommandLine="*-e *"\n| stats count by user, host, CommandLine'
        ],
        "hunt_steps": [
            "Identify binaries with appended or overlay content",
            "Detect files that write or extract additional executables or scripts",
            "Analyze run-only formats like stripped AppleScripts or packed PS1",
            "Look for process injection behaviors where child processes originate from non-standard parent binaries"
        ],
        "expected_outcomes": [
            "Detection of embedded payloads in binaries or scripts",
            "Identification of malicious activity from trusted-looking files",
            "Correlated alerts based on post-execution behavior (e.g., network callbacks or lateral movement)"
        ],
        "clearing_steps": [
            "Quarantine embedded payloads and extract contents for sandbox analysis",
            "Hash and ban known embedded samples across endpoints",
            "Hunt for similar file structures or overlays across the enterprise"
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1140", "example": "Payloads are extracted and deobfuscated during runtime"},
            {"tactic": "Defense Evasion", "technique": "T1055", "example": "Embedded payloads injected into trusted processes"}
        ],
        "watchlist": [
            "Executables with suspicious size or dual extensions",
            "Run-only scripts or obfuscated PowerShell files",
            "Signed binaries that suddenly exhibit malicious behavior"
        ],
        "enhancements": [
            "Enable file scanning for appended data after EOF",
            "Deploy YARA rules to catch embedded signatures or overlays",
            "Use endpoint tools to detect spawning of unexpected processes"
        ],
        "summary": "Adversaries may embed payloads within other benign files such as executables, scripts, or documents. These payloads can be extracted or injected at runtime, allowing them to bypass content filters, digital signature verification, or static inspection.",
        "remediation": "Use static and behavioral analysis to dissect embedded content. Implement YARA and sandbox rules to flag known obfuscation techniques.",
        "improvements": "Improve detection of overlay payloads in signed binaries, track file size anomalies, and train analysts on identifying non-obvious payload carriers.",
        "false_positive": "Some legitimate applications may use embedding (e.g., installation packages), so alerting should be paired with behavioral analysis.",
        "tags": [
            "defense evasion", "obfuscation", "payload injection", "embedded malware", "staged execution", "overlays", "fileless attacks"
        ]
    }
