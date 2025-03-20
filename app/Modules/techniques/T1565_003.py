def get_content():
    return {
        "id": "T1565.003",  # Tactic Technique ID
        "url_id": "1565/003",  # URL segment for technique reference
        "title": "Data Manipulation: Runtime Data Manipulation",  # Name of the attack technique
        "description": "Adversaries may modify systems to manipulate data at runtime, threatening integrity and influencing business processes or decision making. They may alter application binaries or use techniques such as changing default file associations or masquerading to achieve these effects.",  # Simple description
        "tags": [
            "Data Manipulation",
            "Runtime Data Manipulation",
            "Integrity",
            "APT38",
            "Lazarus",
            "FireEye APT38 Oct 2018",
            "DOJ Lazarus Sony 2018",
            "Masquerading",
            "Change Default File Association",
            "Impact"
        ],
        "tactic": "Impact",  # Associated MITRE ATT&CK tactic
        "protocol": "Various",  # Protocol used in the attack technique
        "os": "Linux, Windows, macOS",  # Targeted operating systems
        "tips": [
            "Inspect important application binary file hashes, locations, and modifications for suspicious/unexpected values",
            "Monitor for unexpected changes to file associations or renamed executables",
            "Implement strong code signing and integrity checks for critical application binaries"
        ],
        "data_sources": "File: File Creation, File: File Deletion, File: File Metadata, File: File Modification, Process: OS API Execution",  # Data sources
        "log_sources": [],
        "source_artifacts": [],
        "destination_artifacts": [],
        "detection_methods": [
            "File integrity monitoring to detect unauthorized modifications",
            "Process monitoring to identify unusual file association changes",
            "Code signing verification to detect tampered binaries"
        ],
        "apt": [
            "APT38",
            "Lazarus"
        ],
        "spl_query": [],
        "hunt_steps": [
            "Search for mismatched file hashes in critical applications",
            "Check system logs for repeated attempts to change file associations or rename executables",
            "Correlate any suspicious binary modifications with user or process context"
        ],
        "expected_outcomes": [
            "Identification of malicious runtime data manipulations",
            "Detection of unauthorized binary alterations",
            "Discovery of masquerading or file association changes"
        ],
        "false_positive": "Legitimate patching or software updates may modify application binaries. Verify changes align with authorized maintenance windows.",
        "clearing_steps": [
            "Restore tampered binaries from trusted backups",
            "Revert unauthorized changes to file associations or system configurations",
            "Review and revoke privileges for compromised accounts"
        ],
        "mitre_mapping": [
            {
                "tactic": "Persistence",
                "technique": "Change Default File Association (T1546.001)",
                "example": "Manipulating default file associations to redirect application execution"
            },
            {
                "tactic": "Defense Evasion",
                "technique": "Masquerading (T1036)",
                "example": "Renaming or altering legitimate binaries to evade detection"
            }
        ],
        "watchlist": [
            "Unexpected modifications to high-value application binaries",
            "Sudden changes to file associations for critical data types",
            "Frequent renaming of system executables"
        ],
        "enhancements": [
            "Implement multi-factor authentication for privileged or specialized software access",
            "Use version control and digital signatures for critical binaries"
        ],
        "summary": "Runtime data manipulation allows adversaries to alter how information is displayed or processed in real-time, undermining data integrity and potentially impacting organizational decisions.",
        "remediation": "Adopt strict code signing, integrity checks, and least privilege principles. Monitor file associations and binaries for unauthorized changes, and maintain robust backups for rapid recovery.",
        "improvements": "Regularly validate the integrity of critical application binaries and monitor system logs for anomalous file changes or association modifications. Enforce strong access controls on specialized software."
    }
