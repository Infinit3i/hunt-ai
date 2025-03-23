def get_content():
    return {
        "id": "T1027.013",
        "url_id": "T1027/013",
        "title": "Obfuscated Files or Information: Encrypted/Encoded File",
        "description": "Adversaries may encrypt or encode files to obfuscate strings, bytes, and other specific patterns to impede detection. Encrypting and/or encoding file content aims to conceal malicious artifacts within a file used in an intrusion.",
        "tags": ["Obfuscation", "Encryption", "Encoding", "Malware", "Defense Evasion"],
        "tactic": "Defense Evasion",
        "protocol": "",
        "os": "Linux, Windows, macOS",
        "tips": [],
        "data_sources": "File: File Creation, File: File Metadata",
        "log_sources": [
            {"type": "File", "source": "File Creation", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "File", "location": "File Metadata", "identify": "Encrypted/Encoded File"}
        ],
        "destination_artifacts": [
            {"type": "File", "location": "File Metadata", "identify": "Encrypted/Encoded File"}
        ],
        "detection_methods": ["Inspect file metadata and content for unusual encoding/encryption patterns"],
        "apt": ["APT33", "Lazarus", "Sodinokibi", "APT28"],
        "spl_query": [],
        "hunt_steps": ["Search for encoded or encrypted files in network shares and endpoint file systems"],
        "expected_outcomes": ["Detection of obfuscated files or payloads"],
        "false_positive": "Legitimate encrypted/encoded files may trigger false positives",
        "clearing_steps": ["Remove obfuscated files and replace with clean versions", "Use decryption tools if necessary"],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1027", "example": "Obfuscated files with encoded malware"}
        ],
        "watchlist": ["Monitor for unusual file creation or encoding/decoding activity"],
        "enhancements": ["Implement additional checks for multiple layers of encryption/encoding"],
        "summary": "Obfuscation of file content through encryption or encoding techniques to evade detection during an intrusion.",
        "remediation": "Implement file scanning and decryption tools to inspect encoded/encrypted files",
        "improvements": "Enhance detection capabilities by monitoring file metadata for anomalous encoding patterns",
        "mitre_version": "16.1"
    }
