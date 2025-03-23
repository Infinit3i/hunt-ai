def get_content():
    return {
        "id": "T1027.012",
        "url_id": "T1027/012",
        "title": "Obfuscated Files or Information: LNK Icon Smuggling",
        "description": "Adversaries may smuggle commands to download malicious payloads past content filters by hiding them within otherwise seemingly benign Windows shortcut files. Windows shortcut files (.LNK) include many metadata fields, including an icon location field (also known as the `IconEnvironmentDataBlock`) designed to specify the path to an icon file that is to be displayed for the LNK file within a host directory. Adversaries may abuse this LNK metadata to download malicious payloads. For example, adversaries have been observed using LNK files as phishing payloads to deliver malware. Once invoked (e.g., Malicious File), payloads referenced via external URLs within the LNK icon location field may be downloaded. These files may also then be invoked by Command and Scripting Interpreter/System Binary Proxy Execution arguments within the target path field of the LNK.",
        "tags": ["LNK Icon Smuggling", "Malware Delivery", "Phishing", "Command Execution"],
        "tactic": "Defense Evasion",
        "protocol": "HTTP(S)",
        "os": "Windows",
        "tips": [
            "Monitor for unusual LNK file creation patterns or modification of LNK file metadata.",
            "Block LNK files from being delivered through phishing or external email systems.",
            "Examine and validate shortcut files for external URL references in the icon location field."
        ],
        "data_sources": "Windows File, Windows File Metadata",
        "log_sources": [
            {"type": "File", "source": "LNK File", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "File", "location": "%SystemRoot%\\System32\\Wbem\\Repository", "identify": "LNK files with external URL payloads"}
        ],
        "destination_artifacts": [
            {"type": "File", "location": "%USERPROFILE%\\Desktop", "identify": "Malicious downloaded payload from LNK link"}
        ],
        "detection_methods": [
            "Detect LNK files with external URLs in icon location fields.",
            "Identify network traffic that corresponds to downloads initiated by LNK files.",
            "Monitor for the execution of LNK files with suspicious file creation timestamps."
        ],
        "apt": ["APT28", "APT29", "Fin7"],
        "spl_query": [
            "| search source=LNK icon_url=*.exe | table file_name, file_path, icon_location"
        ],
        "hunt_steps": [
            "Hunt for LNK files in user directories with suspicious icon location metadata.",
            "Check for external connections initiated by LNK files, especially to uncommon URLs or IPs."
        ],
        "expected_outcomes": [
            "Detection of LNK files attempting to download payloads or executing with suspicious commands."
        ],
        "false_positive": "Legitimate LNK files used for document or application shortcuts, particularly in custom environments.",
        "clearing_steps": [
            "Remove malicious LNK files from affected systems.",
            "Cleanse registry entries associated with the malicious LNK file.",
            "Remove downloaded payloads that were executed via the LNK file."
        ],
        "mitre_mapping": [
            {"tactic": "Execution", "technique": "T1059", "example": "Command-line execution via LNK file"}
        ],
        "watchlist": [
            "Monitor for LNK files with icon URLs pointing to suspicious or unusual external domains."
        ],
        "enhancements": [
            "Improve LNK file detection using regular expression matching for unusual metadata and URL patterns.",
            "Implement strict filtering for files with icon fields that do not match expected formats or origins."
        ],
        "summary": "LNK Icon Smuggling involves using the icon location field in Windows shortcut files to download malicious payloads. This technique may bypass traditional file-based defenses by embedding external URLs within LNK files.",
        "remediation": "Block the use of LNK files with external URLs, especially from untrusted sources, and monitor for such files in email systems.",
        "improvements": "Enhance LNK file scanning capabilities and ensure comprehensive blocking of malicious metadata patterns.",
        "mitre_version": "16.1"
    }
