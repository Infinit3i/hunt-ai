def get_content():
    return {
        "id": "T1553.005",
        "url_id": "T1553/005",
        "title": "Subvert Trust Controls: Mark-of-the-Web Bypass",
        "description": "Adversaries may abuse specific file formats to subvert Mark-of-the-Web (MOTW) controls. In Windows, downloaded files are tagged with a hidden NTFS Alternate Data Stream (Zone.Identifier) to denote their Internet origin. This MOTW restricts file behavior, such as triggering Protected View in Office or SmartScreen checks for executables. However, adversaries may deliver payloads inside container formats (e.g., .iso, .vhd, .gzip) that strip or avoid MOTW when extracted or mounted, thereby bypassing defenses.",
        "tags": ["MOTW", "Zone.Identifier", "Defense Evasion", "SmartScreen Bypass", "NTFS ADS"],
        "tactic": "Defense Evasion",
        "protocol": "",
        "os": "Windows",
        "tips": [
            "Monitor use of container file formats from untrusted sources.",
            "Audit user interaction with ISO, VHD, and archive formats.",
            "Disable automount features where feasible.",
            "Detect files lacking MOTW extracted from recently downloaded containers."
        ],
        "data_sources": "File: File Creation, File: File Metadata",
        "log_sources": [
            {"type": "File", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "File", "location": "%Downloads%", "identify": "Container file missing Zone.Identifier"}
        ],
        "destination_artifacts": [],
        "detection_methods": [
            "Zone.Identifier presence validation",
            "Event correlation across download, mount, and execution",
            "SmartScreen interaction logs",
            "Extraction/mount activity monitoring"
        ],
        "apt": [
            "TA505",
            "Black Basta"
        ],
        "spl_query": [
            "index=windows_logs source=*Downloads* file_extension IN (iso, vhd, gz, arj)\n| search NOT Zone.Identifier"
        ],
        "hunt_steps": [
            "Identify compressed or image files downloaded from browsers.",
            "Analyze extracted/mounted contents for MOTW absence.",
            "Track subsequent execution attempts of extracted payloads."
        ],
        "expected_outcomes": [
            "Files within containers lack MOTW and bypass SmartScreen",
            "Execution of payloads not subjected to Protected View"
        ],
        "false_positive": "Some internal or legacy tooling may use containerized content without MOTW. Validate based on source, behavior, and risk context.",
        "clearing_steps": [
            "Re-scan contents using MOTW-aware antivirus tools.",
            "Quarantine and re-tag extracted content.",
            "Educate users on risks of running unpacked downloaded files."
        ],
        "clearing_playbook": [
            "https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-phishing"
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1202", "example": "Use of ISO files to avoid MOTW tagging."}
        ],
        "watchlist": [
            "Executable files created without MOTW",
            "ISO and VHD file mounts from Downloads",
            "Unexpected use of archive file extensions"
        ],
        "enhancements": [
            "Integrate MOTW checks in antivirus or EDR routines",
            "Flag container file extractions lacking MOTW propagation"
        ],
        "summary": "Mark-of-the-Web (MOTW) can be bypassed using specific archive and image formats that do not preserve NTFS ADS. This allows adversaries to trick systems into treating untrusted content as safe, circumventing SmartScreen or Protected View.",
        "remediation": "Monitor MOTW usage, validate content from untrusted sources, and block auto-execution of mounted container files.",
        "improvements": "Automate detection of file extractions without MOTW and correlate with download and execution behavior.",
        "mitre_version": "16.1"
    }
