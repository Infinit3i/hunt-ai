def get_content():
    """
    Returns structured content for the BIOS Flashing persistence method.
    """
    return {
        "id": "T1542.001",
        "url_id": "1542/001",
        "title": "System Firmware: BIOS Flashing",
        "tactic": "Persistence",
        "data_sources": "Firmware Version Monitoring, Windows Event Logs, Registry, File Integrity Monitoring",
        "protocol": "N/A",
        "os": "Windows, Linux, macOS",
        "objective": "Detect and mitigate unauthorized BIOS flashing that enables advanced persistence at the firmware level.",
        "scope": "Monitor firmware modifications and unauthorized flashing attempts.",
        "threat_model": "Adversaries may modify the BIOS or UEFI firmware to establish persistent control over a system, executing malicious code before the OS loads.",
        "hypothesis": [
            "Has the BIOS/UEFI firmware been altered from the original manufacturer version?",
            "Are unauthorized BIOS flashing tools being executed on endpoints?",
            "Are there mismatches between firmware integrity checks and vendor-provided binaries?"
        ],
        "tips": [
            "Monitor firmware hashes and compare with known-good versions.",
            "Enable Secure Boot to prevent unauthorized firmware changes.",
            "Audit BIOS/UEFI logs for unexpected modifications."
        ],
        "log_sources": [
            {"type": "Registry", "source": "HKCU\\Software\\OEM\\FirmwareTools", "destination": "Local System"},
            {"type": "Event Logs", "source": "Windows Security Log (Event ID 1100)", "destination": "SIEM"},
            {"type": "Firmware Monitoring", "source": "OEM Firmware Integrity Checks", "destination": "Endpoint Security"}
        ],
        "source_artifacts": [
            {"type": "Executable", "location": "C:\\Windows\\Temp\\", "identify": "Flashing tool binary detected."}
        ],
        "destination_artifacts": [
            {"type": "Firmware", "location": "BIOS/UEFI Chip", "identify": "Unauthorized firmware modification."}
        ],
        "detection_methods": [
            "Monitor registry keys for BIOS flashing tools.",
            "Track Event ID 1100 (Windows Audit Log Cleared) before firmware changes.",
            "Compare firmware versions with manufacturer-provided binaries."
        ],
        "apt": ["G0025", "G0019"],
        "spl_query": [
            "index=windows EventCode=1100 | stats count by host", 
            "index=firmware integrity_check=failure | stats count by device"
        ],
        "hunt_steps": [
            "Check SIEM for Event ID 1100 indicating audit log clearing.",
            "Correlate with firmware integrity check failures.",
            "Investigate registry modifications for flashing tools."
        ],
        "expected_outcomes": [
            "Unauthorized BIOS flashing detected: Initiate incident response.",
            "No malicious activity found: Continue routine firmware integrity monitoring."
        ],
        "false_positive": "Legitimate BIOS updates from the vendor may trigger detection events. Validate against official release notes.",
        "clearing_steps": [
            "Restore BIOS/UEFI firmware to factory default.",
            "Reflash the firmware with a trusted OEM version.",
            "Enable Secure Boot and prevent unauthorized flashing."
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1562.001 (Disable Security Tools)", "example": "Adversaries may disable firmware protections to facilitate flashing."}
        ],
        "watchlist": [
            "Monitor registry keys associated with flashing utilities.",
            "Track audit log clearing before firmware modifications.",
            "Ensure firmware integrity checks are regularly performed."
        ],
        "enhancements": [
            "Implement firmware integrity monitoring solutions.",
            "Restrict BIOS flashing to authorized administrators only.",
            "Enforce Secure Boot policies across endpoints."
        ],
        "summary": "Monitor and prevent unauthorized BIOS flashing attempts to mitigate firmware-level persistence.",
        "remediation": "Restore original firmware, enable Secure Boot, and enforce flashing restrictions.",
        "improvements": "Strengthen firmware integrity monitoring and enforce strict BIOS update policies."
    }