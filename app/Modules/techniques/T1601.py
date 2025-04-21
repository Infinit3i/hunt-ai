def get_content():
    return {
        "id": "T1601",
        "url_id": "T1601",
        "title": "Modify System Image",
        "description": "Adversaries may make changes to the operating system image of embedded network devices in order to evade detection, disable defenses, or introduce new capabilities. These devices often run monolithic operating systems where most system functions are encapsulated in a single firmware file.\n\nAttackers may:\n- Modify the firmware **in storage**, replacing the OS image file to execute malicious changes after the next boot.\n- Modify the system **in memory**, directly altering the running OS, which may be used for evasion or temporary capabilities that disappear after reboot.\n\nChanges may be used alone or in combination with:\n- [Patch System Image (T1601.001)](https://attack.mitre.org/techniques/T1601/001): Altering OS instructions to disable security or add adversarial logic.\n- [Downgrade System Image (T1601.002)](https://attack.mitre.org/techniques/T1601/002): Installing an older, more vulnerable OS version to bypass security improvements.",
        "tags": ["firmware manipulation", "network devices", "embedded systems", "monolithic OS", "defense evasion"],
        "tactic": "Defense Evasion",
        "protocol": "TFTP, FTP, SCP, SSH, Console",
        "os": "Network",
        "tips": [
            "Validate firmware integrity via cryptographic hash comparisons against vendor-provided values.",
            "Secure firmware update paths and restrict administrative interface access.",
            "Use boot integrity mechanisms (e.g., Secure Boot) when supported."
        ],
        "data_sources": "File: File Modification",
        "log_sources": [
            {"type": "Firmware Logs", "source": "Device Storage", "destination": "Central Log Aggregator"},
            {"type": "Console Access", "source": "Terminal or SSH Session", "destination": "Bastion Host"},
            {"type": "Runtime Integrity Tools", "source": "Memory Validation Interface", "destination": "Vendor Debugging Toolkit"}
        ],
        "source_artifacts": [
            {"type": "Modified OS Image", "location": "Flash/TFTP Server", "identify": "Malicious version used to replace original firmware"},
            {"type": "Live Memory Patches", "location": "Runtime Memory", "identify": "Temporary in-memory tampering"}
        ],
        "destination_artifacts": [
            {"type": "Altered Firmware File", "location": "Device Flash Memory", "identify": "Updated boot image with adversarial changes"},
            {"type": "Spoofed Version Output", "location": "CLI Interfaces", "identify": "Deceptive versioning to mislead operators"}
        ],
        "detection_methods": [
            "Checksum validation of the current image against a known-good reference from the vendor.",
            "CLI version checks compared to expected baselines.",
            "Memory validation using vendor-assisted forensic tools."
        ],
        "apt": [
            "APT actors using techniques like [Synful Knock](https://www.cisco.com/c/en/us/about/security-center/ios-rootkits.html) to persist and hide in routers through OS modification."
        ],
        "spl_query": "index=device_logs sourcetype=firmware_operations \n| search event_type=\"firmware_replace\" OR \"os_boot_change\" \n| stats count by device_id, firmware_version, checksum",
        "hunt_steps": [
            "Collect firmware versions across network appliances and compare against approved versions.",
            "Scan flash memory for non-standard image names or boot configurations.",
            "Engage vendor technical support for deep memory inspection if compromise is suspected."
        ],
        "expected_outcomes": [
            "Firmware image mismatch or unknown version string.",
            "CLI or SNMP output inconsistencies around OS version or checksum.",
            "Devices booting with unapproved or old firmware images."
        ],
        "false_positive": "Legitimate firmware upgrades or rollback testing can mimic this behavior if not tightly controlled or documented.",
        "clearing_steps": [
            "Reinstall validated firmware from the vendor.",
            "Wipe and reconfigure boot settings to default.",
            "Verify image integrity before and after reload."
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1601", "example": "Replacing network OS image with adversarial version to disable logging."}
        ],
        "watchlist": [
            "Unexpected firmware image replacements or checksum mismatches.",
            "Devices booting without scheduled firmware upgrade activities.",
            "Direct access to boot configuration commands."
        ],
        "enhancements": [
            "Enforce image signing and validation for all bootable firmware.",
            "Automate periodic validation of system versions and checksums.",
            "Use separate control planes for firmware access versus user activity."
        ],
        "summary": "Modifying the system image of embedded devices grants adversaries persistence and stealth. Changes may occur live in memory or on persistent storage and typically aim to disable defenses or introduce malicious behavior.",
        "remediation": "Re-flash the OS using a clean image, validate hash, lock boot settings, and consult vendor support for deep inspection.",
        "improvements": "Implement boot attestation checks, segment update traffic, and maintain a secure audit trail of all firmware interactions.",
        "mitre_version": "16.1"
    }
