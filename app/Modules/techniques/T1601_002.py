def get_content():
    return {
        "id": "T1601.002",
        "url_id": "T1601/002",
        "title": "Modify System Image: Downgrade System Image",
        "description": "Adversaries may install an older version of a network device's operating system to weaken security controls and defenses. Older firmware versions often include outdated encryption algorithms, fewer security features, or unpatched vulnerabilities. This downgrade can be used to support evasion or prepare the system for further malicious modifications such as [Patch System Image](https://attack.mitre.org/techniques/T1601/001). \n\nOn embedded systems and network appliances, adversaries may replace the stored system image file with an older version. This may involve using TFTP/FTP/SCP or web interfaces to upload the outdated OS and then configuring the device to boot from it upon restart. Devices like routers or firewalls may allow these actions with sufficient administrative access, often achieved through prior compromise or misconfigurations.\n\nExamples include Synful Knock, where attackers used a malicious bootloader to manipulate Cisco IOS devices, and downgrade them to facilitate additional payloads.",
        "tags": ["firmware", "downgrade", "network", "evasion", "encryption bypass", "firmware tampering"],
        "tactic": "Defense Evasion",
        "protocol": "TFTP, FTP, SCP, HTTP, SSH",
        "os": "Network",
        "tips": [
            "Enforce secure boot and image signing mechanisms.",
            "Restrict firmware uploads to validated personnel and IPs.",
            "Regularly audit firmware version across all critical network appliances."
        ],
        "data_sources": "File: File Modification",
        "log_sources": [
            {"type": "Device Configuration Logs", "source": "Network Device", "destination": "Syslog Server"},
            {"type": "Firmware Update Logs", "source": "Router/Switch", "destination": "NMS or SIEM"},
            {"type": "Command Logs", "source": "SSH or Console Access", "destination": "Terminal/Remote Session Log"}
        ],
        "source_artifacts": [
            {"type": "Legacy OS Image", "location": "TFTP Server", "identify": "Used for downgrade operation"},
            {"type": "Config File", "location": "Boot Parameters", "identify": "Modified to point to older OS"},
            {"type": "Remote Session Logs", "location": "Console History", "identify": "May indicate downgrade command issued"}
        ],
        "destination_artifacts": [
            {"type": "Modified System Image", "location": "Flash Memory", "identify": "Replaces updated OS with downgraded one"},
            {"type": "Device Restart", "location": "System Reboot Log", "identify": "Applies downgrade on next boot"}
        ],
        "detection_methods": [
            "Monitor firmware version changes and compare to expected versions.",
            "Use cryptographic integrity checks on firmware images.",
            "Correlate system reboots with firmware replacement or abnormal image paths."
        ],
        "apt": [
            "Synful Knock: Used downgrade tactics to inject persistent implants on Cisco devices.",
            "APT28: Known to tamper with embedded systems and network infrastructure for persistence."
        ],
        "spl_query": "index=network_logs sourcetype=\"device:update\" \n| stats latest(firmware_version) by device_id \n| where firmware_version IN [\"12.1\", \"12.0\", \"11.x\"]",
        "hunt_steps": [
            "Query firmware version across network appliances.",
            "Look for administrative actions or file transfers involving system images.",
            "Audit for restarts or boot logs that reference alternate images."
        ],
        "expected_outcomes": [
            "Devices running older firmware than the enterprise baseline.",
            "Indicators of evasion due to loss of logging or security visibility.",
            "Image files present that differ from current verified vendor distributions."
        ],
        "false_positive": "Legitimate firmware rollback due to compatibility issues or emergency reversion may be mistaken as malicious.",
        "clearing_steps": [
            "Restore validated firmware version from vendor.",
            "Reboot system into secure boot mode (if supported).",
            "Re-image affected system with a cryptographically signed OS."
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1601.002", "example": "Synful Knock firmware downgrade for persistent implant"}
        ],
        "watchlist": [
            "Firmware version mismatches with golden image",
            "TFTP/FTP file transfers of .bin/.img files to routers",
            "Config changes to boot path variables"
        ],
        "enhancements": [
            "Deploy signed firmware and enable secure boot features.",
            "Implement firmware monitoring with version enforcement.",
            "Restrict downgrade capability to physical console access only."
        ],
        "summary": "Firmware downgrading reduces defenses on critical devices, often disabling modern security features. This tactic may be used standalone or paired with firmware patching for full control.",
        "remediation": "Re-flash affected systems with vendor-signed latest firmware, validate integrity, and enforce downgrade prevention policies.",
        "improvements": "Integrate firmware validation with NMS, enforce ACLs on update protocols (e.g., disable TFTP), and monitor for boot parameter tampering.",
        "mitre_version": "16.1"
    }
