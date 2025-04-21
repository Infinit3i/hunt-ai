def get_content():
    return {
        "id": "T1600.002",
        "url_id": "T1600/002",
        "title": "Weaken Encryption: Disable Crypto Hardware",
        "description": "Adversaries may disable a network device’s dedicated hardware-based cryptographic processor in order to weaken the security posture of the system. Encryption hardware in devices like routers, switches, and firewalls is designed to accelerate cryptographic operations and enhance resistance to tampering. \n\nWhen disabled—often via [Modify System Image](https://attack.mitre.org/techniques/T1601)—the device reverts to using less secure and more vulnerable software-based encryption handled by general-purpose processors. This makes encrypted traffic easier to exploit. Attackers frequently pair this technique with [Reduce Key Space (T1600.001)](https://attack.mitre.org/techniques/T1600/001) to reduce the computational requirements for brute-forcing encryption.",
        "tags": ["encryption", "hardware tampering", "firmware manipulation", "crypto bypass", "network compromise"],
        "tactic": "Defense Evasion",
        "protocol": "None (local device tampering)",
        "os": "Network",
        "tips": [
            "Audit firmware and image integrity regularly using checksums and vendor-provided signatures.",
            "Investigate any CLI-based changes to cryptographic settings or modules.",
            "Use secure boot and attestation features to lock firmware and hardware behavior."
        ],
        "data_sources": "File: File Modification",
        "log_sources": [
            {"type": "Firmware/Config Change", "source": "Device CLI or SNMP", "destination": "SIEM or Syslog"},
            {"type": "Hardware Status Logs", "source": "Crypto Engine Monitor", "destination": "Central Monitoring Platform"}
        ],
        "source_artifacts": [
            {"type": "Modified OS Image", "location": "Flash Memory", "identify": "Firmware altered to disable crypto hardware routines"}
        ],
        "destination_artifacts": [
            {"type": "Cryptographic Operation Logs", "location": "Device Memory or Logs", "identify": "Switched from hardware to software crypto"},
            {"type": "Runtime Hardware Flags", "location": "Crypto Status Register", "identify": "Disabled or offline crypto module"}
        ],
        "detection_methods": [
            "Vendor-supported telemetry for crypto engine status.",
            "Compare boot-time hardware crypto initialization logs against baseline behavior.",
            "Monitor CLI access logs for unexpected crypto-related configuration changes."
        ],
        "apt": [
            "Used in conjunction with Modify System Image by actors targeting embedded devices to weaken encryption protections and exfiltrate sensitive data over compromised or weakly encrypted links."
        ],
        "spl_query": "index=network_devices sourcetype=firmware_logs \n| search crypto_module_status=\"disabled\" OR encryption_mode=\"software\" \n| stats count by device_id, time",
        "hunt_steps": [
            "Check cryptographic hardware status via CLI or SNMP OIDs.",
            "Verify image hashes against known-good vendor references.",
            "Scan config files for references disabling crypto modules or offloading settings."
        ],
        "expected_outcomes": [
            "Crypto hardware listed as disabled or unavailable.",
            "Switch to CPU-based encryption noted in logs or performance degradation.",
            "Firmware integrity mismatch compared to signed versions."
        ],
        "false_positive": "Some legacy devices may revert to software encryption due to hardware failure or policy-based configurations during low-load operation.",
        "clearing_steps": [
            "Re-enable crypto hardware via CLI or reset configuration.",
            "Re-flash firmware with a verified image from the vendor.",
            "Reboot device and verify crypto module activation."
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1600.002", "example": "Disabling cryptographic hardware in routers to weaken VPN encryption."}
        ],
        "watchlist": [
            "Logs showing crypto engine not initialized or running in fallback mode.",
            "Repeated access to encryption config sections without corresponding change tickets.",
            "High CPU utilization on devices normally offloading to crypto chips."
        ],
        "enhancements": [
            "Enable hardware attestation for cryptographic modules.",
            "Force hardware-only crypto policy where supported.",
            "Log every change to crypto-related configuration areas with audit trail enforcement."
        ],
        "summary": "Disabling dedicated crypto hardware forces devices to rely on weaker software encryption, opening paths for easier traffic manipulation or decryption.",
        "remediation": "Re-flash device firmware, enable secure boot, and validate crypto hardware functionality post-recovery. Restrict admin CLI access.",
        "improvements": "Deploy firmware integrity scanning tools and hardware attestation systems. Use vendor telemetry features to alert on crypto subsystem downgrades.",
        "mitre_version": "16.1"
    }
