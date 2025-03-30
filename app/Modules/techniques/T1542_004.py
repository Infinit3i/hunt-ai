def get_content():
    return {
        "id": "T1542.004",
        "url_id": "T1542/004",
        "title": "Pre-OS Boot: ROMMONkit",
        "description": "ROMMONkit refers to an adversary’s abuse of the ROM Monitor (ROMMON), a firmware-level bootloader in Cisco devices, to implant persistent malware. ROMMON functions during early system initialization and, if replaced or altered, provides the adversary low-level, stealthy, and highly persistent access. This is analogous to UEFI/BIOS implants in endpoints, but within the network device domain. Adversaries can use unauthorized firmware updates to overwrite the ROMMON image and hijack the device's boot process.",
        "tags": ["rommonkit", "firmware implant", "bootloader", "T1542.004", "Cisco", "network persistence", "defense evasion", "Synful Knock"],
        "tactic": "Defense Evasion, Persistence",
        "protocol": "",
        "os": "Network",
        "tips": [
            "Use Cisco Secure Boot and image verification features where supported.",
            "Monitor for unauthorized ROMMON upgrade attempts, particularly via TFTP.",
            "Deploy Cisco IOS Software Integrity Assurance features where available."
        ],
        "data_sources": "Firmware: Firmware Modification",
        "log_sources": [
            {"type": "Firmware", "source": "", "destination": "ROMMON"},
            {"type": "Process", "source": "TFTP or upgrade interfaces", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Malicious ROMMON", "location": "Flash/ROM firmware", "identify": "Bootloader version mismatch or tampered checksum"}
        ],
        "destination_artifacts": [
            {"type": "Adversary ROMMON firmware", "location": "Boot flash image", "identify": "Unauthorized firmware signature or checksum"}
        ],
        "detection_methods": [
            "Monitor ROMMON image hash against expected vendor-provided checksums.",
            "Watch for unauthorized or undocumented firmware upgrade attempts via TFTP or CLI.",
            "Use Cisco IOS Image File Verification (IFV) to validate image integrity."
        ],
        "apt": [
            "Synful Knock – known for implanting a persistent ROMMONkit on Cisco routers, modifying bootloader behavior and enabling backdoor access without traditional indicators of compromise."
        ],
        "spl_query": [
            'index=network_devices\n| search firmware_change=true ROMMON',
            'index=syslog OR index=network\n| search "TFTP firmware upload" OR "ROMMON upgrade"',
            'index=config\n| search command="upgrade rommon" OR file_hash!=expected_hash'
        ],
        "hunt_steps": [
            "Collect current ROMMON version and image hashes from affected Cisco devices.",
            "Compare image metadata and cryptographic hash to known trusted ROMMON firmware.",
            "Validate router integrity using Cisco IOS Secure Boot and IFV audit logs."
        ],
        "expected_outcomes": [
            "Detection of unauthorized bootloader modifications.",
            "Prevention of stealthy persistent implants via firmware validation.",
            "Identification of APT-like stealth access in edge routers or network infrastructure."
        ],
        "false_positive": "Planned ROMMON upgrades may show similar artifacts. Validate via change control documentation and vendor release alignment.",
        "clearing_steps": [
            "Reflash device firmware from secure media provided by the vendor.",
            "Perform full reset and reconfiguration using verified boot images.",
            "Contact Cisco TAC to verify secure boot chain if compromise is suspected."
        ],
        "mitre_mapping": [
            {"tactic": "Persistence", "technique": "T1542.004", "example": "Synful Knock modified ROMMON firmware in Cisco routers to establish long-term, covert access."}
        ],
        "watchlist": [
            "Unauthorized firmware write attempts",
            "ROMMON hash mismatches post-boot",
            "Undocumented ROMMON versions observed in inventory"
        ],
        "enhancements": [
            "Automate firmware integrity hash checks for all network gear.",
            "Deploy telemetry sensors on edge routers for boot-time anomalies.",
            "Use Cisco IOS Change Control and Image File Integrity verification features."
        ],
        "summary": "ROMMONkit represents a stealthy and persistent adversary technique that leverages network device boot firmware (e.g., Cisco ROMMON) to implant adversarial code. It can evade traditional detection and grant long-term unauthorized access at the hardware initialization layer.",
        "remediation": "Reflash ROMMON with vendor-verified images. Use Secure Boot features and involve Cisco if compromise is suspected. Validate hash values of boot images periodically.",
        "improvements": "Incorporate hardware integrity validation into your routine security posture for all critical network gear.",
        "mitre_version": "16.1"
    }
