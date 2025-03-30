def get_content():
    return {
        "id": "T1542.002",
        "url_id": "T1542/002",
        "title": "Pre-OS Boot: Component Firmware",
        "description": "Adversaries may modify firmware of individual system components—such as hard drives, network adapters, GPUs, or peripheral devices—to establish stealthy persistence and evade host-level defenses. Unlike system firmware like BIOS or UEFI, component firmware often lacks integrity checking or visibility to standard monitoring tools, making it an ideal vector for long-term control.",
        "tags": ["firmware", "component", "persistence", "defense evasion", "pre-OS", "T1542.002", "SMART", "Cyclops Blink", "Equation Group"],
        "tactic": "Defense Evasion, Persistence",
        "protocol": "",
        "os": "Linux, Windows, macOS",
        "tips": [
            "Use SMART telemetry and Smartmontools to baseline device behavior.",
            "Compare component firmware hashes against known-good images from vendors.",
            "Investigate unusual partition table entries or firmware update tools run from host."
        ],
        "data_sources": "Driver: Driver Metadata, Firmware: Firmware Modification, Process: OS API Execution",
        "log_sources": [
            {"type": "Driver", "source": "Component firmware driver", "destination": ""},
            {"type": "Firmware Logs", "source": "", "destination": ""},
            {"type": "Process", "source": "Firmware update utility", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Firmware Tools", "location": "C:\\ or /usr/bin/", "identify": "Non-OEM update utilities"},
            {"type": "SMART Logs", "location": "/var/log/smartd.log", "identify": "Unexpected reallocated sectors or firmware anomalies"}
        ],
        "destination_artifacts": [
            {"type": "Malicious Firmware", "location": "Component memory (e.g., HDD controller, NIC EEPROM)", "identify": "Stealth persistence payload"},
            {"type": "Altered Partition Tables", "location": "Disk structure", "identify": "Hidden storage regions"}
        ],
        "detection_methods": [
            "Use Smartmontools to detect anomalies in hard drive firmware and behavior.",
            "Compare component firmware to known-good baselines using vendor tools or forensic utilities.",
            "Inspect disk structure and memory regions for rogue partitions or non-standard data blocks."
        ],
        "apt": [
            "Equation Group – known to leverage HDD/SSD firmware implants (per Kaspersky research).",
            "Sandworm (Cyclops Blink) – deployed malicious firmware to WatchGuard and ASUS devices.",
            "Slingshot – used router firmware manipulation for persistence and covert command & control."
        ],
        "spl_query": [
            'index=firmware OR index=drivers\n| search path="*fwupdate*" OR description="*firmware*"',
            'index=oslogs\n| search command_line="*smartctl*" OR message="firmware version mismatch"',
            'index=forensics\n| search artifact="MBR" OR artifact="partition" action="unexpected entry"'
        ],
        "hunt_steps": [
            "Collect component firmware images via vendor or forensic tools.",
            "Extract SMART logs and look for reallocated sectors or critical warnings.",
            "Compare against known hashes from trusted firmware versions.",
            "Inspect disk partition tables and MBR/GPT for signs of tampering."
        ],
        "expected_outcomes": [
            "Detection of unauthorized firmware updates on components.",
            "Identification of suspicious hardware behavior (e.g., SMART errors).",
            "Evidence of persistence across reimages or drive wipes."
        ],
        "false_positive": "Legitimate firmware updates or degraded hardware triggering SMART warnings can cause benign anomalies. Verify updates through vendor channels and review hardware lifecycle history.",
        "clearing_steps": [
            "Replace compromised components (e.g., HDD, NIC, embedded controllers).",
            "Reflash known-good firmware using OEM tools (if available).",
            "Isolate system from network and investigate surrounding assets for firmware propagation."
        ],
        "mitre_mapping": [
            {"tactic": "Persistence", "technique": "T1542.002", "example": "Equation Group malware modified HDD firmware to maintain covert access across reimaging."}
        ],
        "watchlist": [
            "Devices with anomalous SMART telemetry",
            "Access to vendor-specific firmware flashing tools",
            "Firmware not matching OEM baselines"
        ],
        "enhancements": [
            "Implement strict inventory of firmware versions across critical components.",
            "Set up alerts for unauthorized firmware access or updates from userland.",
            "Deploy host firmware attestation where possible."
        ],
        "summary": "Component firmware manipulation offers adversaries deep persistence and stealth. Malicious firmware implants in hard drives, NICs, or embedded components can evade detection while surviving OS reinstalls or disk replacements.",
        "remediation": "Where flashing tools fail, replace affected hardware. Restore clean firmware from OEM repositories. Block untrusted firmware utilities at endpoint level.",
        "improvements": "Incorporate firmware integrity verification into asset monitoring tools. Educate incident responders on handling low-level hardware threats.",
        "mitre_version": "16.1"
    }
