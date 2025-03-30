def get_content():
    return {
        "id": "T1542",
        "url_id": "T1542",
        "title": "Pre-OS Boot",
        "description": "Adversaries may abuse Pre-OS Boot mechanisms, such as the BIOS or UEFI, to gain persistence below the operating system layer. This method enables attackers to execute malicious code before the OS loads, bypassing many traditional security defenses like antivirus, EDR, and file monitoring solutions. Firmware-based implants can be stealthy, long-lived, and extremely difficult to detect or remove without physical access or specialized tools.",
        "tags": ["persistence", "defense evasion", "firmware", "UEFI", "BIOS", "bootkit", "pre-boot", "T1542", "low-level"],
        "tactic": "Defense Evasion, Persistence",
        "protocol": "",
        "os": "Linux, Network, Windows, macOS",
        "tips": [
            "Compare current firmware/bootloader hashes against known-good baselines.",
            "Utilize CHIPSEC or vendor-specific tools to audit BIOS/UEFI integrity.",
            "Enable Secure Boot and TPM to help detect unauthorized modifications."
        ],
        "data_sources": "Command: Command Execution, Drive: Drive Modification, Driver: Driver Metadata, Firmware: Firmware Modification, Network Traffic: Network Connection Creation, Process: OS API Execution",
        "log_sources": [
            {"type": "Firmware Integrity", "source": "TPM", "destination": ""},
            {"type": "Drive Access", "source": "Pre-OS firmware", "destination": ""},
            {"type": "Network Traffic", "source": "", "destination": "C2"},
            {"type": "Process Monitoring", "source": "Bootloader interaction", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Firmware Image", "location": "System board EEPROM", "identify": "UEFI/BIOS modification"},
            {"type": "Boot Records", "location": "Disk MBR/GPT sectors", "identify": "Changes to boot loader or bootkits"}
        ],
        "destination_artifacts": [
            {"type": "C2 Communication", "location": "Network logs", "identify": "Early boot beaconing over hidden protocols"},
            {"type": "Persistence Components", "location": "UEFI variables or drivers", "identify": "Bootloader hooks or rogue DXE drivers"}
        ],
        "detection_methods": [
            "Compare firmware images against golden snapshots using tools like CHIPSEC.",
            "Monitor for unexplained boot record modifications.",
            "Audit firmware update events and drivers loaded during early boot."
        ],
        "apt": [
            "Sednit (APT28/Fancy Bear)",  # Used LoJax to persist in UEFI
            "APT41",                      # Explored bootkits and low-level access in espionage campaigns
            "Equation Group",            # Known for firmware implants like EquationDrug and GrayFish
            "Strider",                   # Used boot-level stealth mechanisms
            "MosaicRegressor",           # UEFI rootkit identified in 2020
            "Lojax/LoJax"                # A UEFI implant used by APT28
        ],
        "spl_query": [
            'index=bootlogs OR index=sysmon EventCode=1 OR EventCode=6\n| search image_path="*boot*" OR description="UEFI*" OR command_line="*fwupd*"',
            'index=network sourcetype=packet_capture\n| search dns_query="*fw-update*" OR dns_query="*uefi*"',
            'index=edr process_name="fwupdate.exe" OR command_line="*bios*" OR command_line="*flash*"\n| stats count by host, user, command_line'
        ],
        "hunt_steps": [
            "Extract and hash UEFI/BIOS images and compare with vendor reference firmware.",
            "Check boot sectors for unknown or modified bootloaders.",
            "Review logs for unexpected firmware updates or drive accesses."
        ],
        "expected_outcomes": [
            "Detection of firmware implants or unauthorized bootloader changes.",
            "Identification of low-level persistence techniques outside the OS.",
            "Forensic artifacts indicating compromise below kernel level."
        ],
        "false_positive": "Firmware updates by OEM tools or system patches may show similar indicators. Validate by checking digital signatures and update logs.",
        "clearing_steps": [
            "Flash known-good firmware using physical tools or vendor utilities.",
            "Reset BIOS/UEFI configuration and enable Secure Boot.",
            "Perform forensic bootloader wipe and reinstall OS if tampering is detected."
        ],
        "mitre_mapping": [
            {"tactic": "Persistence", "technique": "T1542", "example": "APT28 used LoJax to implant a UEFI rootkit on compromised hosts, persisting even after disk reformat."}
        ],
        "watchlist": [
            "Bootloader modification activity",
            "Unsigned firmware or early boot drivers",
            "Unexpected usage of fwupdate or similar firmware utilities"
        ],
        "enhancements": [
            "Use TPM measurements and Secure Boot attestation.",
            "Deploy firmware scanning tools like CHIPSEC periodically.",
            "Log and alert on unauthorized firmware or bootloader changes."
        ],
        "summary": "Pre-OS Boot abuse grants deep persistence by injecting into BIOS or UEFI firmware. Such implants operate below OS-level defenses and require hardware-assisted detection.",
        "remediation": "Implement firmware integrity monitoring, use Secure Boot, isolate affected devices for forensic recovery, and work with OEMs for full remediation.",
        "improvements": "Enforce signed firmware updates, monitor early-boot execution chains, and integrate boot validation into incident response plans.",
        "mitre_version": "16.1"
    }
