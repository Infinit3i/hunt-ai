def get_content():
    return {
        "id": "T1495",
        "url_id": "T1495",
        "title": "Firmware Corruption",
        "description": "Adversaries may overwrite or corrupt the flash memory contents of system BIOS or other firmware in devices attached to a system in order to render them inoperable or unable to boot, thus denying the availability to use the devices and/or the system. Firmware is software that is loaded and executed from non-volatile memory on hardware devices in order to initialize and manage device functionality. These devices may include the motherboard, hard drive, or video cards. In general, adversaries may manipulate, overwrite, or corrupt firmware in order to deny the use of the system or devices. For example, corruption of firmware responsible for loading the operating system for network devices may render the network devices inoperable. Depending on the device, this attack may also result in data destruction.",
        "tags": ["firmware", "bios", "availability"],
        "tactic": "Impact",
        "protocol": "",
        "os": "Linux, Network, Windows, macOS",
        "tips": [
            "Log attempts to read/write to BIOS and compare against known patching behavior.",
            "Utilize hardware-based protections for firmware.",
            "Monitor firmware updates and BIOS flashing utilities."
        ],
        "data_sources": "Firmware",
        "log_sources": [
            {"type": "Firmware", "source": "Firmware Modification", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Event Logs", "location": "UEFI or BIOS logs", "identify": "Write operations to firmware or unexpected flashing activity."}
        ],
        "destination_artifacts": [],
        "detection_methods": [
            "Detect manipulation or unauthorized access to firmware interfaces.",
            "Use firmware integrity measurement tools to detect changes."
        ],
        "apt": [
            "Trickbot", "Bad Rabbit"
        ],
        "spl_query": [
            "index=firmware_logs message=*write* OR *flash* \n| stats count by device_id, firmware_version, user"
        ],
        "hunt_steps": [
            "Search firmware logs for unexpected flash or write activity.",
            "Identify machines with unapproved firmware versions.",
            "Review user accounts performing firmware updates."
        ],
        "expected_outcomes": [
            "System becomes inoperable due to corrupted firmware.",
            "Network devices fail to boot after firmware manipulation."
        ],
        "false_positive": "Firmware patching during scheduled maintenance may generate similar logs—validate against maintenance windows.",
        "clearing_steps": [
            "Reflash firmware from trusted recovery images if available.",
            "Replace hardware if firmware recovery is not possible.",
            "Update access control policies around firmware-level tools."
        ],
        "clearing_playbook": [
            "https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-ransomware"
        ],
        "mitre_mapping": [
            {"tactic": "Impact", "technique": "T1485", "example": "Corrupting firmware that prevents system boot and data access."}
        ],
        "watchlist": [
            "Unusual firmware flashing or version changes.",
            "Write operations to firmware during off-hours.",
            "Tools like flashrom or vendor-specific BIOS utilities in use."
        ],
        "enhancements": [
            "Enable UEFI Secure Boot and integrity verification.",
            "Deploy hardware root of trust capabilities."
        ],
        "summary": "Firmware corruption renders devices or systems inoperable, posing a serious threat to availability and continuity.",
        "remediation": "Ensure hardware supports firmware integrity protections, apply only signed firmware updates, and restrict firmware-level access.",
        "improvements": "Use secure boot, monitor firmware changes, and establish audit trails for firmware updates.",
        "mitre_version": "16.1"
    }
