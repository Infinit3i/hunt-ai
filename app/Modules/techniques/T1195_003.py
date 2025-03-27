def get_content():
    return {
        "id": "T1195.003",
        "url_id": "T1195/003",
        "title": "Supply Chain Compromise: Compromise Hardware Supply Chain",
        "description": "Adversaries may manipulate hardware components in products prior to receipt by a final consumer for the purpose of data or system compromise. By modifying hardware or firmware in the supply chain, adversaries can insert a backdoor into consumer networks that may be difficult to detect and give the adversary a high degree of control over the system. Hardware backdoors may be inserted into various devices, such as servers, workstations, network infrastructure, or peripherals.",
        "tags": ["supply chain", "initial access", "hardware tampering", "firmware compromise", "pre-boot manipulation"],
        "tactic": "Initial Access",
        "protocol": "",
        "os": "Linux, Windows, macOS",
        "tips": [
            "Perform detailed physical inspections on inbound hardware.",
            "Use trusted hardware vendors and secure shipping procedures.",
            "Enable secure boot and check firmware integrity."
        ],
        "data_sources": "Sensor Health",
        "log_sources": [
            {"type": "Sensor Health", "source": "", "destination": ""}
        ],
        "source_artifacts": [],
        "destination_artifacts": [],
        "detection_methods": [
            "Monitor host and firmware integrity using trusted platform modules (TPM).",
            "Check for unauthorized changes to BIOS/UEFI or firmware.",
            "Inspect boot sequences for tampering."
        ],
        "apt": [],
        "spl_query": [
            "index=firmware_logs sourcetype=boot_integrity \n| search firmware_modified=true \n| stats count by host, firmware_version"
        ],
        "hunt_steps": [
            "Compare deployed firmware against known secure versions.",
            "Investigate firmware updates pushed outside of authorized channels.",
            "Inspect systems with early boot modifications or BIOS config changes."
        ],
        "expected_outcomes": [
            "Detection of unauthorized hardware or firmware manipulation.",
            "Improved validation procedures in hardware procurement."
        ],
        "false_positive": "Vendor firmware updates may appear suspicious if not centrally documented.",
        "clearing_steps": [
            "Replace affected hardware with verified trusted components.",
            "Reflash firmware with secure, vendor-approved images.",
            "Perform forensic validation of system integrity."
        ],
        "clearing_playbook": [
            "https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-supply-chain"
        ],
        "mitre_mapping": [
            {"tactic": "Persistence", "technique": "T1542.001", "example": "Firmware-based backdoor maintains access even after OS reinstalls."}
        ],
        "watchlist": [
            "Unexpected firmware changes without administrative approval",
            "Boot-time anomalies across systems from the same hardware lot"
        ],
        "enhancements": [
            "Enable secure boot and trusted boot policies.",
            "Deploy hardware attestation mechanisms across endpoints."
        ],
        "summary": "Hardware supply chain compromise enables insertion of stealthy backdoors at a physical level, affecting firmware or components before software even loads.",
        "remediation": "Establish secure procurement processes, validate hardware at receipt, and reflash firmware with verified images.",
        "improvements": "Adopt hardware attestation practices, enforce firmware access controls, and log pre-boot integrity checks.",
        "mitre_version": "16.1"
    }
