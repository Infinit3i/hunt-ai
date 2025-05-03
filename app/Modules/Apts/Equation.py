def get_content():
    return {
        "id": "G0020",
        "url_id": "Equation",
        "title": "Equation",
        "tags": ["advanced", "state-sponsored", "firmware", "zero-day", "stealth", "high-complexity"],
        "description": (
            "Equation is a highly advanced threat group known for using multiple custom remote access tools, zero-day exploits, and stealthy persistence techniques. "
            "It is one of the few groups documented to have successfully developed and deployed firmware-level attacks, specifically targeting hard disk drives (HDDs). "
            "Equation has used encrypted virtual file systems and payloads designed to activate only under specific environmental conditions, indicating highly targeted and tailored operations."
        ),
        "associated_groups": [],
        "campaigns": [],
        "techniques": [
            "T1480.001",  # Execution Guardrails: Environmental Keying
            "T1564.005",  # Hide Artifacts: Hidden File System
            "T1120",      # Peripheral Device Discovery
            "T1542.002"   # Pre-OS Boot: Component Firmware
        ],
        "contributors": [],
        "version": "1.2",
        "created": "31 May 2017",
        "last_modified": "16 April 2025",
        "navigator": "",
        "references": [
            {
                "source": "Equation Group: Questions and Answers - Kaspersky Lab (2015)",
                "url": "https://example.com/equation-qa-kaspersky"
            },
            {
                "source": "Gauss: Abnormal Distribution - Kaspersky Lab (2012)",
                "url": "https://example.com/gauss-analysis"
            }
        ],
        "resources": [],
        "remediation": (
            "Deploy firmware integrity monitoring tools and implement secure boot policies where possible. "
            "Ensure endpoint detection platforms monitor for environmental execution conditions and unauthorized access to the Windows Registry storing encrypted file systems."
        ),
        "improvements": (
            "Invest in low-level disk forensics and BIOS/UEFI integrity checks. Maintain backup and recovery strategies for firmware corruption scenarios."
        ),
        "hunt_steps": [
            "Inspect registry for large, unusual encrypted blobs potentially linked to virtual file systems.",
            "Monitor for use of tools interacting with hard disk firmware interfaces.",
            "Identify payloads that trigger only under specific system/environment conditions."
        ],
        "expected_outcomes": [
            "Detection of stealthy persistence using hidden file systems.",
            "Early identification of advanced malware requiring specific environmental triggers.",
            "Discovery of firmware-level modifications or attempts to interact with HDD firmware."
        ],
        "false_positive": (
            "Rare, but encrypted data in the registry or environmental checks in scripts may be legitimate in specialized enterprise software."
        ),
        "clearing_steps": [
            "Manually verify and restore compromised firmware with OEM tools if available.",
            "Purge unauthorized registry-stored virtual file systems.",
            "Re-image compromised systems and conduct full forensic analysis of hardware-level threats."
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": []
        }
    }
