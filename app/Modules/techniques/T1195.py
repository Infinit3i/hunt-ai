def get_content():
    return {
        "id": "T1195",
        "url_id": "T1195",
        "title": "Supply Chain Compromise",
        "description": "Adversaries may manipulate products or product delivery mechanisms prior to receipt by a final consumer for the purpose of data or system compromise. Supply chain compromise can take place at any stage of the supply chain including: manipulation of development tools, development environments, source code repositories, software update mechanisms, and system images. Adversaries looking to gain execution have often focused on malicious additions to legitimate software in distribution or update channels. Targeting may be specific or widespread depending on the adversary's goal.",
        "tags": ["supply chain", "initial access", "software tampering", "malware injection"],
        "tactic": "Initial Access",
        "protocol": "",
        "os": "Linux, Windows, macOS",
        "tips": [
            "Verify software binaries using hash or signature verification.",
            "Perform integrity checks on updates and distribution packages.",
            "Physically inspect hardware when possible for tampering."
        ],
        "data_sources": "File, Sensor Health",
        "log_sources": [
            {"type": "File", "source": "", "destination": ""},
            {"type": "Sensor Health", "source": "", "destination": ""}
        ],
        "source_artifacts": [],
        "destination_artifacts": [],
        "detection_methods": [
            "Hash and integrity validation of software binaries.",
            "Behavioral analysis of newly installed or updated applications."
        ],
        "apt": ["Cadet Blizzard", "APT44"],
        "spl_query": [
            "index=endpoint sourcetype=file_integrity \n| search file_modified=true file_signature_invalid=true"
        ],
        "hunt_steps": [
            "Review software update logs for suspicious behavior.",
            "Check for anomalies in package sources or repositories.",
            "Verify hardware and firmware images for changes."
        ],
        "expected_outcomes": [
            "Early detection of tampered software or firmware.",
            "Improved assurance of integrity in deployed systems."
        ],
        "false_positive": "Unsigned but legitimate updates may appear suspicious; verify vendor details before remediation.",
        "clearing_steps": [
            "Reinstall affected software from trusted sources.",
            "Audit system integrity using checksums and vendor references."
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1036", "example": "Malicious update masquerading as legitimate software."}
        ],
        "watchlist": ["Unexpected changes in software binaries or firmware images"],
        "enhancements": [
            "Integrate SBOM (Software Bill of Materials) tracking.",
            "Apply stricter controls to CI/CD and update pipelines."
        ],
        "summary": "Supply chain compromise introduces malicious changes in software or hardware prior to delivery, enabling attackers to gain access to systems or data.",
        "remediation": "Validate software and firmware integrity, perform code audits, and secure build pipelines.",
        "improvements": "Use reproducible builds, automated code scanning, and dependency monitoring tools.",
        "mitre_version": "16.1"
    }
