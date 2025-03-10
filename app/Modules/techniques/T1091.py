def get_content():
    return {
        "id": "T1091",
        "url_id": "T1091",
        "title": "Replication Through Removable Media",
        "tactic": "Lateral Movement, Initial Access, Persistence",
        "tags": ["USB", "Removable Media", "Persistence", "Malware Propagation"],
        "data_sources": "File monitoring, Process monitoring, Windows Registry, Device monitoring",
        "protocol": "N/A",
        "os": "Windows, Linux, macOS",
        "objective": "Detect and mitigate malware or unauthorized files spreading through removable media like USB drives.",
        "scope": "Monitor file transfers, execution, and modifications on removable media to prevent unauthorized replication.",
        "threat_model": "Adversaries may use USB drives or other removable media to infect systems, install backdoors, or establish persistence, especially in air-gapped environments.",
        "hypothesis": [
            "Are there unauthorized files being copied onto removable media?",
            "Are removable drives executing processes upon insertion?",
            "Are unauthorized registry or system configurations being altered due to removable media usage?"
        ],
        "log_sources": [
            {"type": "File System", "source": "File write operations on removable media"},
            {"type": "Process Monitoring", "source": "Execution of binaries from removable media"},
            {"type": "Windows Registry", "source": "Autorun configurations related to removable drives"},
            {"type": "Device Monitoring", "source": "USB device insertions and removals"}
        ],
        "source_artifacts": [
            {"type": "Malware Samples", "location": "Removable media storage", "identify": "Check for known malware hashes"}
        ],
        "destination_artifacts": [
            {"type": "Registry Keys", "location": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "identify": "Look for persistence mechanisms via removable media"}
        ],
        "detection_methods": [
            "Monitor execution of applications directly from removable media.",
            "Detect unauthorized files being copied onto USB drives.",
            "Analyze registry changes for persistence mechanisms related to removable media.",
            "Monitor USB insertions for anomalous activity."
        ],
        "apt": ["Stuxnet", "DarkHotel", "Equation Group"],
        "spl_query": ["index=windows EventCode=4663 ObjectType=File AND (ObjectName=\\\\Device\\Harddisk* OR ObjectName=*\\USB)"],
        "hunt_steps": [
            "Identify unusual file modifications or execution from removable media.",
            "Correlate USB insertions with unexpected process executions.",
            "Analyze logs for persistence mechanisms linked to removable media.",
            "Investigate unauthorized transfers of sensitive files onto USB devices."
        ],
        "expected_outcomes": [
            "Detection of unauthorized execution from removable media.",
            "Identification of persistence techniques utilizing USB devices.",
            "Mitigation of malware propagation through removable media."
        ],
        "false_positive": "Legitimate usage of USB storage devices by authorized personnel.",
        "clearing_steps": [
            "Disable autorun for removable drives.",
            "Enforce endpoint security policies to block unauthorized USB devices.",
            "Remove unauthorized executables or scripts from removable media.",
            "Monitor for persistence artifacts and remediate compromised hosts."
        ],
        "mitre_mapping": [
            {"tactic": "Initial Access", "technique": "T1204 (User Execution)", "example": "Malware executed upon USB insertion."},
            {"tactic": "Persistence", "technique": "T1547.001 (Registry Run Keys)", "example": "Malicious persistence mechanism set via registry modification."},
            {"tactic": "Defense Evasion", "technique": "T1070.004 (Indicator Removal on Host)", "example": "Logs cleared after executing malicious payload from USB."}
        ],
        "watchlist": [
            "Monitor all file executions originating from removable drives.",
            "Detect unauthorized data transfers to removable media.",
            "Alert on persistence techniques leveraging USB autorun."
        ],
        "enhancements": [
            "Implement device control policies to restrict unauthorized USB access.",
            "Enhance endpoint protection to detect removable media-based threats.",
            "Conduct regular audits to identify unauthorized use of removable devices."
        ],
        "summary": "Removable media can serve as a vector for malware propagation and persistence, particularly in air-gapped environments.",
        "remediation": "Disable autorun features, enforce strict device access policies, and educate users on removable media risks.",
        "improvements": "Utilize behavioral analytics to detect anomalous USB usage patterns and restrict access based on organizational policies."
    }
