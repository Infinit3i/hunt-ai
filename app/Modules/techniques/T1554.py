def get_content():
    return {
        "id": "T1554",
        "url_id": "1554",
        "title": "Compromise Host Software Binary",
        "description": 'Adversaries may modify host software binaries to establish persistent access to systems. Software binaries/executables provide a wide range of system commands or services, programs, and libraries. Common software binaries are SSH clients, FTP clients, email clients, web browsers, and many other user or server applications. Adversaries may establish persistence though modifications to host software binaries. For example, an adversary may replace or otherwise infect a legitimate application binary (or support files) with a backdoor. Since these binaries may be routinely executed by applications or the user, the adversary can leverage this for persistent access to the host. An adversary may also modify a software binary such as an SSH client in order to persistently collect credentials during logins (i.e., [Modify Authentication Process](https://attack.mitre.org/techniques/T1556)).(Citation: Google Cloud Mandiant UNC3886 2024) An adversary may also modify an existing binary by patching in malicious functionality (e.g., IAT Hooking/Entry point patching)(Citation: Unit42 Banking Trojans Hooking 2022) prior to the binary’s legitimate execution. For example, an adversary may modify the entry point of a binary to point to malicious code patched in by the adversary before resuming normal execution flow.(Citation: ESET FontOnLake Analysis 2021) After modifying a binary, an adversary may attempt to [Impair Defenses](https://attack.mitre.org/techniques/T1562) by preventing it from updating (e.g., via the yum-versionlock command or versionlock.list file in Linux systems that use the yum package manager).(Citation: Google Cloud Mandiant UNC3886 2024)',
        "tags": [
            "persistence",
            "compromise-host-binary",
            "binary-modification"
        ],
        "tactic": "Persistence",
        "protocol": "N/A",
        "os": "Linux, Windows, macOS",
        "tips": [
            "Compare software binaries against known-good hashes to detect unauthorized modifications.",
            "Implement file integrity monitoring (FIM) to alert on unexpected changes to critical binaries.",
            "Restrict file system permissions to prevent unauthorized modification of system binaries.",
            "Regularly patch and update software to reduce opportunities for binary manipulation."
        ],
        "data_sources": "File: File Creation, File Modification, File Metadata, File Deletion",
        "log_sources": [
            {
                "type": "File",
                "source": "File Integrity Monitoring or EDR Telemetry",
                "destination": "SIEM"
            }
        ],
        "source_artifacts": [
            {
                "type": "Binary",
                "location": "Legitimate system or application binaries",
                "identify": "Potentially replaced or patched executable"
            }
        ],
        "destination_artifacts": [
            {
                "type": "Binary",
                "location": "Maliciously altered executable in the same path",
                "identify": "Backdoored or patched binary"
            }
        ],
        "detection_methods": [
            "Check digital signatures and compare file hashes with known-good versions",
            "Monitor for suspicious modifications to system directories or application binaries",
            "Review software update logs to detect attempts at blocking or tampering with patch processes",
            "Correlate file integrity alerts with process execution or authentication logs"
        ],
        "apt": [
            "UNC3886",
            "Agrius"
        ],
        "spl_query": [
            "index=os_file_events event=FileWrite (file_path=*bin* OR file_path=*usr*) \n| stats count by file_path, process_name, user"
        ],
        "hunt_steps": [
            "Collect and centralize file modification events for critical binaries (e.g., OS binaries, SSH client).",
            "Identify unusual or unauthorized file writes in system/application directories.",
            "Correlate changes in binaries with process execution logs to detect malicious replacements.",
            "Investigate any blocks or unusual modifications to system update/patch mechanisms."
        ],
        "expected_outcomes": [
            "Detection of maliciously replaced or patched binaries providing adversary persistence.",
            "Identification of attempts to block legitimate software updates or patching processes.",
            "Visibility into unauthorized file modifications within critical system paths."
        ],
        "false_positive": "Some legitimate system updates or patches may alter binaries. Baseline and trust checks are necessary to distinguish between authorized and malicious changes.",
        "clearing_steps": [
            "Restore affected binaries from trusted backups or official sources.",
            "Reinstate normal update/patch mechanisms if they were disabled or tampered with.",
            "Revoke any compromised credentials used to make unauthorized changes.",
            "Conduct a full system scan and forensic analysis to ensure no additional persistence mechanisms remain."
        ],
        "mitre_mapping": [
            {
                "tactic": "Persistence",
                "technique": "Modify Authentication Process (T1556)",
                "example": "Adversaries may modify SSH client binaries to capture credentials during logins."
            },
            {
                "tactic": "Defense Evasion",
                "technique": "Impair Defenses (T1562)",
                "example": "Adversaries may prevent software updates to maintain a compromised binary on the host."
            }
        ],
        "watchlist": [
            "System directories containing binaries frequently modified outside of normal patch cycles",
            "Processes that attempt to modify or overwrite binaries in critical paths",
            "Installation or usage of version-lock utilities on Linux systems (e.g., yum-versionlock)"
        ],
        "enhancements": [
            "Implement strict access controls around privileged directories to prevent unauthorized file writes.",
            "Use application allow-listing to ensure only signed, trusted binaries can execute.",
            "Perform regular backups and maintain offline copies of critical system files for recovery."
        ],
        "summary": "Adversaries may modify legitimate host software binaries to establish persistence or intercept credentials, often by replacing or patching executables in system or application directories.",
        "remediation": "Restore clean copies of modified binaries, ensure patch/update processes are functioning, remove any malicious modifications, and strengthen file integrity controls.",
        "improvements": "Implement robust file integrity monitoring, enforce least privilege on binary directories, and maintain continuous visibility into software update mechanisms to detect tampering quickly."
    }
