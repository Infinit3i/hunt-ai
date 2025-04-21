def get_content():
    return {
        "id": "T1570",
        "url_id": "T1570",
        "title": "Lateral Tool Transfer",
        "description": "Adversaries may transfer tools or files across systems in a compromised environment to facilitate further operations. After initial access, adversaries often move files from one host to another to prepare for lateral movement, persistence, or data collection.\n\nThey may use standard file-sharing protocols such as SMB or tools like FTP, SCP, rsync, or cloud-synced services such as Dropbox or OneDrive. Adversaries may also abuse administrative shares or authenticated sessions like RDP to copy tools across endpoints without triggering alerts from network egress monitors, since traffic remains internal.",
        "tags": ["lateral_movement", "file_transfer", "internal_network", "remote_access"],
        "tactic": "Lateral Movement",
        "protocol": "SMB, RDP, SCP, SFTP, FTP, HTTP",
        "os": "Windows, Linux, macOS",
        "tips": [
            "Correlate file hashes across endpoints to identify reused payloads.",
            "Baseline expected internal file transfer behavior and alert on deviations.",
            "Track usage of native utilities for potential LOLBIN-based transfers."
        ],
        "data_sources": "Network Traffic, File Creation, File Metadata, Process Creation, Named Pipe, Network Share Access, Command Logs",
        "log_sources": [
            {"type": "File Transfer Events", "source": "SMB, FTP, SFTP logs", "destination": ""},
            {"type": "Command Execution", "source": "Sysmon (Event ID 1), Audit Process Tracking", "destination": ""},
            {"type": "Named Pipes", "source": "Sysmon (Event ID 17/18)", "destination": ""},
            {"type": "Network Flow Logs", "source": "Zeek, NetFlow, Firewall Logs", "destination": ""},
            {"type": "Process Creation", "source": "EDR Tools (e.g., CrowdStrike, SentinelOne)", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Transfer Tool Invocation", "location": "Source Host CLI", "identify": "Commands like `scp`, `xcopy`, `ftp`"},
            {"type": "Network Session", "location": "Source Endpoint", "identify": "Outbound SMB session to peer device"}
        ],
        "destination_artifacts": [
            {"type": "Created Executables", "location": "Remote System", "identify": "Staged tools with rare or obfuscated names"},
            {"type": "File Metadata", "location": "Transferred File", "identify": "Similar timestamps or hashes between hosts"}
        ],
        "detection_methods": [
            "Monitor for file creation on remote shares using SMB or FTP.",
            "Detect unexpected usage of native tools like xcopy, scp, or curl for file transfers.",
            "Correlate file hashes, names, and creation times across endpoints.",
            "Analyze network flows for lateral file movement activity outside regular backup operations."
        ],
        "apt": [
            "LockerGoga", "FIN10", "Agrius", "Cobalt Kitty", "Olympic Destroyer", "Conti", "WannaCry", "HermeticWizard", "BlackCat", "SaintBot"
        ],
        "spl_query": [
            "index=sysmon sourcetype=Sysmon EventCode=11 \n| search TargetFilename=\"*\\\\ADMIN$\\\\*\" OR TargetFilename=\"*\\\\C$\\\\Users\\\\*\" \n| stats count by TargetFilename, User, ComputerName"
        ],
        "hunt_steps": [
            "Search for file creation events on admin shares or user directories.",
            "Identify internal IP-to-IP transfers using SMB, FTP, or HTTP on odd ports.",
            "Check for use of `ftp`, `xcopy`, `bitsadmin`, or `certutil` to fetch files.",
            "Compare hashes of newly created files across multiple systems.",
            "Validate user privileges and investigate abnormal remote write behaviors."
        ],
        "expected_outcomes": [
            "Lateral Tool Transfer Detected: Quarantine tool artifacts and investigate pivot activity.",
            "No Malicious Activity Found: Continue refining internal transfer baselines and detection coverage."
        ],
        "false_positive": "Legitimate file transfers for patch deployments, IT maintenance, and system imaging tools may appear similar. Validate through context (e.g., time, tool, and user role).",
        "clearing_steps": [
            "Isolate affected systems and remove transferred tools.",
            "Revoke compromised credentials and review file permissions.",
            "Restore clean backups of modified systems or reimage if necessary."
        ],
        "mitre_mapping": [
            {"tactic": "Lateral Movement", "technique": "T1570 (Lateral Tool Transfer)", "example": "Using `xcopy` or `SCP` to move malware to lateral targets."},
            {"tactic": "Defense Evasion", "technique": "T1027 (Obfuscated Files or Information)", "example": "Obfuscating transferred files to bypass detection."},
            {"tactic": "Execution", "technique": "T1059 (Command and Scripting Interpreter)", "example": "Using scripts to automate tool deployment across systems."}
        ],
        "watchlist": [
            "Watch for new file creation across multiple endpoints with identical hashes.",
            "Flag command-line usage of file copy tools in lateral contexts.",
            "Detect abnormal use of RDP or SMB connections tied to binary transfers."
        ],
        "enhancements": [
            "Deploy deception file shares with honey binaries to trap lateral tool transfers.",
            "Use UEBA to identify user accounts copying files across multiple hosts in short time spans.",
            "Implement host-based logging for transfers via `certutil`, `bitsadmin`, `ftp` or PowerShell."
        ],
        "summary": "Adversaries move tools across systems to stage payloads for lateral movement. Monitoring file copies over SMB, use of native transfer tools, and correlations between system activities can help detect this technique.",
        "remediation": "Contain affected systems, remove tools transferred laterally, and conduct forensic review for additional signs of compromise.",
        "improvements": "Enhance internal segmentation, increase endpoint monitoring fidelity, and enrich detection of file copy operations linked to abnormal process chains.",
        "mitre_version": "16.1"
    }
