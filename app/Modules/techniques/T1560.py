def get_content():
    return {
        "id": "T1560",
        "url_id": "1560",
        "title": "Archive Collected Data",
        "description": "An adversary may compress and/or encrypt data that is collected prior to exfiltration. Compressing the data can help to obfuscate the collected data and minimize the amount of data sent over the network. Encryption can be used to hide information that is being exfiltrated from detection or make exfiltration less conspicuous upon inspection by a defender. Both compression and encryption are done prior to exfiltration, and can be performed using a utility, 3rd party library, or custom method.",
        "tags": ["Data Exfiltration", "Encryption", "Compression"],
        "tactic": "Collection",
        "protocol": "N/A",
        "os": "Linux, Windows, macOS",
        "tips": [
            "Monitor process creation logs for compression and encryption utilities.",
            "Use endpoint detection to identify anomalous archiving behavior.",
            "Monitor for cryptographic library loads such as crypt32.dll in Windows."
        ],
        "data_sources": "Command Execution, File Creation, Process Creation, Script Execution",
        "log_sources": [
            {"type": "Command", "source": "Command Execution", "destination": "Logs"},
            {"type": "File", "source": "File Creation", "destination": "Logs"},
            {"type": "Process", "source": "Process Creation", "destination": "Logs"},
            {"type": "Script", "source": "Script Execution", "destination": "Logs"}
        ],
        "source_artifacts": [
            {"type": "File", "location": "Compressed archive files", "identify": "ZIP, RAR, 7z, TAR.GZ formats"}
        ],
        "destination_artifacts": [
            {"type": "File", "location": "Remote storage or exfiltration endpoint", "identify": "Encrypted or compressed data"}
        ],
        "detection_methods": ["Process monitoring", "File creation analysis", "Network anomaly detection"],
        "apt": ["APT10", "APT40", "Lazarus Group", "Turla"],
        "spl_query": [
            "index=security | search process_name=*zip* OR process_name=*rar* OR process_name=*7z*",
            "index=network | search dest_ip=* and file_type=compressed"
        ],
        "hunt_steps": [
            "Identify abnormal use of archiving utilities.",
            "Monitor cryptographic API calls in system logs.",
            "Look for large amounts of compressed data in unusual destinations."
        ],
        "expected_outcomes": ["Detection of suspicious archiving and encryption activities"],
        "false_positive": "Legitimate use of compression and encryption tools for business purposes.",
        "clearing_steps": [
            "Terminate unauthorized archiving processes.",
            "Remove suspicious archive files from endpoints.",
            "Investigate and block the exfiltration path."
        ],
        "mitre_mapping": [
            {"tactic": "Exfiltration", "technique": "T1041", "example": "Exfiltration Over C2 Channel"}
        ],
        "watchlist": ["Unexpected use of WinRAR, 7-Zip, or tar on critical servers."],
        "enhancements": ["Implement DLP rules to monitor and block unauthorized compression attempts."],
        "summary": "Adversaries may archive collected data before exfiltration to obfuscate its contents and reduce file size, making detection more challenging.",
        "remediation": "Monitor and restrict the use of compression tools. Implement strict DLP rules to prevent unauthorized data compression and encryption.",
        "improvements": "Use behavioral analysis to detect abnormal data compression activities and correlate with potential exfiltration events."
    }
