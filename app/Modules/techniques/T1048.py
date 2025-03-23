def get_content():
    return {
        "id": "T1048",
        "url_id": "T1048",
        "title": "Exfiltration Over Alternative Protocol",
        "description": "Adversaries may steal data by exfiltrating it over a different protocol than that of the existing command and control channel. The data may also be sent to an alternate network location from the main command and control server. Alternate protocols include FTP, SMTP, HTTP/S, DNS, SMB, or any other network protocol not being used as the main command and control channel. Adversaries may also opt to encrypt and/or obfuscate these alternate channels. Exfiltration can be done using common operating system utilities such as Net/SMB or FTP, or tools like curl on macOS and Linux to invoke HTTP/S or FTP/S protocols.",
        "tags": ["Exfiltration", "Alternative Protocol", "Data Exfiltration", "Obfuscation"],
        "tactic": "Exfiltration",
        "protocol": "",
        "os": "IaaS, Linux, Network, Office Suite, SaaS, Windows, macOS",
        "tips": ["Analyze network data for uncommon data flows, such as a client sending significantly more data than it receives from a server. Analyze packet contents to detect communications that do not follow expected protocol behavior for the port that is being used."],
        "data_sources": "Application Log: Application Log Content, Cloud Storage: Cloud Storage Access, Command: Command Execution, File: File Access, Network Traffic: Network Connection Creation, Network Traffic: Network Traffic Content, Network Traffic: Network Traffic Flow",
        "log_sources": [
            {"type": "Application Log", "source": "Application Log Content", "destination": ""},
            {"type": "Cloud Storage", "source": "Cloud Storage Access", "destination": ""},
            {"type": "Command", "source": "Command Execution", "destination": ""},
            {"type": "File", "source": "File Access", "destination": ""},
            {"type": "Network Traffic", "source": "Network Connection Creation", "destination": ""},
            {"type": "Network Traffic", "source": "Network Traffic Content", "destination": ""},
            {"type": "Network Traffic", "source": "Network Traffic Flow", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Network Traffic", "location": "Network Traffic Flow", "identify": "Exfiltrated data sent over an alternate protocol"}
        ],
        "destination_artifacts": [
            {"type": "Network Traffic", "location": "Network Traffic Content", "identify": "Exfiltration traffic via HTTP, FTP, DNS, or SMB"}
        ],
        "detection_methods": ["Monitor for unusual network traffic patterns indicating data exfiltration over uncommon protocols", "Analyze packet contents for the use of alternative protocols that differ from the main command and control channel"],
        "apt": ["Hydraq", "Kobalos", "PoetRAT", "Chaes", "Ransomware Spotlight Play", "FrameworkPOS", "PoetRAT", "Chaes", "S3 Security", "AWS Temporary Security Credentials"],
        "spl_query": [],
        "hunt_steps": ["Search for use of alternative protocols in network logs and file access logs", "Look for outbound traffic that does not match the expected protocol or destination patterns"],
        "expected_outcomes": ["Detection of data exfiltration over alternative protocols such as FTP, DNS, SMB, or HTTP/S"],
        "false_positive": "Legitimate use of FTP, HTTP/S, or other protocols for business operations may occasionally be flagged as false positives.",
        "clearing_steps": ["Terminate any active exfiltration processes and block the use of unauthorized protocols. Monitor and mitigate any potential breach points."],
        "mitre_mapping": [
            {"tactic": "Exfiltration", "technique": "T1048", "example": "Exfiltrating data over HTTPS or FTP"}
        ],
        "watchlist": ["Monitor for traffic that shows signs of data being sent over protocols that are not commonly used in the environment"],
        "enhancements": ["Improve detection by examining application layer traffic for obfuscation or encryption indicative of exfiltration"],
        "summary": "Exfiltration over alternative protocols involves sending stolen data over protocols like FTP, HTTP/S, DNS, or SMB that are not typically used for command and control traffic.",
        "remediation": "Block unnecessary ports and protocols used for data exfiltration. Enable robust monitoring of network traffic for any irregularities in data flows.",
        "improvements": "Enhance detection and prevention of exfiltration over alternative protocols by inspecting packet contents and monitoring for abnormal data volumes.",
        "mitre_version": "16.1"
    }
