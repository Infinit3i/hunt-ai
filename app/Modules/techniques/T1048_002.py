def get_content():
    return {
        "id": "T1048.002",
        "url_id": "T1048/002",
        "title": "Exfiltration Over Alternative Protocol: Exfiltration Over Asymmetric Encrypted Non-C2 Protocol",
        "description": "Adversaries may steal data by exfiltrating it over an asymmetrically encrypted network protocol other than that of the existing command and control channel. Asymmetric encryption algorithms, also known as public-key cryptography, use different keys on each end of the channel. This requires pairs of cryptographic keys that can encrypt/decrypt data from the corresponding key. The public keys of each entity are exchanged before encrypted communications begin. Network protocols that use asymmetric encryption (such as HTTPS/TLS/SSL) often utilize symmetric encryption once keys are exchanged. Adversaries may opt to use these encrypted mechanisms baked into protocols or manually configure encryption for exfiltration.",
        "tags": ["Exfiltration", "Encrypted Protocol", "Asymmetric Encryption", "Data Exfiltration"],
        "tactic": "Exfiltration",
        "protocol": "",
        "os": "Linux, Windows, macOS",
        "tips": ["Analyze network data for uncommon data flows, such as a client sending significantly more data than it receives from a server.", "Processes utilizing the network that do not normally have network communication or have never been seen before are suspicious."],
        "data_sources": "Command: Command Execution, File: File Access, Network Traffic: Network Connection Creation, Network Traffic: Network Traffic Content, Network Traffic: Network Traffic Flow",
        "log_sources": [
            {"type": "Command", "source": "Command Execution", "destination": ""},
            {"type": "File", "source": "File Access", "destination": ""},
            {"type": "Network Traffic", "source": "Network Connection Creation", "destination": ""},
            {"type": "Network Traffic", "source": "Network Traffic Content", "destination": ""},
            {"type": "Network Traffic", "source": "Network Traffic Flow", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Network Traffic", "location": "Network Traffic Flow", "identify": "Asymmetric encryption used in non-C2 protocols for data exfiltration"}
        ],
        "destination_artifacts": [
            {"type": "Network Traffic", "location": "Network Traffic Content", "identify": "Exfiltrated data sent using asymmetric encryption"}
        ],
        "detection_methods": ["Monitor for unusual traffic patterns involving asymmetric encryption in network protocols.", "Analyze packet contents for encryption keys or encrypted traffic that is inconsistent with expected protocol behavior."],
        "apt": ["Sodinokibi", "SolarWinds", "Rclone", "Volexity", "Liderc", "GRU Brute Force Campaign"],
        "spl_query": [],
        "hunt_steps": ["Search for the use of asymmetric encryption algorithms like RSA in network traffic", "Look for key exchange artifacts or encrypted communication traffic"],
        "expected_outcomes": ["Identification of data being exfiltrated over asymmetric encrypted non-C2 protocols, such as HTTPS/TLS/SSL"],
        "false_positive": "Legitimate encrypted traffic may be flagged as exfiltration, especially if asymmetric encryption protocols like HTTPS are used for business operations.",
        "clearing_steps": ["Terminate any active exfiltration processes and block unauthorized use of asymmetric encryption protocols for data transfer", "Inspect network logs for unusual traffic patterns and decrypt, if possible, to retrieve exfiltrated data"],
        "mitre_mapping": [
            {"tactic": "Exfiltration", "technique": "T1048", "example": "Exfiltrating data over HTTPS with asymmetric encryption"}
        ],
        "watchlist": ["Monitor for encrypted traffic that uses asymmetric encryption algorithms like RSA or protocols like HTTPS for data exfiltration"],
        "enhancements": ["Use deep packet inspection to detect asymmetric encryption patterns in unexpected contexts.", "Enhance detection by identifying abnormal traffic volume or unusual network connections that coincide with sensitive data exfiltration."],
        "summary": "Exfiltration over asymmetric encrypted non-C2 protocols involves the use of asymmetric encryption (e.g., RSA, TLS/SSL) to exfiltrate data over non-C2 network protocols such as HTTPS, often leading to evasion of detection.",
        "remediation": "Limit the use of asymmetric encryption in non-standard protocols for data transfers and monitor for unusual encrypted traffic patterns.",
        "improvements": "Enhance detection and prevention of exfiltration over asymmetric encrypted non-C2 protocols by inspecting packet contents and monitoring for abnormal data volumes.",
        "mitre_version": "16.1"
    }
