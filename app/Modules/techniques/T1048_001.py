def get_content():
    return {
        "id": "T1048.001",
        "url_id": "T1048/001",
        "title": "Exfiltration Over Alternative Protocol: Exfiltration Over Symmetric Encrypted Non-C2 Protocol",
        "description": "Adversaries may steal data by exfiltrating it over a symmetrically encrypted network protocol other than that of the existing command and control channel. Symmetric encryption algorithms are those that use shared or the same keys/secrets on each end of the channel. This requires an exchange or pre-arranged agreement/possession of the value used to encrypt and decrypt data. Network protocols that use asymmetric encryption often utilize symmetric encryption once keys are exchanged, but adversaries may opt to manually share keys and implement symmetric cryptographic algorithms (e.g., RC4, AES) instead of using mechanisms that are baked into a protocol. This may result in multiple layers of encryption or encryption in protocols that are not typically encrypted.",
        "tags": ["Exfiltration", "Encrypted Protocol", "Symmetric Encryption", "Data Exfiltration"],
        "tactic": "Exfiltration",
        "protocol": "",
        "os": "Linux, Windows, macOS",
        "tips": ["Analyze network data for uncommon data flows, such as a client sending significantly more data than it receives from a server.", "Artifacts and evidence of symmetric key exchange may be recoverable by analyzing network traffic or looking for hard-coded values within malware."],
        "data_sources": "Command: Command Execution, File: File Access, Network Traffic: Network Connection Creation, Network Traffic: Network Traffic Content, Network Traffic: Network Traffic Flow",
        "log_sources": [
            {"type": "Command", "source": "Command Execution", "destination": ""},
            {"type": "File", "source": "File Access", "destination": ""},
            {"type": "Network Traffic", "source": "Network Connection Creation", "destination": ""},
            {"type": "Network Traffic", "source": "Network Traffic Content", "destination": ""},
            {"type": "Network Traffic", "source": "Network Traffic Flow", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Network Traffic", "location": "Network Traffic Flow", "identify": "Symmetric encryption used in non-C2 protocols for data exfiltration"}
        ],
        "destination_artifacts": [
            {"type": "Network Traffic", "location": "Network Traffic Content", "identify": "Exfiltrated data sent using symmetric encryption"}
        ],
        "detection_methods": ["Monitor for symmetric encryption patterns in network traffic that are not typical for the environment", "Analyze packet contents for evidence of encryption or key exchange mechanisms"],
        "apt": ["Hydraq", "Kobalos", "PoetRAT", "S3 Security", "OilRig", "Latrodectus", "Grim Spider"],
        "spl_query": [],
        "hunt_steps": ["Search for the use of encryption algorithms like RC4 or AES in network traffic", "Look for key exchange artifacts or hard-coded encryption values within malware"],
        "expected_outcomes": ["Identification of data being exfiltrated over encrypted non-C2 protocols, such as HTTP or FTP with symmetric encryption"],
        "false_positive": "Legitimate encrypted traffic may be misidentified as exfiltration, especially if encrypted protocols like HTTPS are used for routine business operations.",
        "clearing_steps": ["Terminate the exfiltration process and block unauthorized use of encrypted protocols for data transfer", "Inspect network logs for unusual traffic patterns and decrypt, if possible, to retrieve exfiltrated data"],
        "mitre_mapping": [
            {"tactic": "Exfiltration", "technique": "T1048", "example": "Exfiltration using encrypted HTTP or FTP with symmetric encryption"}
        ],
        "watchlist": ["Monitor for encrypted traffic that uses protocols typically not encrypted or for exfiltration outside of expected command and control channels"],
        "enhancements": ["Deploy traffic analysis systems capable of detecting the use of symmetric encryption in non-standard protocols", "Improve detection by identifying abnormal traffic volume or unusual network connections that coincide with sensitive data exfiltration"],
        "summary": "Exfiltration over symmetric encrypted non-C2 protocols involves the use of encryption mechanisms, like RC4 or AES, to exfiltrate data over network protocols that are not typically encrypted, such as HTTP or FTP.",
        "remediation": "Limit the use of non-standard protocols for data transfers, especially those involving encryption. Monitor for unusual network activity and the presence of encryption algorithms in unexpected contexts.",
        "improvements": "Enhance detection by using network traffic monitoring tools capable of identifying encrypted data streams or symmetric encryption algorithms used in unauthorized protocols.",
        "mitre_version": "16.1"
    }
