def get_content():
    return {
        "id": "T1557.001",
        "url_id": "T1557/001",
        "title": "Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay",
        "description": "Adversaries may respond to LLMNR/NBT-NS network traffic to impersonate an authoritative source for name resolution, forcing communication with an attacker-controlled system.",
        "tags": [
            "LLMNR Poisoning", "NBT-NS Attack", "SMB Relay", "NTLM Hash Capture",
            "Network Spoofing", "Responder Tool", "Man-in-the-Middle", "Windows Network Security",
            "Credential Theft", "Name Resolution Exploitation"
        ],
        "tactic": "Collection, Credential Access",
        "protocol": "LLMNR, NetBIOS, SMB, NTLMv2",
        "os": ["Windows"],
        "tips": [
            "Disable LLMNR and NetBIOS over TCP/IP to prevent poisoning attacks.",
            "Implement SMB signing to prevent relay attacks.",
            "Monitor Windows event logs for suspicious name resolution traffic."
        ],
        "data_sources": [
            "Network Traffic: Network Traffic Content",
            "Network Traffic: Network Traffic Flow",
            "Service: Service Creation",
            "Windows Registry: Windows Registry Key Modification"
        ],
        "log_sources": [
            {"type": "Windows Event Logs", "source": "Event IDs 4697, 7045", "destination": "SIEM"},
            {"type": "Network Logs", "source": "UDP 5355 and UDP 137 traffic", "destination": "SOC"},
            {"type": "System Logs", "source": "Windows Registry changes for LLMNR settings", "destination": "Endpoint Detection Platform"}
        ],
        "source_artifacts": [
            {"type": "Packet Capture", "location": "/var/log/llmnr_poison.pcap", "identify": "Captured LLMNR and NetBIOS traffic"}
        ],
        "destination_artifacts": [
            {"type": "Threat Intelligence", "location": "SMB Relay Attack Indicators", "identify": "Compromised network authentication data"}
        ],
        "detection_methods": [
            "Monitor changes to HKLM\\Software\\Policies\\Microsoft\\Windows NT\\DNSClient registry key.",
            "Look for unauthorized traffic on UDP 5355 (LLMNR) and UDP 137 (NBT-NS).",
            "Detect unauthorized SMB relay attempts using NTLM hashes."
        ],
        "apt": ["Threat Actors Exploiting LLMNR and SMB Relay", "APT Groups Targeting Windows Networks"],
        "spl_query": [
            "index=network_logs source=/var/log/llmnr_poison.pcap \"Suspicious LLMNR Response\"\n| table _time, Source_IP, Destination_IP, Protocol, NTLM_Hash"
        ],
        "hunt_steps": [
            "Identify unauthorized name resolution requests with multiple responses.",
            "Analyze SMB authentication attempts using relayed NTLM hashes.",
            "Investigate usage of known tools like Responder, Inveigh, or NBNSpoof."
        ],
        "expected_outcomes": [
            "Detection of adversary-controlled name resolution spoofing attempts.",
            "Identification of credentials intercepted using SMB relay techniques."
        ],
        "false_positive": "Legitimate network scanning tools or misconfigured name resolution settings.",
        "clearing_steps": [
            "Disable LLMNR and NBT-NS via Group Policy on Windows devices.",
            "Enforce SMB signing to prevent unauthorized relay attacks."
        ],
        "mitre_mapping": [
            {"tactic": "Collection, Credential Access", "technique": "LLMNR/NBT-NS Poisoning and SMB Relay", "example": "An attacker intercepting NTLMv2 hashes to relay authentication attempts against a target system."}
        ],
        "watchlist": [
            "Known tools such as Responder, Inveigh, Metasploit NBNSpoof used for LLMNR attacks.",
            "Indicators of SMB relay abuse in network authentication logs."
        ],
        "enhancements": [
            "Deploy intrusion detection systems (IDS) to detect unauthorized LLMNR/NBT-NS responses.",
            "Use Active Directory monitoring solutions to track NTLM relay-based authentication anomalies."
        ],
        "summary": "LLMNR/NBT-NS Poisoning and SMB Relay attacks exploit weak name resolution settings in Windows networks to capture authentication data and escalate privileges.",
        "remediation": "Disable insecure name resolution protocols, enable SMB signing, and monitor for unauthorized network authentication attempts.",
        "improvements": "Adopt Kerberos authentication for secure credential handling and enforce strict network segmentation to reduce exposure to SMB relay attacks."
    }
