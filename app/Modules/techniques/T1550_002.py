def get_content():
    return {
        "id": "T1550.002",
        "url_id": "T1550/002",
        "title": "Use Alternate Authentication Material: Pass the Session",
        "tactic": "Defense Evasion, Credential Access, Lateral Movement",
        "data_sources": "Authentication Logs, Network Traffic, Windows Event Logs, Endpoint Security Logs",
        "protocol": "SMB, RDP, NTLM, Kerberos",
        "os": "Windows, Linux",
        "objective": "Detect and prevent adversaries from reusing session tokens or cookies to bypass authentication mechanisms.",
        "scope": "Monitor network authentication events and analyze session token reuse across different hosts.",
        "threat_model": "Adversaries may hijack authenticated sessions to impersonate users and escalate privileges, often evading credential theft protections.",
        "hypothesis": [
            "Are there unusual or unauthorized session reuse events?",
            "Are adversaries leveraging stolen cookies or authentication tokens?",
            "Is there unexpected authentication to privileged accounts without corresponding logon events?"
        ],
        "tips": [
            "Monitor Windows Event ID 4624 (Logon) and Event ID 4776 (Credential Validation).",
            "Detect anomalous reuse of NTLM/Kerberos tokens across different hosts.",
            "Monitor for suspicious authentication attempts using session-based credentials."
        ],
        "log_sources": [
            {"type": "Authentication Logs", "source": "Windows Event ID 4624, 4776, 4769", "destination": "Security.evtx"},
            {"type": "Network Traffic", "source": "Packet Capture (PCAP), Zeek Logs", "destination": "Network Analysis"},
            {"type": "Endpoint Security Logs", "source": "CrowdStrike, Defender ATP", "destination": "SIEM"}
        ],
        "source_artifacts": [
            {"type": "Windows Security Log", "location": "Security.evtx", "identify": "Tracking authentication events and session reuse."},
            {"type": "NTLM Hashes", "location": "Memory Dump (LSASS)", "identify": "Capturing stored NTLM session credentials."}
        ],
        "destination_artifacts": [
            {"type": "Kerberos Tickets", "location": "C:\\Windows\\Temp\\*.kirbi", "identify": "Potential presence of stolen Kerberos tickets for session hijacking."},
            {"type": "Session Cookies", "location": "Browser Storage, Memory Dumps", "identify": "Detection of stolen web authentication tokens."}
        ],
        "detection_methods": [
            "Monitor logon sessions with mismatched logon types and authentication events.",
            "Analyze authentication logs for session reuse anomalies.",
            "Detect the presence of stolen Kerberos tickets using memory forensics."
        ],
        "apt": ["G0032", "G0069"],
        "spl_query": [
            "index=windows EventCode=4624 LogonType=3 | stats count by AccountName, IpAddress, WorkstationName",
            "index=windows EventCode=4769 | stats count by ServiceName, TicketEncryptionType, AccountName"
        ],
        "hunt_steps": [
            "Investigate abnormal authentication attempts with reused tokens.",
            "Analyze network traffic logs for NTLM session relays.",
            "Check for suspicious Kerberos ticket requests from compromised hosts."
        ],
        "expected_outcomes": [
            "Pass-the-Session attack detected and contained.",
            "No malicious activity found; baseline authentication behavior refined."
        ],
        "false_positive": "Some legitimate session reuse scenarios may exist, especially in shared environments.",
        "clearing_steps": [
            "Revoke and reissue affected Kerberos tickets.",
            "Invalidate all active NTLM sessions and force reauthentication.",
            "Flush browser session cookies and reset authentication tokens."
        ],
        "mitre_mapping": [
            {"tactic": "Credential Access", "technique": "T1003 (Credential Dumping)", "example": "Extracting session tokens from LSASS memory."},
            {"tactic": "Lateral Movement", "technique": "T1550.003 (Pass the Hash)", "example": "Using NTLM hashes for authentication instead of passwords."}
        ],
        "watchlist": [
            "Monitor repeated authentication requests from the same token across multiple hosts.",
            "Detect anomalies in NTLM/Kerberos authentication traffic.",
            "Investigate new service ticket requests from unexpected hosts."
        ],
        "enhancements": [
            "Implement Kerberos FAST (Flexible Authentication Secure Tunneling) to mitigate ticket interception.",
            "Enable SMB signing and enforce NTLM relay protections.",
            "Deploy enhanced logging for Windows authentication events."
        ],
        "summary": "Pass-the-Session attacks allow adversaries to hijack authenticated sessions, bypassing credential theft defenses.",
        "remediation": "Force reauthentication of all active sessions, enforce multi-factor authentication, and monitor authentication logs.",
        "improvements": "Enhance authentication security by enforcing strict session validation and reducing NTLM usage."
    }
