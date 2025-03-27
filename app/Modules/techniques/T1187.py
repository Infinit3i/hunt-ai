def get_content():
    return {
        "id": "T1187",
        "url_id": "T1187",
        "title": "Forced Authentication",
        "description": "Adversaries may gather credential material by invoking or forcing a user to automatically provide authentication information through a mechanism in which they can intercept. The Server Message Block (SMB) protocol is commonly used in Windows networks for authentication and communication between systems for access to resources and file sharing. When a Windows system attempts to connect to an SMB resource it will automatically attempt to authenticate and send credential information for the current user to the remote system. Web Distributed Authoring and Versioning (WebDAV) is also typically used by Windows systems as a backup protocol when SMB is blocked or fails. Adversaries may take advantage of this behavior to gain access to user account hashes through forced SMB/WebDAV authentication. When the user's system accesses the untrusted resource it will attempt authentication and send information, including the user's hashed credentials, over SMB to the adversary controlled server. With access to the credential hash, an adversary can perform off-line brute force cracking to gain access to plaintext credentials.",
        "tags": ["smb", "webdav", "credential access", "hash capture", "authentication"],
        "tactic": "Credential Access",
        "protocol": "SMB, WebDAV",
        "os": "Windows",
        "tips": [
            "Monitor SMB and WebDAV outbound traffic to untrusted IPs or domains.",
            "Detect .LNK and .SCF files pointing to external resources."
        ],
        "data_sources": "File, Network Traffic",
        "log_sources": [
            {"type": "File", "source": "", "destination": ""},
            {"type": "Network Traffic", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "File Access", "location": "User profile directories", "identify": ".LNK or .SCF with external references"},
            {"type": "Network Connections", "location": "Firewall or proxy logs", "identify": "SMB/WebDAV to external IPs"}
        ],
        "destination_artifacts": [],
        "detection_methods": [
            "Monitor outbound SMB and WebDAV authentication attempts.",
            "Inspect .LNK/.SCF file creation or modification.",
            "Alert on credentials sent to unknown hosts."
        ],
        "apt": ["Nobelium", "Berserk Bear", "APT Energy"],
        "spl_query": [
            "index=network sourcetype=bro_smb \n| search destination_ip!=internal_network \n| stats count by src_ip, destination_ip"
        ],
        "hunt_steps": [
            "Identify .SCF or .LNK files with external icon references.",
            "Trace SMB or WebDAV outbound flows to non-corporate addresses.",
            "Search for Normal.dotm template injection activity."
        ],
        "expected_outcomes": [
            "Detection of credential harvesting via forced authentication.",
            "Reduction in outbound NTLM hashes leaking via SMB/WebDAV."
        ],
        "false_positive": "Internal file shares or network tools using SMB/WebDAV may cause benign alerts.",
        "clearing_steps": [
            "Delete any unauthorized .LNK/.SCF files referencing external content.",
            "Block outbound SMB and WebDAV at network boundaries.",
            "Change passwords of affected users."
        ],
        "mitre_mapping": [
            {"tactic": "Credential Access", "technique": "T1110", "example": "Captured hashes from forced authentication cracked using brute-force methods."}
        ],
        "watchlist": ["Unusual SMB or WebDAV traffic to external IPs", "Creation of .SCF files with icon references"],
        "enhancements": [
            "Deploy SMB signing and disable NTLM where possible.",
            "Use proxy solutions to detect/stop hash leakage."
        ],
        "summary": "Forced Authentication abuses Windows behavior to collect user hashes through SMB/WebDAV requests to attacker-controlled systems.",
        "remediation": "Harden SMB/WebDAV configurations, monitor for forced auth attempts, and enforce strong passwords.",
        "improvements": "Integrate behavior-based detection for external icon loads or template injection.",
        "mitre_version": "16.1"
    }
