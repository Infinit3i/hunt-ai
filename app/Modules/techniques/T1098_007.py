def get_content():
    return {
        "id": "T1098.007",  
        "url_id": "T1098/007",  
        "title": "Account Manipulation: Additional Local or Domain Groups",  
        "description": (
            "An adversary may add additional local or domain groups to an adversary-controlled account "
            "to maintain persistent access to a system or domain. On Windows, accounts may use the "
            "`net localgroup` and `net group` commands to add existing users to local and domain groups. "
            "On Linux, adversaries may use the `usermod` command for the same purpose. "
            "For example, accounts may be added to the local administrators group on Windows devices to "
            "maintain elevated privileges. They may also be added to the Remote Desktop Users group, "
            "allowing them to leverage Remote Desktop Protocol to log into the endpoints in the future. "
            "On Linux, accounts may be added to the sudoers group, allowing them to persistently leverage "
            "Sudo and Sudo Caching for elevated privileges. In Windows environments, machine accounts may "
            "also be added to domain groups. This allows the local SYSTEM account to gain privileges on the domain."
        ),
        "tags": ["Persistence", "Privilege Escalation"],  
        "tactic": "Persistence, Privilege Escalation",  
        "protocol": "",  
        "os": ["Linux", "Windows", "macOS"],  
        "tips": [
            "Monitor group modifications in Windows and Linux environments.",
            "Implement auditing policies to detect unauthorized group changes.",
            "Use endpoint security tools to track administrative group changes."
        ],  
        "data_sources": [
            "Windows Security", "Windows Powershell", "Windows Application", "Windows System",
            "Sysmon", "Zeek", "Suricata", "Active Directory", "User Account Modification"
        ],  
        "log_sources": [
            {"type": "Windows Security", "source": "Event Logs", "destination": "SIEM"},
            {"type": "Active Directory", "source": "Group Membership Changes", "destination": "SIEM"},
            {"type": "Sysmon", "source": "Process Tracking", "destination": "SIEM"}
        ],
        "source_artifacts": [
            {"type": "Log File", "location": "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx", "identify": "Group Membership Changes"}
        ],
        "destination_artifacts": [
            {"type": "Log File", "location": "/var/log/auth.log", "identify": "Usermod Command Execution"}
        ],
        "detection_methods": [
            "Monitor for suspicious group additions in Windows/Linux event logs.",
            "Correlate administrative account modifications with unusual access behavior."
        ],
        "apt": ["APT35", "APT41", "TA505", "Elephant Beetle"],  
        "spl_query": [
            "index=security EventCode=4728 OR EventCode=4732 OR EventCode=4756\n| table _time, Account_Name, Group_Name, Workstation_Name"
        ],  
        "hunt_steps": [
            "Identify recent group membership modifications.",
            "Check for unauthorized users in privileged groups.",
            "Investigate related login activity for persistence indicators."
        ],  
        "expected_outcomes": [
            "Unauthorized group modifications detected.",
            "Malicious accounts identified and removed."
        ],  
        "false_positive": "Administrators adding users to groups for legitimate access.",  
        "clearing_steps": [
            "Review and remove unauthorized accounts from administrative groups.",
            "Audit group modification logs for additional anomalies."
        ],  
        "mitre_mapping": [
            {"tactic": "Persistence", "technique": "Account Manipulation", "example": "Adding users to administrator groups"}
        ],  
        "watchlist": [
            "Suspicious group membership changes.",
            "Unexpected administrative privilege escalations."
        ],  
        "enhancements": [
            "Enable alerts for administrative group modifications.",
            "Use behavioral analytics to detect anomalies."
        ],  
        "summary": "Adversaries may modify local or domain group memberships to maintain access and escalate privileges.",  
        "remediation": "Regularly audit group membership and enforce least privilege principles.",  
        "improvements": "Implement real-time monitoring for administrative changes."  
    }
