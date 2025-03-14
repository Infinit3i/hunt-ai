def get_content():
    return {
        "id": "T1098.005",  
        "url_id": "T1098/005",  
        "title": "Account Manipulation: Device Registration",  
        "description": "Adversaries may register unauthorized devices in identity and authentication systems to maintain access and bypass security controls.",  
        "tags": [
            "account manipulation", "device registration attack", "MFA bypass", 
            "identity provider attack", "privilege escalation", "persistence attack", 
            "Entra ID security", "Active Directory security", "cybersecurity threats"
        ],  
        "tactic": "Persistence, Privilege Escalation",  
        "protocol": "",  
        "os": ["Windows"],  
        "tips": [
            "Monitor for new device registrations in Entra ID and Intune.",
            "Enforce MFA enrollment restrictions to prevent unauthorized device registration.",
            "Audit device management logs for anomalies."
        ],  
        "data_sources": [
            "Active Directory", "Application Log: Application Log Content", "User Account: User Account Modification"
        ],  
        "log_sources": [
            {"type": "Active Directory", "source": "Device Registration Events", "destination": "SIEM"},
            {"type": "Application Log", "source": "Authentication Events", "destination": "SIEM"}
        ],
        "source_artifacts": [
            {"type": "Log File", "location": "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx", "identify": "Device Registration Logs"}
        ],
        "destination_artifacts": [
            {"type": "Log File", "location": "/var/log/auth.log", "identify": "Unauthorized Device Enrollment"}
        ],
        "detection_methods": [
            "Monitor for unauthorized device enrollments in MFA and Entra ID.",
            "Correlate device registration logs with suspicious user activity."
        ],
        "apt": ["APT29", "CrowdStrike TELCO BPO Campaign", "Mandiant APT29 Microsoft 365"],  
        "spl_query": [
            "index=security EventCode=4769 OR EventCode=4776 OR EventCode=4624\n| table _time, Account_Name, Device_ID, Source_IP"
        ],  
        "hunt_steps": [
            "Identify recent device enrollments in MFA and Intune.",
            "Check for unauthorized device associations with compromised accounts.",
            "Investigate related login activity for persistence indicators."
        ],  
        "expected_outcomes": [
            "Unauthorized device enrollments detected.",
            "Compromised accounts identified and secured."
        ],  
        "false_positive": "Legitimate users registering new devices.",  
        "clearing_steps": [
            "Revoke unauthorized device registrations.",
            "Strengthen MFA policies to prevent self-enrollment abuse."
        ],  
        "mitre_mapping": [
            {"tactic": "Persistence", "technique": "Account Manipulation", "example": "Registering new devices to compromised accounts"}
        ],  
        "watchlist": [
            "Suspicious new device registrations.",
            "Unexpected MFA bypass activities."
        ],  
        "enhancements": [
            "Enable alerts for device registration from unusual locations.",
            "Use risk-based authentication to detect anomalous device enrollments."
        ],  
        "summary": "Adversaries may register devices to maintain access and bypass security policies.",  
        "remediation": "Regularly review device registrations and enforce strict MFA enrollment controls.",  
        "improvements": "Implement conditional access policies to restrict unauthorized device registrations."  
    }