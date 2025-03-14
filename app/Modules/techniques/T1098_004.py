# attack_technique_T1098_004.py

def get_content():
    return {
        "id": "T1098.004",  
        "url_id": "T1098/004",  
        "title": "Account Manipulation: SSH Authorized Keys",  
        "description": "Adversaries may modify the SSH authorized_keys file to maintain persistence on a victim host by enabling key-based authentication for unauthorized access.",  
        "tags": [
            "SSH attack", "authorized_keys modification", "persistence attack", "privilege escalation", 
            "Linux security", "macOS security", "cloud security", "SSH key abuse", 
            "Google Cloud SSH attack", "Azure VM SSH exploitation"
        ],  
        "tactic": "Persistence, Privilege Escalation",  
        "protocol": "SSH",  
        "os": ["Linux", "macOS", "Network"],  
        "tips": [
            "Monitor for changes in ~/.ssh/authorized_keys files across critical user accounts.",
            "Use file integrity monitoring to detect unauthorized modifications to SSH configuration files.",
            "Audit API requests for adding SSH keys in cloud environments like AWS, Azure, and GCP."
        ],  
        "data_sources": [
            "Command Execution", "File Modification", "Process Creation", "Cloud Metadata Modification"
        ],  
        "log_sources": [
            {"type": "File Integrity", "source": "/etc/ssh/sshd_config", "destination": "SIEM"},
            {"type": "Command Execution", "source": "Bash History", "destination": "SIEM"},
            {"type": "Cloud API Logs", "source": "GCP IAM Logs", "destination": "SIEM"}
        ],
        "source_artifacts": [
            {"type": "Log File", "location": "/var/log/auth.log", "identify": "Unauthorized SSH Key Changes"}
        ],
        "destination_artifacts": [
            {"type": "Log File", "location": "/root/.ssh/authorized_keys", "identify": "Modified SSH Keys"}
        ],
        "detection_methods": [
            "Monitor SSH authorized_keys modifications across user accounts.",
            "Analyze SSH session logs for unauthorized public key authentications."
        ],
        "apt": ["Earth Lusca", "TeamTNT", "Skidmap", "Bundlore"],  
        "spl_query": [
            "index=security source=/var/log/auth.log \"Added SSH Key\"\n| table _time, Account_Name, SSH_Key, Source_IP"
        ],  
        "hunt_steps": [
            "Identify recently modified authorized_keys files.",
            "Check cloud API logs for unauthorized SSH key additions.",
            "Investigate privilege escalation attempts using SSH keys."
        ],  
        "expected_outcomes": [
            "Unauthorized SSH key additions detected.",
            "Compromised accounts identified and mitigated."
        ],  
        "false_positive": "System administrators adding SSH keys for legitimate remote access.",  
        "clearing_steps": [
            "Review and remove unauthorized SSH keys from user accounts.",
            "Enforce SSH key-based access policies with strong monitoring controls."
        ],  
        "mitre_mapping": [
            {"tactic": "Persistence", "technique": "Account Manipulation", "example": "Adding SSH keys for unauthorized access"}
        ],  
        "watchlist": [
            "New SSH keys added to critical user accounts.",
            "Suspicious modifications to SSH configuration files."
        ],  
        "enhancements": [
            "Enable alerts for unauthorized SSH key modifications.",
            "Restrict SSH key addition privileges to specific users."
        ],  
        "summary": "Attackers can modify SSH authorized_keys files to maintain persistence and escalate privileges on a target system.",  
        "remediation": "Regularly audit SSH key usage and restrict key-based authentication to trusted sources.",  
        "improvements": "Implement least-privilege access controls and enforce key rotation policies."  
    }
