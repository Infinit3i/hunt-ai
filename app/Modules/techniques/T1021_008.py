def get_content():
    return {
        "id": "T1021.008",
        "url_id": "T1021/008",
        "title": "Remote Services: Direct Cloud VM Connections",
        "description": "Adversaries may log into cloud-hosted VMs using valid credentials through cloud-native services like Azure Serial Console or AWS EC2 Instance Connect.",
        "tags": ["cloud", "vm", "console", "serial access", "ec2", "azure", "lateral movement", "valid accounts"],
        "tactic": "Lateral Movement",
        "protocol": "HTTPS (Cloud Native Console/API)",
        "os": "IaaS",
        "tips": [
            "Audit cloud IAM policies and restrict use of Serial Console or Instance Connect to essential roles only.",
            "Monitor cloud service logs for console or session starts from unfamiliar users or IPs.",
            "Enforce the use of multi-factor authentication and rotate SSH keys regularly."
        ],
        "data_sources": "Logon Session",
        "log_sources": [
            {"type": "Logon Session", "source": "Cloud Audit Logs", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Logon Session", "location": "AWS CloudTrail, Azure Activity Logs", "identify": "instance connect or serial console sessions"},
            {"type": "Environment Variables", "location": "/home/<user>/ or user profile", "identify": "presence of temporary tokens or SSH credentials"},
            {"type": "Memory Dumps", "location": "VM RAM", "identify": "token data, commands, and shell activity from console session"}
        ],
        "destination_artifacts": [
            {"type": "Logon Session", "location": "Cloud-hosted VM system logs", "identify": "root/system shell session"},
            {"type": "Process List", "location": "Running on VM", "identify": "interactive shell launched from system"},
            {"type": "Network Connections", "location": "VM or instance firewall logs", "identify": "internal lateral movement following console access"}
        ],
        "detection_methods": [
            "Monitor console access events in cloud audit logs",
            "Alert on privileged session creation using native cloud methods",
            "Detect anomalous login times and locations for cloud console access"
        ],
        "apt": ["N/A"],
        "spl_query": [
            'index=aws sourcetype="aws:cloudtrail" eventName="SendSSHPublicKey" OR eventName="StartSession" \n| stats count by userIdentity.arn, sourceIPAddress',
            'index=azure sourcetype="azure:activity" OperationName="Serial Console Access" \n| table Caller, ActivityStatus, TimeGenerated'
        ],
        "hunt_steps": [
            "Search for serial console or instance connect logins",
            "Correlate sessions with actions taken on the VM (commands, file access)",
            "Identify use of access tokens or ephemeral credentials"
        ],
        "expected_outcomes": [
            "Identify unauthorized or uncommon direct VM access via cloud-native services",
            "Detect pivoting from cloud consoles into the virtual infrastructure",
            "Flag privilege abuse through root/system level interactive sessions"
        ],
        "false_positive": "Cloud administrators may legitimately use these tools for troubleshooting; build a baseline for known user behavior and roles.",
        "clearing_steps": [
            "Revoke or rotate cloud IAM credentials used",
            "Terminate console sessions and disable serial access temporarily",
            "Audit affected VM for persistence mechanisms or file drops"
        ],
        "mitre_mapping": [
            {"tactic": "Persistence", "technique": "T1053.003", "example": "Scheduled tasks or cron jobs configured via console session"},
            {"tactic": "Defense Evasion", "technique": "T1562.001", "example": "Disable monitoring agents during console access"}
        ],
        "watchlist": [
            "Serial Console or EC2 Instance Connect usage from unknown IP ranges",
            "Cloud CLI users performing direct console access",
            "Multiple failed login attempts followed by successful token-based access"
        ],
        "enhancements": [
            "Limit cloud-native console access to break-glass accounts",
            "Enable session recording where possible (e.g., AWS Systems Manager)",
            "Deploy honeypots configured with alerting on console connection"
        ],
        "summary": "Adversaries may exploit cloud-native tools to connect directly to virtual machines, bypassing traditional network access paths and performing lateral movement via privileged interactive sessions.",
        "remediation": "Restrict access to cloud-native VM console methods. Apply least privilege to IAM roles and enforce tight network segmentation.",
        "improvements": "Enhance logging for all console-related access, correlate activity with endpoint agents, and use conditional access policies.",
        "mitre_version": "16.1"
    }
