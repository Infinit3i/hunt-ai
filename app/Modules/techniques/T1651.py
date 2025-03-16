def get_content():
    return {
        "id": "T1651",  # Tactic Technique ID
        "url_id": "1651",  # URL segment for technique reference
        "title": "Cloud Administration Command",  # Name of the attack technique
        "description": "Adversaries may abuse cloud management services to execute commands within virtual machines. Resources such as AWS Systems Manager, Azure RunCommand, and Runbooks allow users to remotely run scripts in virtual machines by leveraging installed virtual machine agents. If an adversary gains administrative access to a cloud environment, they may be able to abuse cloud management services to execute commands in the environment’s virtual machines. Additionally, an adversary that compromises a service provider or delegated administrator account may similarly be able to leverage a Trusted Relationship to execute commands in connected virtual machines.",  
        "tags": [
            "t1651", 
            "cloud administration command", 
            "aws systems manager", 
            "azure runcommand", 
            "cloud attack", 
            "virtual machine exploitation", 
            "cloud execution", 
            "cloud security", 
            "trusted relationship abuse", 
            "remote script execution"
        ],  
        "tactic": "Execution",  
        "protocol": "IaaS",  
        "os": "Cloud Environments",  
        "tips": [
            "Monitor cloud management service logs for unusual command executions.",
            "Restrict administrative access to cloud management tools.",
            "Use role-based access control (RBAC) to limit command execution permissions.",
            "Enable multi-factor authentication (MFA) for cloud administrator accounts."
        ],  
        "data_sources": "Command: Command Execution, Process: Process Creation, Script: Script Execution",  
        "log_sources": [  
            {"type": "Cloud Logs", "source": "AWS Systems Manager", "destination": "Security Monitoring"},  
            {"type": "Cloud Logs", "source": "Azure RunCommand", "destination": "SIEM"}  
        ],  
        "source_artifacts": [  
            {"type": "Execution Logs", "location": "Cloud Console", "identify": "Admin Command Executions"},  
            {"type": "Audit Logs", "location": "Cloud Provider Logs", "identify": "Unexpected Script Execution"}  
        ],  
        "destination_artifacts": [  
            {"type": "Log File", "location": "/var/log/cloud-admin.log", "identify": "Cloud Admin Execution Logs"}  
        ],  
        "detection_methods": ["Cloud Activity Monitoring", "SIEM Rule Analysis for Unexpected Command Execution"],  
        "apt": ["APT29", "Mandiant Nobelium"],  
        "spl_query": ["index=cloud_logs | search admin_command_execution"],  
        "hunt_steps": ["Detect unexpected admin-level cloud command executions.", "Monitor for excessive privilege escalations in cloud environments."],  
        "expected_outcomes": ["Detection of unauthorized cloud command executions used for malicious activity."],  
        "false_positive": "Legitimate cloud admin tasks may trigger command executions.",  
        "clearing_steps": ["Review admin access logs.", "Audit IAM roles and permissions for least privilege enforcement."],  
        "mitre_mapping": [
            {"tactic": "Execution", "technique": "T1651", "example": "Cloud administrators executing unexpected scripts on virtual machines."}
        ],  
        "watchlist": ["Unusual cloud command executions", "Abnormal IAM role modifications"],  
        "enhancements": ["Implement least privilege access to cloud administration tools.", "Use behavioral analytics to detect abnormal admin activity."],  
        "summary": "Cloud administration tools can be abused to execute commands on virtual machines, allowing adversaries to run malicious scripts remotely.",  
        "remediation": "Restrict access to cloud administration tools and monitor for unauthorized executions.",  
        "improvements": "Enhance cloud logging and implement automated anomaly detection for admin command usage."  
    }
