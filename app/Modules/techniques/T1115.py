def get_content():
    return {
        "id": "T1115",  # Tactic Technique ID
        "url_id": "1115",  # URL segment for technique reference
        "title": "Clipboard Data",  # Name of the attack technique
        "description": "Adversaries may collect data stored in the clipboard from users copying information within or between applications. For example, on Windows adversaries can access clipboard data by using clip.exe or Get-Clipboard. Additionally, adversaries may monitor then replace users’ clipboard with their data (e.g., Transmitted Data Manipulation). macOS and Linux also have commands, such as pbpaste, to grab clipboard contents.",  
        "tags": [
            "t1115", 
            "clipboard data", 
            "copy paste attack", 
            "get-clipboard", 
            "clip.exe", 
            "clipboard hijacking", 
            "data theft", 
            "linux pbpaste", 
            "windows clipboard exploit", 
            "macos clipboard attack"
        ],  
        "tactic": "Collection",  
        "protocol": "System APIs",  
        "os": "Linux, Windows, macOS",  
        "tips": [
            "Monitor clipboard activity for unauthorized access and suspicious data transfers.",
            "Restrict clipboard access for untrusted applications.",
            "Enable endpoint protection solutions to detect clipboard hijacking.",
            "Analyze command execution logs for Get-Clipboard or clip.exe usage."
        ],  
        "data_sources": "Command: Command Execution, Process: OS API Execution",  
        "log_sources": [  
            {"type": "System Logs", "source": "Clipboard Access", "destination": "Security Monitoring"}  
        ],  
        "source_artifacts": [  
            {"type": "Clipboard Data", "location": "Memory", "identify": "Clipboard Content Extraction"},  
            {"type": "Command Execution", "location": "System Logs", "identify": "Get-Clipboard / clip.exe usage"}  
        ],  
        "destination_artifacts": [  
            {"type": "Log File", "location": "/var/log/security.log", "identify": "Clipboard Access Logs"}  
        ],  
        "detection_methods": ["Monitoring Clipboard API Access", "Analyzing System Logs for Clipboard Reads"],  
        "apt": ["APT38", "DarkTortilla", "Agent Tesla"],  
        "spl_query": ["index=security_logs | search clipboard_access"],  
        "hunt_steps": ["Detect clipboard access via command-line tools.", "Monitor for sudden clipboard content modifications."],  
        "expected_outcomes": ["Detection of clipboard data collection used for stealing sensitive information."],  
        "false_positive": "Legitimate applications may access clipboard data, such as password managers.",  
        "clearing_steps": ["Restrict clipboard access permissions.", "Monitor system logs for unauthorized clipboard usage."],  
        "mitre_mapping": [
            {"tactic": "Collection", "technique": "T1115", "example": "Malware accessing clipboard data to steal credentials."}
        ],  
        "watchlist": ["Unusual clipboard access patterns", "Processes frequently reading clipboard data"],  
        "enhancements": ["Implement clipboard access control policies.", "Use security tools to detect clipboard hijacking attempts."],  
        "summary": "Adversaries may use clipboard access to steal sensitive data copied by users, such as passwords and personal information.",  
        "remediation": "Restrict clipboard access, monitor API usage, and analyze logs for suspicious behavior.",  
        "improvements": "Enhance endpoint security solutions to flag unauthorized clipboard access."  
    }
