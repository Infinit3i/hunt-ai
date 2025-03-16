def get_content():
    return {
        "id": "T1037",  # Tactic Technique ID
        "url_id": "1037",  # URL segment for technique reference
        "title": "Boot or Logon Initialization Scripts",  # Name of the attack technique
        "description": "Adversaries may use scripts automatically executed at boot or logon initialization to establish persistence. Initialization scripts can be used to perform administrative functions, which may often execute other programs or send information to an internal logging server. These scripts can vary based on operating system and whether applied locally or remotely. Adversaries may use these scripts to maintain persistence on a single system. Depending on the access configuration of the logon scripts, either local credentials or an administrator account may be necessary. An adversary may also be able to escalate their privileges since some boot or logon initialization scripts run with higher privileges.",  
        "tags": [],  
        "tactic": "Persistence, Privilege Escalation",  
        "protocol": "Linux, Network, Windows, macOS",  
        "os": "Linux, Windows, macOS",  
        "tips": [
            "Monitor logon scripts for unusual access by abnormal users or at abnormal times.",
            "Look for files added or modified by unusual accounts outside of normal administration duties.",
            "Monitor running processes for actions that could be indicative of abnormal programs or executables running upon logon."
        ],  
        "data_sources": "Active Directory: Active Directory Object Modification, Command: Command Execution, File: File Creation, File: File Modification, Process: Process Creation, Windows Registry: Windows Registry Key Creation",  
        "log_sources": [  
            {"type": "Process", "source": "Logon Scripts", "destination": "Process Creation"}  
        ],  
        "source_artifacts": [  
            {"type": "Script File", "location": "/etc/init.d/", "identify": "Startup scripts on Linux"},  
            {"type": "Registry Key", "location": "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "identify": "Windows startup scripts"}  
        ],  
        "destination_artifacts": [  
            {"type": "Log File", "location": "/var/log/auth.log", "identify": "Logon script executions"}  
        ],  
        "detection_methods": ["Script Monitoring", "Process Execution Analysis"],  
        "apt": ["APT29", "APT41", "Rocke"],  
        "spl_query": ["index=system_logs | search logon_script"],  
        "hunt_steps": ["Check for unauthorized script modifications.", "Analyze execution patterns of boot scripts."],  
        "expected_outcomes": ["Detection of unauthorized boot or logon script execution."],  
        "false_positive": "Legitimate system administration scripts may trigger alerts.",  
        "clearing_steps": ["Remove unauthorized scripts from startup directories.", "Reset system logon script configurations."],  
        "mitre_mapping": [
            {"tactic": "Persistence", "technique": "T1547", "example": "Logon scripts used for malware persistence."}
        ],  
        "watchlist": ["Unusual script modifications", "Execution of scripts by unexpected users"],  
        "enhancements": ["Restrict write access to logon script locations.", "Enable logging of script execution events."],  
        "summary": "Boot or logon initialization scripts can be exploited by adversaries to maintain persistence and escalate privileges.",  
        "remediation": "Monitor and restrict script execution policies to prevent unauthorized modifications.",  
        "improvements": "Implement script whitelisting to prevent execution of unauthorized scripts."  
    }
