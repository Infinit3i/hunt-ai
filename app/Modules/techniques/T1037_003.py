def get_content():
    return {
        "id": "T1037.003",  # Tactic Technique ID
        "url_id": "1037/003",  # URL segment for technique reference
        "title": "Boot or Logon Initialization Scripts: Network Logon Script",  # Name of the attack technique
        "description": "Adversaries may use network logon scripts automatically executed at logon initialization to establish persistence. Network logon scripts can be assigned using Active Directory or Group Policy Objects. These logon scripts run with the privileges of the user they are assigned to. Depending on the systems within the network, initializing one of these scripts could apply to more than one or potentially all systems. Adversaries may use these scripts to maintain persistence on a network. Depending on the access configuration of the logon scripts, either local credentials or an administrator account may be necessary.",  
        "tags": [],  
        "tactic": "Persistence, Privilege Escalation",  
        "protocol": "Windows",  
        "os": "Windows",  
        "tips": [
            "Monitor logon scripts for unusual access by abnormal users or at abnormal times.",
            "Look for files added or modified by unusual accounts outside of normal administration duties.",
            "Monitor running processes for actions that could be indicative of abnormal programs or executables running upon logon."
        ],  
        "data_sources": "Active Directory: Active Directory Object Modification, Command: Command Execution, File: File Creation, File: File Modification, Process: Process Creation",  
        "log_sources": [  
            {"type": "Active Directory", "source": "Logon Scripts", "destination": "Process Creation"}  
        ],  
        "source_artifacts": [  
            {"type": "Logon Script", "location": "\\\\DomainController\\Netlogon\\", "identify": "Network Logon Script"}  
        ],  
        "destination_artifacts": [  
            {"type": "Log File", "location": "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx", "identify": "Windows Logon Event Logs"}  
        ],  
        "detection_methods": ["Logon Script Monitoring", "Process Execution Analysis"],  
        "apt": [],  
        "spl_query": ["index=windows_logs | search network_logon_script"],  
        "hunt_steps": ["Check for unauthorized modifications to network logon scripts.", "Analyze execution patterns of logon scripts across systems."],  
        "expected_outcomes": ["Detection of unauthorized network logon script execution."],  
        "false_positive": "Legitimate administrative logon scripts may trigger alerts.",  
        "clearing_steps": ["Remove unauthorized network logon scripts from Active Directory.", "Reset network logon script configurations."],  
        "mitre_mapping": [
            {"tactic": "Persistence", "technique": "T1037", "example": "Network logon scripts used for malware persistence in enterprise environments."}
        ],  
        "watchlist": ["Unusual Active Directory modifications", "Execution of network logon scripts by unexpected users"],  
        "enhancements": ["Restrict write access to network logon script locations.", "Enable logging of network logon script execution events."],  
        "summary": "Network logon scripts can be exploited by adversaries to maintain persistence and escalate privileges within a Windows network.",  
        "remediation": "Monitor and restrict network logon script execution policies to prevent unauthorized modifications.",  
        "improvements": "Implement Group Policy Object (GPO) monitoring to detect unauthorized script changes."  
    }
