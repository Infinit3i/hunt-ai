def get_content():
    return {
        "id": "T1037.001",  # Tactic Technique ID
        "url_id": "1037/001",  # URL segment for technique reference
        "title": "Boot or Logon Initialization Scripts: Logon Script (Windows)",  # Name of the attack technique
        "description": "Adversaries may use Windows logon scripts automatically executed at logon initialization to establish persistence. Windows allows logon scripts to be run whenever a specific user or group of users log into a system. This is done via adding a path to a script to the HKCU\\Environment\\UserInitMprLogonScript Registry key. Adversaries may use these scripts to maintain persistence on a single system. Depending on the access configuration of the logon scripts, either local credentials or an administrator account may be necessary.",  
        "tags": [],  
        "tactic": "Persistence, Privilege Escalation",  
        "protocol": "Windows",  
        "os": "Windows",  
        "tips": [
            "Monitor for changes to Registry values associated with Windows logon scripts, namely HKCU\\Environment\\UserInitMprLogonScript.",
            "Monitor running processes for actions that could be indicative of abnormal programs or executables running upon logon."
        ],  
        "data_sources": "Command: Command Execution, Process: Process Creation, Windows Registry: Windows Registry Key Creation",  
        "log_sources": [  
            {"type": "Registry", "source": "HKCU\\Environment\\UserInitMprLogonScript", "destination": "Registry Logs"}  
        ],  
        "source_artifacts": [  
            {"type": "Registry Key", "location": "HKCU\\Environment\\UserInitMprLogonScript", "identify": "Windows Logon Script"}  
        ],  
        "destination_artifacts": [  
            {"type": "Log File", "location": "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx", "identify": "Windows Logon Event Logs"}  
        ],  
        "detection_methods": ["Registry Monitoring", "Process Behavior Analysis"],  
        "apt": ["Kimsuky", "Cobalt Gang", "Zebrocy", "Attor", "Seduploader"],  
        "spl_query": ["index=windows_registry | search logon_script"],  
        "hunt_steps": ["Check for unauthorized modifications to Windows logon scripts.", "Analyze execution patterns of logon scripts."],  
        "expected_outcomes": ["Detection of unauthorized Windows logon script execution."],  
        "false_positive": "Legitimate administrative scripts may modify logon script registry keys.",  
        "clearing_steps": ["Remove unauthorized logon scripts from the registry.", "Reset system logon script configurations."],  
        "mitre_mapping": [
            {"tactic": "Persistence", "technique": "T1037", "example": "Logon scripts used for malware persistence on Windows."}
        ],  
        "watchlist": ["Unusual registry modifications", "Execution of logon scripts by unexpected users"],  
        "enhancements": ["Restrict write access to logon script registry keys.", "Enable logging of logon script execution events."],  
        "summary": "Windows logon scripts can be exploited by adversaries to maintain persistence and escalate privileges.",  
        "remediation": "Monitor and restrict logon script execution policies to prevent unauthorized modifications.",  
        "improvements": "Implement registry whitelisting to prevent unauthorized logon script modifications."  
    }
