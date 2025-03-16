def get_content():
    return {
        "id": "T1037.005",  # Tactic Technique ID
        "url_id": "1037/005",  # URL segment for technique reference
        "title": "Boot or Logon Initialization Scripts: Startup Items",  # Name of the attack technique
        "description": "Adversaries may use startup items automatically executed at boot initialization to establish persistence. Startup items execute during the final phase of the boot process and contain shell scripts or other executable files along with configuration information used by the system to determine the execution order for all startup items. This is technically a deprecated technology (superseded by Launch Daemon), and thus the appropriate folder, /Library/StartupItems isn’t guaranteed to exist on the system by default, but does appear to exist by default on macOS Sierra. A startup item is a directory whose executable and configuration property list (plist), StartupParameters.plist, reside in the top-level directory. An adversary can create the appropriate folders/files in the StartupItems directory to register their own persistence mechanism. Additionally, since StartupItems run during the bootup phase of macOS, they will run as the elevated root user.",  
        "tags": [],  
        "tactic": "Persistence, Privilege Escalation",  
        "protocol": "macOS",  
        "os": "macOS",  
        "tips": [
            "Monitor the /Library/StartupItems folder for changes.",
            "Check programs executed from this mechanism against a whitelist.",
            "Monitor processes that are executed during the bootup process for unusual or unknown applications and behavior."
        ],  
        "data_sources": "Command: Command Execution, File: File Creation, File: File Modification, Process: Process Creation",  
        "log_sources": [  
            {"type": "File Monitoring", "source": "/Library/StartupItems", "destination": "System Logs"}  
        ],  
        "source_artifacts": [  
            {"type": "Startup Item", "location": "/Library/StartupItems", "identify": "macOS Startup Item"}  
        ],  
        "destination_artifacts": [  
            {"type": "Log File", "location": "/var/log/system.log", "identify": "System Log for Startup Item Execution"}  
        ],  
        "detection_methods": ["File Integrity Monitoring", "Process Execution Analysis"],  
        "apt": ["Adwind"],  
        "spl_query": ["index=mac_logs | search startup_item"],  
        "hunt_steps": ["Check for unauthorized modifications to startup items.", "Analyze execution patterns of startup scripts."],  
        "expected_outcomes": ["Detection of unauthorized startup item execution."],  
        "false_positive": "Legitimate system administration startup items may trigger alerts.",  
        "clearing_steps": ["Remove unauthorized startup items from the system.", "Reset macOS startup configurations."],  
        "mitre_mapping": [
            {"tactic": "Persistence", "technique": "T1037", "example": "Startup items used for malware persistence on macOS."}
        ],  
        "watchlist": ["Unusual modifications to StartupItems", "Execution of startup scripts by unexpected users"],  
        "enhancements": ["Restrict write access to StartupItems directory.", "Enable logging of startup script execution events."],  
        "summary": "Startup items can be exploited by adversaries to maintain persistence and escalate privileges on macOS systems.",  
        "remediation": "Monitor and restrict startup item execution policies to prevent unauthorized modifications.",  
        "improvements": "Implement file integrity monitoring (FIM) to detect unauthorized startup item changes."  
    }
