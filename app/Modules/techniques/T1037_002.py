def get_content():
    return {
        "id": "T1037.002",  # Tactic Technique ID
        "url_id": "1037/002",  # URL segment for technique reference
        "title": "Boot or Logon Initialization Scripts: Login Hook",  # Name of the attack technique
        "description": "Adversaries may use a Login Hook to establish persistence executed upon user logon. A login hook is a plist file that points to a specific script to execute with root privileges upon user logon. The plist file is located in the /Library/Preferences/com.apple.loginwindow.plist file and can be modified using the defaults command-line utility. This behavior is the same for logout hooks where a script can be executed upon user logout. All hooks require administrator permissions to modify or create hooks. Adversaries can add or insert a path to a malicious script in the com.apple.loginwindow.plist file, using the LoginHook or LogoutHook key-value pair. The malicious script is executed upon the next user login. If a login hook already exists, adversaries can add additional commands to an existing login hook. There can be only one login and logout hook on a system at a time. Note: Login hooks were deprecated in 10.11 version of macOS in favor of Launch Daemon and Launch Agent.",  
        "tags": [],  
        "tactic": "Persistence, Privilege Escalation",  
        "protocol": "macOS",  
        "os": "macOS",  
        "tips": [
            "Monitor logon scripts for unusual access by abnormal users or at abnormal times.",
            "Look for files added or modified by unusual accounts outside of normal administration duties.",
            "Monitor running processes for actions that could be indicative of abnormal programs or executables running upon logon."
        ],  
        "data_sources": "Command: Command Execution, File: File Creation, File: File Modification, Process: Process Creation",  
        "log_sources": [  
            {"type": "Process", "source": "Login Hooks", "destination": "Process Creation"}  
        ],  
        "source_artifacts": [  
            {"type": "Plist File", "location": "/Library/Preferences/com.apple.loginwindow.plist", "identify": "Login Hook Configuration"}  
        ],  
        "destination_artifacts": [  
            {"type": "Log File", "location": "/var/log/system.log", "identify": "Login Hook Executions"}  
        ],  
        "detection_methods": ["Script Monitoring", "Process Execution Analysis"],  
        "apt": [],  
        "spl_query": ["index=mac_logs | search login_hook"],  
        "hunt_steps": ["Check for unauthorized modifications to login hooks.", "Analyze execution patterns of login scripts."],  
        "expected_outcomes": ["Detection of unauthorized login hook execution."],  
        "false_positive": "Legitimate administrative scripts may trigger alerts.",  
        "clearing_steps": ["Remove unauthorized login hooks from plist configuration.", "Reset system login hook settings."],  
        "mitre_mapping": [
            {"tactic": "Persistence", "technique": "T1037", "example": "Login hooks used for malware persistence on macOS."}
        ],  
        "watchlist": ["Unusual plist modifications", "Execution of login scripts by unexpected users"],  
        "enhancements": ["Restrict write access to login hook locations.", "Enable logging of login hook execution events."],  
        "summary": "Login Hooks can be exploited by adversaries to maintain persistence and escalate privileges on macOS systems.",  
        "remediation": "Monitor and restrict login hook execution policies to prevent unauthorized modifications.",  
        "improvements": "Implement script whitelisting to prevent execution of unauthorized login hooks."  
    }
