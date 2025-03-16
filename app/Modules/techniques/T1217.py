def get_content():
    return {
        "id": "T1217",  # Tactic Technique ID
        "url_id": "1217",  # URL segment for technique reference
        "title": "Browser Information Discovery",  # Name of the attack technique
        "description": "Adversaries may enumerate information about browsers to learn more about compromised environments. Data saved by browsers (such as bookmarks, accounts, and browsing history) may reveal a variety of personal information about users (e.g., banking sites, relationships/interests, social media, etc.) as well as details about internal network resources such as servers, tools/dashboards, or other related infrastructure. Browser information may also highlight additional targets after an adversary has access to valid credentials, especially Credentials In Files associated with logins cached by a browser. Specific storage locations vary based on platform and/or application, but browser information is typically stored in local files and databases (e.g., %APPDATA%/Google/Chrome).",  
        "tags": [],  
        "tactic": "Discovery",  
        "protocol": "Linux, Windows, macOS",  
        "os": "Linux, Windows, macOS",  
        "tips": [
            "Monitor processes and command-line arguments for actions that could be taken to gather browser bookmark information.",
            "Remote access tools with built-in features may interact directly using APIs to gather information.",
            "Information may also be acquired through system management tools such as Windows Management Instrumentation (WMI) and PowerShell.",
            "Monitor system logs for unexpected access to browser profile directories."
        ],  
        "data_sources": "Command: Command Execution, File: File Access, Process: Process Creation",  
        "log_sources": [  
            {"type": "File Monitoring", "source": "Browser Profile Directories", "destination": "System Logs"}  
        ],  
        "source_artifacts": [  
            {"type": "Browser Data", "location": "%APPDATA%/Google/Chrome", "identify": "Chrome User Data"},  
            {"type": "Browser Data", "location": "~/Library/Application Support/Firefox", "identify": "Firefox User Data"}  
        ],  
        "destination_artifacts": [  
            {"type": "Log File", "location": "/var/log/system.log", "identify": "Browser Access Logs"}  
        ],  
        "detection_methods": ["File Access Monitoring", "Process Execution Analysis"],  
        "apt": ["Dtrack", "Lizar", "Moonstone Sleet", "Metador", "Scattered Spider"],  
        "spl_query": ["index=system_logs | search browser_data_access"],  
        "hunt_steps": ["Check for unauthorized access to browser data files.", "Analyze execution patterns of commands interacting with browser storage."],  
        "expected_outcomes": ["Detection of unauthorized browser information enumeration."],  
        "false_positive": "Legitimate system maintenance tools may access browser data.",  
        "clearing_steps": ["Restrict access to browser profile directories.", "Clear stored browser data and enforce security policies."],  
        "mitre_mapping": [
            {"tactic": "Discovery", "technique": "T1217", "example": "Browser data used for gathering user credentials and reconnaissance."}
        ],  
        "watchlist": ["Unexpected access to browser storage", "Processes querying browser data files"],  
        "enhancements": ["Restrict access to browser profile directories using permissions.", "Enable logging of browser data access events."],  
        "summary": "Browser information discovery allows adversaries to gather user credentials, personal information, and reconnaissance on internal network resources.",  
        "remediation": "Monitor and restrict access to browser profile directories to prevent unauthorized enumeration.",  
        "improvements": "Implement endpoint detection rules to flag suspicious access to browser storage locations."  
    }
