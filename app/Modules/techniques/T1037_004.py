def get_content():
    return {
        "id": "T1037.004",  # Tactic Technique ID
        "url_id": "1037/004",  # URL segment for technique reference
        "title": "Boot or Logon Initialization Scripts: RC Scripts",  # Name of the attack technique
        "description": "Adversaries may establish persistence by modifying RC scripts which are executed during a Unix-like system’s startup. These files allow system administrators to map and start custom services at startup for different run levels. RC scripts require root privileges to modify. Adversaries can establish persistence by adding a malicious binary path or shell commands to rc.local, rc.common, and other RC scripts specific to the Unix-like distribution. Upon reboot, the system executes the script's contents as root, resulting in persistence. Adversary abuse of RC scripts is especially effective for lightweight Unix-like distributions using the root user as default, such as IoT or embedded systems. Several Unix-like systems have moved to Systemd and deprecated the use of RC scripts. This is now a deprecated mechanism in macOS in favor of Launchd. This technique can be used on Mac OS X Panther v10.3 and earlier versions which still execute the RC scripts. To maintain backwards compatibility some systems, such as Ubuntu, will execute the RC scripts if they exist with the correct file permissions.",  
        "tags": [],  
        "tactic": "Persistence, Privilege Escalation",  
        "protocol": "Linux, Network, macOS",  
        "os": "Linux, macOS",  
        "tips": [
            "Monitor for unexpected changes to RC scripts in the /etc/ directory.",
            "Monitor process execution resulting from RC scripts for unusual or unknown applications or behavior.",
            "Monitor for /etc/rc.local file creation, as several Unix-like distributions execute this script if present."
        ],  
        "data_sources": "Command: Command Execution, File: File Creation, File: File Modification, Process: Process Creation",  
        "log_sources": [  
            {"type": "File Monitoring", "source": "/etc/rc.local", "destination": "Process Creation Logs"}  
        ],  
        "source_artifacts": [  
            {"type": "RC Script", "location": "/etc/rc.local", "identify": "Linux Startup Script"}  
        ],  
        "destination_artifacts": [  
            {"type": "Log File", "location": "/var/log/syslog", "identify": "System Log for RC Script Execution"}  
        ],  
        "detection_methods": ["File Integrity Monitoring", "Process Execution Analysis"],  
        "apt": ["APT29", "Cyclops Blink", "Green Lambert"],  
        "spl_query": ["index=linux_logs | search rc_script"],  
        "hunt_steps": ["Check for unauthorized modifications to RC scripts.", "Analyze execution patterns of RC scripts."],  
        "expected_outcomes": ["Detection of unauthorized RC script execution."],  
        "false_positive": "Legitimate system administration RC scripts may trigger alerts.",  
        "clearing_steps": ["Remove unauthorized RC script modifications.", "Reset system startup configurations."],  
        "mitre_mapping": [
            {"tactic": "Persistence", "technique": "T1037", "example": "RC scripts used for malware persistence on Linux."}
        ],  
        "watchlist": ["Unusual modifications to RC scripts", "Execution of RC scripts by unexpected users"],  
        "enhancements": ["Restrict write access to RC script locations.", "Enable logging of RC script execution events."],  
        "summary": "RC scripts can be exploited by adversaries to maintain persistence and escalate privileges on Unix-like systems.",  
        "remediation": "Monitor and restrict RC script execution policies to prevent unauthorized modifications.",  
        "improvements": "Implement file integrity monitoring (FIM) to detect unauthorized RC script changes."  
    }
