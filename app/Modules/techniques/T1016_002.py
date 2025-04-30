def get_content():
    return {
        "id": "T1016.002",
        "url_id": "T1016/002",
        "title": "System Network Configuration Discovery: Wi-Fi Discovery",
        "description": "Adversaries may gather information about known and nearby Wi-Fi networks to support further discovery or credential theft.",
        "tags": ["wifi", "network discovery", "wireless", "password extraction", "netsh", "security find-generic-password"],
        "tactic": "Discovery",
        "protocol": "Wi-Fi",
        "os": "Linux, Windows, macOS",
        "tips": [
            "Hunt for use of netsh wlan and other native commands from unusual parent processes.",
            "Correlate system access to WLAN password file locations and extraction tools.",
            "Review registry and memory analysis for cleartext storage of Wi-Fi credentials."
        ],
        "data_sources": "Sysmon, Command, Process",
        "log_sources": [
            {"type": "Sysmon", "source": "", "destination": ""},
            {"type": "Command", "source": "", "destination": ""},
            {"type": "Process", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Command History", "location": "%APPDATA%\\Microsoft\\Windows\\PowerShell\\PSReadline\\ConsoleHost_history.txt", "identify": "netsh wlan show profiles"},
            {"type": "Process List", "location": "Sysmon Event ID 1", "identify": "netsh wlan or security find-generic-password"},
            {"type": "Wi-Fi Profiles", "location": "/etc/NetworkManager/system-connections/", "identify": "Wi-Fi configuration files with stored credentials"}
        ],
        "destination_artifacts": [
            {"type": "Registry Hives", "location": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Wlansvc", "identify": "Wi-Fi profiles and connection history"},
            {"type": "Windows Defender Logs", "location": "Event Viewer", "identify": "Suspicious credential access behaviors"},
            {"type": "Clipboard Data", "location": "RAM or clipboard forensics", "identify": "Wi-Fi passwords copied from netsh"}
        ],
        "detection_methods": [
            "Monitor for netsh wlan show profiles followed by key=clear",
            "Detect access to /etc/NetworkManager/system-connections/ from non-root users",
            "Alert on use of security find-generic-password on macOS with Wi-Fi names"
        ],
        "apt": ["Agent Tesla", "APT35", "Emotet"],
        "spl_query": [
            'index=sysmon EventCode=1 \n| search CommandLine="*netsh wlan show*" OR CommandLine="*key=clear*"',
            'index=osquery \n| search path="/etc/NetworkManager/system-connections/*" action="read"',
            'index=process_logs \n| search CommandLine="*security find-generic-password*" AND CommandLine="*-wa*"'
        ],
        "hunt_steps": [
            "Search for netsh wlan commands in PowerShell or command prompt logs",
            "Investigate file access to NetworkManager Wi-Fi configuration directories",
            "Correlate clipboard and memory dumps for known SSIDs or passwords"
        ],
        "expected_outcomes": [
            "Extraction of saved Wi-Fi profiles and passwords",
            "Enumeration of reachable Wi-Fi networks using system APIs",
            "Evidence of credential collection for lateral movement"
        ],
        "false_positive": "IT admins or users may legitimately query Wi-Fi profiles for troubleshooting purposes. Review context and parent processes.",
        "clearing_steps": [
            "Delete PowerShell command history",
            "Clear known Wi-Fi profiles using: netsh wlan delete profile name=*",
            "Remove contents from /etc/NetworkManager/system-connections/ securely"
        ],
        "mitre_mapping": [
            {"tactic": "Credential Access", "technique": "T1555.003", "example": "Use collected Wi-Fi credentials for impersonation or lateral access"},
            {"tactic": "Lateral Movement", "technique": "T1021.002", "example": "Reuse of shared Wi-Fi passwords to access adjacent systems"}
        ],
        "watchlist": [
            "netsh wlan commands from unexpected users",
            "Access to macOS keychain for Wi-Fi credentials",
            "Tools querying system Wi-Fi password stores"
        ],
        "enhancements": [
            "Implement EDR rules for Wi-Fi profile queries",
            "Monitor access to Wi-Fi profile storage paths",
            "Baseline and alert on netsh or wlanAPI.dll usage anomalies"
        ],
        "summary": "Wi-Fi Discovery allows adversaries to collect SSIDs and credentials from previously connected or nearby wireless networks, enabling further discovery or credential reuse.",
        "remediation": "Restrict access to Wi-Fi profile storage and audit Wi-Fi command usage. Periodically flush unused saved profiles.",
        "improvements": "Enable Sysmon and EDR alerts on Wi-Fi discovery commands. Encrypt and rotate wireless credentials regularly.",
        "mitre_version": "16.1"
    }
