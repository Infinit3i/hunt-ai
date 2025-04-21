def get_content():
    return {
        "id": "T1564.002",
        "url_id": "T1564/002",
        "title": "Hide Artifacts: Hidden Users",
        "description": "Adversaries may use hidden users to hide the presence of user accounts they create or modify. In macOS, this can involve modifying user attributes and plist files to exclude accounts from login screens. On Windows, attackers may set registry values to prevent accounts from displaying. Linux systems can also hide users from display managers like GDM, depending on the distribution and its configuration.",
        "tags": ["hidden users", "user evasion", "account manipulation", "macOS", "Windows", "Linux"],
        "tactic": "Defense Evasion",
        "protocol": "",
        "os": "Linux, Windows, macOS",
        "tips": [
            "Monitor authentication logs for logins from users not listed in GUI login screens",
            "Correlate file activity and process execution with unlisted users",
            "Detect changes to registry keys or plist values related to login screen configuration"
        ],
        "data_sources": "Command, File, Process, User Account, Windows Registry",
        "log_sources": [
            {"type": "Command", "source": "", "destination": ""},
            {"type": "File", "source": "", "destination": ""},
            {"type": "Process", "source": "", "destination": ""},
            {"type": "User Account", "source": "", "destination": ""},
            {"type": "Windows Registry", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Windows Registry", "location": "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\UserList", "identify": "User value set to 0 to hide from login screen"},
            {"type": "User Account", "location": "/Library/Preferences/com.apple.loginwindow.plist", "identify": "Hide500Users key set to TRUE"},
            {"type": "File", "location": "/Users/<hidden>/", "identify": "Home folder exists but not visible in login"}
        ],
        "destination_artifacts": [
            {"type": "User Account", "location": "System Preferences / Login Screen", "identify": "Account not shown despite login evidence"},
            {"type": "Process", "location": "dscl . create", "identify": "Hidden attribute IsHidden=1 used for user creation"},
            {"type": "File", "location": "~/.config or ~/Library", "identify": "Files associated with hidden users"}
        ],
        "detection_methods": [
            "Monitor dscl usage with IsHidden=1 on macOS",
            "Detect registry changes to UserList key with values of 0",
            "Check for users with UID < 500 on macOS and existing home folders"
        ],
        "apt": ["SMOKEDHAM", "Operation Muzabi"],
        "spl_query": [
            "index=osquery OR index=sysmon \n| search CommandLine=*dscl*IsHidden* \n| stats count by User, CommandLine",
            "index=wineventlog EventCode=13 \n| search RegistryPath=*UserList* \n| where RegistryValueData=0 \n| stats count by User, RegistryKeyPath",
            "index=linux_logs OR index=osquery \n| search CommandLine=*gsettings*disable-user-list* \n| stats count by User, CommandLine"
        ],
        "hunt_steps": [
            "Review /etc/passwd and dscl . list /Users for inconsistencies",
            "Inspect registry key SpecialAccounts\\UserList for hidden user entries",
            "Compare user login timestamps with listed users"
        ],
        "expected_outcomes": [
            "Discovery of user accounts that exist but are hidden from normal views",
            "Detection of modified configuration preventing account visibility",
            "Identification of unauthorized users or persistence via hidden accounts"
        ],
        "false_positive": "Administrators may intentionally hide service or maintenance accounts. Confirm with system owners before responding.",
        "clearing_steps": [
            "On Windows: Remove user entry from UserList registry or set its value to 1",
            "On macOS: Set IsHidden=0 using dscl or adjust plist Hide500Users=False",
            "On Linux: Re-enable user listing via gsettings or greeter configuration"
        ],
        "clearing_playbook": ["https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-phishing"],
        "mitre_mapping": [
            {"tactic": "Persistence", "technique": "T1136.001", "example": "Create new local accounts and hide them from the GUI"},
            {"tactic": "Privilege Escalation", "technique": "T1078.003", "example": "Use of hidden administrative accounts for lateral movement"}
        ],
        "watchlist": [
            "New user creation followed by registry/plist modifications",
            "UID values <500 on macOS",
            "Use of dscl with IsHidden or gsettings on Linux"
        ],
        "enhancements": [
            "Set alerts on modifications to login-related plist or registry keys",
            "Use EDR or osquery to flag hidden account creation",
            "Compare visible users with entries in /etc/passwd or AD"
        ],
        "summary": "Adversaries may hide user accounts from standard login interfaces to remain undetected. This tactic can be used to persist on systems with reduced visibility from users or analysts.",
        "remediation": "Unhide or remove unauthorized user accounts, reset login configuration files and registry keys, and validate user presence across systems.",
        "improvements": "Regularly audit user accounts, UID ranges, and login configuration to detect and prevent stealth user persistence.",
        "mitre_version": "16.1"
    }
