def get_content():
    return {
        "id": "T1222",
        "url_id": "T1222",
        "title": "File and Directory Permissions Modification",
        "description": "Adversaries may modify file or directory permissions/attributes to evade access controls and access protected files. This includes altering ACLs, changing file ownership, or adjusting symbolic link access to enable tampering or execution of sensitive binaries.",
        "tags": ["ACL evasion", "icacls", "chmod", "symbolic links", "file ownership", "defense evasion"],
        "tactic": "Defense Evasion",
        "protocol": "",
        "os": "Linux, Windows, macOS",
        "tips": [
            "Audit ACL changes on critical configuration and binary directories.",
            "Alert when built-in permission-modifying utilities like `icacls`, `chmod`, or `takeown` are used by non-admins.",
            "Correlate permission modification events with persistence or privilege escalation indicators."
        ],
        "data_sources": "Active Directory, Command, File, Process",
        "log_sources": [
            {"type": "Active Directory", "source": "Windows Security", "destination": ""},
            {"type": "Command", "source": "Sysmon", "destination": ""},
            {"type": "File", "source": "Windows Security", "destination": ""},
            {"type": "Process", "source": "Sysmon", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Windows Security Logs", "location": "Security.evtx", "identify": "Event ID 4670 - DACL modification"},
            {"type": "Sysmon Logs", "location": "Microsoft-Windows-Sysmon/Operational", "identify": "CommandLine for icacls.exe or chmod"}
        ],
        "destination_artifacts": [],
        "detection_methods": [
            "Monitor Event ID 4670 in Windows Security logs",
            "Look for processes like icacls.exe, takeown.exe, chmod, or setfacl modifying critical files",
            "Detect changes to symbolic links or shortcuts pointing to protected paths"
        ],
        "apt": [
            "BlackCat", "BlackMatter", "Rust-based ransomware variants", "Gamaredon"
        ],
        "spl_query": [
            "index=wineventlog EventCode=4670\n| stats count by ObjectName, SubjectUserName, ProcessName",
            "index=sysmon EventCode=1 (Image=*icacls.exe OR Image=*takeown.exe OR Image=*chmod)\n| stats count by CommandLine, User, Image"
        ],
        "hunt_steps": [
            "Review recent uses of icacls.exe, takeown.exe, chmod, setfacl",
            "Identify changes to permissions on key system files or application binaries",
            "Check for symbolic link manipulation pointing to sensitive files"
        ],
        "expected_outcomes": [
            "Discovery of attempts to override file access controls",
            "Identification of pre-exploitation steps prior to hijacking or persistence",
            "Increased visibility into ACL manipulation by malicious actors"
        ],
        "false_positive": "Administrators may modify file/directory permissions as part of routine operations. Validate user context and file targeted before taking action.",
        "clearing_steps": [
            "Revert ACL changes using icacls or backup ACL templates",
            "Remove unauthorized symbolic links or permission grants",
            "Restore original file ownership using takeown or chown commands"
        ],
        "clearing_playbook": [
            "https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-malware"
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1222", "example": "Using icacls.exe to allow everyone full control to sensitive binaries"},
            {"tactic": "Persistence", "technique": "T1546.008", "example": "Replacing sethc.exe with cmd.exe after modifying file ACLs"},
            {"tactic": "Privilege Escalation", "technique": "T1574", "example": "Hijack execution flow by modifying permissions of autoloaded executables"}
        ],
        "watchlist": [
            "Usage of icacls.exe or chmod on protected paths",
            "File permissions changed shortly before execution or registry modification",
            "Symlinks created or modified to point to alternate locations"
        ],
        "enhancements": [
            "Enable SACLs for permission change auditing on sensitive directories",
            "Add EDR rules for icacls, takeown, or chmod outside of expected usage hours",
            "Correlate permission modifications with user privilege context and process lineage"
        ],
        "summary": "File and directory permissions modification is used by adversaries to tamper with protected resources, set up persistence, or escalate privileges. Monitoring and controlling such changes is essential for defensive posture.",
        "remediation": "Use group policy and configuration management to enforce ACLs. Limit access to permission-modifying tools to administrators. Periodically scan for unauthorized permission changes.",
        "improvements": "Establish baselines for normal ACL changes. Tune alerting thresholds by directory sensitivity. Monitor symbolic link redirections regularly.",
        "mitre_version": "16.1"
    }