def get_content():
    return {
        "id": "T1222.002",
        "url_id": "T1222/002",
        "title": "Linux and Mac File and Directory Permissions Modification",
        "description": "Adversaries may modify file or directory permissions/attributes to evade access control lists (ACLs) and access protected files. Linux and macOS platforms use permission groups (user, group, other) and standard permissions (read, write, execute). Adversaries may abuse commands like `chown` and `chmod` to change file ownership or mode, potentially locking out other users or enabling execution. This behavior may support persistence or execution flow hijacking techniques.",
        "tags": ["chmod", "chown", "Unix ACL", "macOS", "Linux", "defense evasion"],
        "tactic": "Defense Evasion",
        "protocol": "",
        "os": "Linux, macOS",
        "tips": [
            "Track use of chmod 777 or +x on unusual paths.",
            "Detect ownership transfers using chown/chgrp on sensitive directories.",
            "Review file access logs on persistence or init folders."
        ],
        "data_sources": "Command, File, Process",
        "log_sources": [
            {"type": "Command", "source": "auditd", "destination": ""},
            {"type": "File", "source": "auditd", "destination": ""},
            {"type": "Process", "source": "Syslog", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "audit logs", "location": "/var/log/audit/audit.log", "identify": "chmod or chown entries"},
            {"type": "syslog", "location": "/var/log/syslog", "identify": "chmod/chown activities on binaries"}
        ],
        "destination_artifacts": [],
        "detection_methods": [
            "Monitor chmod and chown commands modifying /etc, /usr/bin, or /Applications",
            "Detect chmod +x on non-binary paths or during suspicious times",
            "Track recursive (-R) permissions changes on home/user/bin folders"
        ],
        "apt": [
            "KVBotnet", "Black Basta", "Kinsing", "Rocke", "Shlayer", "APT32", "TeamTNT", "Sandworm", "Turla"
        ],
        "spl_query": [
            "index=linux_logs sourcetype=auditd type=SYSCALL exe=*chmod* OR exe=*chown*\n| stats count by exe, uid, cwd, command",
            "index=mac_logs process=*chmod* OR process=*chown*\n| stats count by user, command, path"
        ],
        "hunt_steps": [
            "Check audit logs for chmod 777 or -R executions",
            "Review ownership changes of persistence-critical files",
            "Inspect executable flag assignments outside of installation events"
        ],
        "expected_outcomes": [
            "Identify improper access grants to adversaries",
            "Detect precursors to malicious binary execution",
            "Find attempts to lock legitimate users from key files"
        ],
        "false_positive": "Sysadmins and package managers may perform bulk chmod/chown operations. Focus on outliers in context, user, and target file.",
        "clearing_steps": [
            "Reset file permissions with chmod/chown based on backup or policy",
            "Re-secure affected files by applying default ACLs",
            "Audit user groups and restrict unnecessary ownership"
        ],
        "clearing_playbook": [
            "https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-malware"
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1222.002", "example": "chmod +x used to enable malicious script execution"},
            {"tactic": "Persistence", "technique": "T1546.004", "example": "Unix shell profile modified after ownership change"},
            {"tactic": "Privilege Escalation", "technique": "T1574", "example": "Hijacking configuration files by chmod 777 and editing content"}
        ],
        "watchlist": [
            "chmod 777 or chmod -R on sensitive paths",
            "chown operations assigning files to unknown users",
            "Scripts gaining executable flag outside install/update window"
        ],
        "enhancements": [
            "Create baseline ACL snapshots for sensitive files",
            "Alert on recursive chmods involving /usr/local/bin",
            "Disallow chmod/chown on specific file types via sudoers"
        ],
        "summary": "Linux and Mac file permission modification allows adversaries to change execution rights and ownership, potentially enabling unauthorized access, persistence, or attack flow redirection.",
        "remediation": "Enforce strict sudo policy for permission commands. Use mandatory access control systems like AppArmor or SELinux. Alert on sensitive file permission deviations.",
        "improvements": "Integrate ACL monitoring with SIEM. Tag and protect privileged binaries. Educate users on secure chmod/chown practices.",
        "mitre_version": "16.1"
    }
