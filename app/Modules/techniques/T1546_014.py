def get_content():
    return {
        "id": "T1546.014",
        "url_id": "T1546/014",
        "title": "Event Triggered Execution: Emond",
        "description": "Adversaries may gain persistence and elevate privileges by executing malicious content triggered by the Event Monitor Daemon (emond). Emond loads rule files from `/etc/emond.d/rules/` and executes defined actions, such as system commands, when specific events occur. Abuse of emond rules can result in privilege escalation to root or persistent command execution.",
        "tags": [],
        "tactic": "Persistence, Privilege Escalation",
        "protocol": "",
        "os": "macOS",
        "tips": [
            "Look for suspicious plist files in `/etc/emond.d/rules/`.",
            "Verify if `/private/var/db/emondClients` is created unexpectedly.",
            "Check if emond is launching inappropriately during user auth or startup."
        ],
        "data_sources": "Command, File, Process",
        "log_sources": [
            {"type": "Command", "source": "source", "destination": "destination"},
            {"type": "File", "source": "source", "destination": "destination"},
            {"type": "Process", "source": "source", "destination": "destination"}
        ],
        "source_artifacts": [
            {"type": "File", "location": "/etc/emond.d/rules/", "identify": "Suspicious plist rule creation"},
            {"type": "File", "location": "/private/var/db/emondClients", "identify": "Trigger for emond to launch"}
        ],
        "destination_artifacts": [],
        "detection_methods": [
            "Monitor file creation/modification in `/etc/emond.d/rules/` and `/private/var/db/emondClients`",
            "Detect abnormal process creation originating from emond rules",
            "Track command executions triggered outside of user input"
        ],
        "apt": [],
        "spl_query": [],
        "hunt_steps": [
            "Identify new files under `/etc/emond.d/rules/` and review for commands",
            "Review system logs for emond service activity",
            "Inspect Launch Daemon plist for unexpected triggers"
        ],
        "expected_outcomes": [
            "Discovery of persistence via emond rule",
            "Detection of privilege escalation mechanism via root-triggered execution"
        ],
        "false_positive": "Legitimate admin-defined emond rules for automation; validate intent and command behavior",
        "clearing_steps": [
            "sudo rm /etc/emond.d/rules/<malicious_rule>.plist",
            "sudo rm /private/var/db/emondClients/<malicious_trigger>",
            "sudo launchctl unload /System/Library/LaunchDaemons/com.apple.emond.plist"
        ],
        "mitre_mapping": [
            {
                "tactic": "Privilege Escalation",
                "technique": "T1543.004",
                "example": "Used Launch Daemon to invoke emond rules as root"
            }
        ],
        "watchlist": [
            "Creation of any file in `/etc/emond.d/rules/`",
            "New plist rules without documentation or tickets",
            "Unexpected process execution by `/sbin/emond`"
        ],
        "enhancements": [
            "File integrity monitoring on `/etc/emond.d/rules/` and `/private/var/db/emondClients`",
            "Alert on rule file creation by non-admin users"
        ],
        "summary": "This technique abuses emond rule triggers to gain persistence and privilege escalation on macOS systems.",
        "remediation": "Delete any unauthorized emond rules and prevent emond from running by disabling the Launch Daemon.",
        "improvements": "Implement strict control and auditing for rule-based automation in macOS environments.",
        "mitre_version": "16.1"
    }
