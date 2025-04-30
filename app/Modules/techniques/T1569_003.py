def get_content():
    return {
        "id": "T1569.003",
        "url_id": "T1569/003",
        "title": "Systemctl",
        "description": "Adversaries may abuse systemctl to execute commands or programs as Systemd services on Linux systems.",
        "tags": ["linux", "systemctl", "systemd", "execution", "service abuse", "TeamTNT"],
        "tactic": "execution",
        "protocol": "",
        "os": "Linux",
        "tips": [
            "Audit the use of 'systemctl enable' and 'start' commands by non-root users.",
            "Review modifications in systemd unit file directories for unexpected changes.",
            "Correlate service creations with suspicious parent processes or commands."
        ],
        "data_sources": "Command, File, Process, Service",
        "log_sources": [
            {"type": "Command", "source": "", "destination": ""},
            {"type": "File", "source": "", "destination": ""},
            {"type": "Process", "source": "", "destination": ""},
            {"type": "Service", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "File", "location": "/etc/systemd/system/", "identify": "Custom or malicious unit files"}
        ],
        "destination_artifacts": [
            {"type": "Process", "location": "/lib/systemd/system/", "identify": "Unexpected daemon behavior triggered by systemctl"}
        ],
        "detection_methods": [
            "Monitor command execution of systemctl, especially by non-root users.",
            "Track changes to service unit files and watch for unexpected modifications.",
            "Inspect processes spawned by systemctl or systemd that are outside baseline behavior."
        ],
        "apt": ["TeamTNT"],
        "spl_query": [
            "sourcetype=auditd OR sourcetype=sysmon_linux(command=\"systemctl\" AND (command=\"start\" OR command=\"enable\"))\n| stats count by host, user, command, parent_process, _time\n| where user!=\"root\" AND NOT match(command, \"expected_service\")\n| sort -_time",
            "sourcetype=auditd(path IN (\"/etc/systemd/system/\", \"/usr/lib/systemd/system/\", \"/home//.config/systemd/user/\") AND (syscall=\"open\" OR syscall=\"write\"))\n| stats count by file_path, user, process_name, _time\n| where NOT match(file_path, \"expected_admin_changes\")\n| sort -_time",
            "sourcetype=sysmon_linux OR sourcetype=auditd(parent_process=\"systemd\" OR process_name=\"daemon\")\n| stats count by process_name, parent_process, user, cmdline, _time\n| where user!=\"root\" AND NOT match(cmdline, \"known_daemon_pattern\")\n| sort -_time",
            "sourcetype=auditd(command=\"systemctl\" AND command=\"enable\" OR command=\"create\")\n| stats count by user, command, process_name, _time\n| where NOT match(command, \"whitelisted_services\")\n| sort -_time"
        ],
        "hunt_steps": [
            "List all recently enabled or started systemd services.",
            "Review unit file changes under /etc/systemd/system/.",
            "Trace service invocations back to triggering user or script."
        ],
        "expected_outcomes": [
            "Detection of unauthorized execution of systemd services using systemctl."
        ],
        "false_positive": "System administrators may configure services manually. Validate based on user roles and ticketing history.",
        "clearing_steps": [
            "Disable and remove unauthorized services using systemctl disable and rm <unit file>.",
            "Restore overwritten or malicious unit files to default.",
            "Audit service enablement policies and lock service directories."
        ],
        "clearing_playbook": [
            "https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-malware"
        ],
        "mitre_mapping": [
            {"tactic": "execution", "technique": "T1569", "example": "System Services"},
            {"tactic": "persistence", "technique": "T1543.002", "example": "Create or Modify System Process"}
        ],
        "watchlist": [
            "Non-root users running 'systemctl start' or 'enable'",
            "Unexpected changes to /etc/systemd/system/ unit files"
        ],
        "enhancements": [
            "Use file integrity monitoring on systemd unit file directories.",
            "Alert on daemon processes with non-standard configurations."
        ],
        "summary": "Systemctl can be leveraged by adversaries to execute or persist malicious services using systemd on Linux hosts, often under the guise of legitimate startup operations.",
        "remediation": "Restrict systemctl usage to privileged users and validate service configurations regularly.",
        "improvements": "Implement auditd policies and baseline systemd behavior across server fleets.",
        "mitre_version": "17.0"
    }
