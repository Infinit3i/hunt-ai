def get_content():
    return {
        "id": "T1036.011",
        "url_id": "T1036/011",
        "title": "Overwrite Process Arguments",
        "description": "Adversaries may modify a process's in-memory arguments to change its name in order to appear as a legitimate or benign process.",
        "tags": ["masquerading", "process", "argv", "linux", "defense evasion", "in-memory"],
        "tactic": "defense-evasion",
        "protocol": "",
        "os": "Linux",
        "tips": [
            "Compare values from /proc/<PID>/cmdline, comm, and exe for inconsistencies.",
            "Watch for suspicious processes with generic or mismatched names.",
            "Flag processes that clear argv[1..n] early in execution."
        ],
        "data_sources": "Process",
        "log_sources": [
            {"type": "Process", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Process List", "location": "/proc", "identify": "Discrepancy between argv[0] and actual binary path."},
            {"type": "Memory Dumps", "location": "Volatile Memory", "identify": "Manual overwrite of argv[0] and nulling of argv[1..n]"}
        ],
        "destination_artifacts": [
            {"type": "Process List", "location": "RAM", "identify": "Mismatch in process name vs execution path"}
        ],
        "detection_methods": [
            "Compare /proc/<PID>/cmdline vs comm and exe to identify mismatches.",
            "Monitor for early nullification of argv array in memory."
        ],
        "apt": ["BPFDoor"],
        "spl_query": [
            "index=* sourcetype=linux_audit OR sourcetype=osquery \n| eval mismatch=if(cmdline!=exe AND comm!=exe, 1, 0) \n| where mismatch=1 \n| table _time, host, user, pid, cmdline, comm, exe"
        ],
        "hunt_steps": [
            "List all running processes and extract values of /proc/<PID>/cmdline, comm, and exe.",
            "Identify if argv[0] differs from the true binary.",
            "Look for cleared or nullified argv[1..n]."
        ],
        "expected_outcomes": [
            "Detection of processes that are masquerading by overwriting their argv[0] to appear benign."
        ],
        "false_positive": "Some benign daemons may legitimately have slight mismatches due to init wrappers or symbolic links.",
        "clearing_steps": [
            "kill -9 <PID>",
            "rm -f /tmp/rogue_binary",
            "Check cron/systemd for persistence and remove references"
        ],
        "clearing_playbook": [
            "https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-malware"
        ],
        "mitre_mapping": [
            {"tactic": "defense-evasion", "technique": "T1036", "example": "Masquerading"},
            {"tactic": "defense-evasion", "technique": "T1055.012", "example": "Process Hollowing"}
        ],
        "watchlist": [
            "Processes with modified argv[0] or empty arguments",
            "Unexpected process names executing from /tmp or /dev" 
        ],
        "enhancements": [
            "Use EDR tools to correlate argv string vs binary execution path.",
            "Automate memory inspection for early string overwrites."
        ],
        "summary": "Overwrite Process Arguments enables attackers to disguise running processes by modifying command-line arguments in memory, a stealthy tactic especially on Linux systems.",
        "remediation": "Ensure process auditing tools compare cmdline and binary source. Educate analysts to validate process name authenticity.",
        "improvements": "Automate /proc comparisons and memory monitoring for suspicious argv changes.",
        "mitre_version": "17.0"
    }
