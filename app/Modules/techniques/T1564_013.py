def get_content():
    return {
        "id": "T1564.013",
        "url_id": "T1564/013",
        "title": "Bind Mounts",
        "description": "Adversaries may abuse bind mounts on file structures to hide their activity and artifacts from native utilities.",
        "tags": ["bind mount", "linux", "proc hiding", "defense evasion", "mount"],
        "tactic": "defense-evasion",
        "protocol": "",
        "os": "Linux",
        "tips": [
            "Monitor /bin/mount command executions involving /proc paths.",
            "Inspect for unusual /proc directory manipulations using audit logs.",
            "Use eBPF or syscall tracing to capture mount operations with MS_BIND."
        ],
        "data_sources": "Command, File, OS API Execution",
        "log_sources": [
            {"type": "Command", "source": "", "destination": ""},
            {"type": "File", "source": "", "destination": ""},
            {"type": "OS API Execution", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Process List", "location": "/proc", "identify": "PID directories showing inconsistent or hidden metadata due to bind mount masking"}
        ],
        "destination_artifacts": [
            {"type": "Mount Table", "location": "/proc/mounts", "identify": "Overlay entries showing bind mounts on other /proc/ paths"}
        ],
        "detection_methods": [
            "Monitor usage of mount commands that include --bind or -B flags targeting /proc.",
            "Inspect audit logs or syscall traces for MS_BIND flag usage.",
            "Flag suspicious /proc directories created with write access."
        ],
        "apt": ["KV Botnet Activity"],
        "spl_query": [
            "index=linux_logs source=\"/var/log/audit/audit.log\"| eval syscall=coalesce(syscall, \"unknown\"), exe=coalesce(exe, \"unknown\")\n| search syscall=\"mount\" exe=\"/bin/mount\" (msg=\"bind\" OR msg=\"bind,rw\")\n| rex field=msg \"a0=\\\"(?<source_path>[^\\\"]+)\\\" a1=\\\"(?<target_path>[^\\\"]+)\\\"\"\n| where like(source_path, \"/proc/%\") AND like(target_path, \"/proc/%\")\n| eval is_suspicious=if(match(target_path, \"/proc/[1-9][0-9]*\") AND NOT cidrmatch(source_path, target_path), 1, 0)\n| stats count by exe, source_path, target_path, uid, pid, is_suspicious\n| where is_suspicious=1",
            "index=syscalls source=\"/var/log/audit/audit.log\"| search syscall=\"mount\"| regex args=\".bind.\"\n| eval suspicious=if(like(args, \"%/proc/%\") AND like(args, \"%bind%\"), 1, 0)\n| stats count by pid, exe, args, uid, suspicious\n| where suspicious=1"
        ],
        "hunt_steps": [
            "Review /proc/mounts for bind-mounted /proc entries.",
            "Query audit logs for mount usage with --bind flag.",
            "Use eBPF-based or syscall-level monitors to trace mount system calls."
        ],
        "expected_outcomes": [
            "Identification of malicious use of bind mounts to obscure running process artifacts."
        ],
        "false_positive": "System administrators may use bind mounts legitimately in container or chroot environments. Validate context and intent.",
        "clearing_steps": [
            "Unmount the bind mount using umount <target>.",
            "Investigate the original source directory and clean malicious content.",
            "Audit all /proc entries to validate correct process mappings."
        ],
        "clearing_playbook": [
            "https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-malware"
        ],
        "mitre_mapping": [
            {"tactic": "defense-evasion", "technique": "T1564", "example": "Hide Artifacts"},
            {"tactic": "execution", "technique": "T1202", "example": "Indirect Command Execution"}
        ],
        "watchlist": [
            "Mount commands using bind option targeting /proc",
            "Unexpected changes to /proc mount table entries"
        ],
        "enhancements": [
            "Use immutable flags on sensitive /proc entries when possible.",
            "Automate alerts on mount operations involving /proc paths."
        ],
        "summary": "Bind mounts can be abused on Linux systems to hide process activity by overlaying /proc directories with benign content, evading monitoring tools.",
        "remediation": "Unmount suspicious bind mounts and investigate any process metadata inconsistencies.",
        "improvements": "Implement tighter audit controls around mount operations and correlate with PID behavior.",
        "mitre_version": "17.0"
    }
