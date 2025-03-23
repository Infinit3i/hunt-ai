def get_content():
    return {
        "id": "T1003.007",
        "url_id": "T1003/007",
        "title": "OS Credential Dumping: Proc Filesystem",
        "description": "Adversaries may gather credentials from Linux systems by inspecting the proc filesystem for memory containing passwords or hashes.",
        "tags": ["proc", "linux", "credential dumping", "memory analysis", "maps", "mem", "mimipenguin", "cleartext"],
        "tactic": "Credential Access",
        "protocol": "",
        "os": "Linux",
        "tips": [
            "Use AuditD to detect access to /proc/*/maps or /mem files",
            "Restrict access to memory files to only privileged processes",
            "Sanitize application memory by clearing credentials after use"
        ],
        "data_sources": "Command, File",
        "log_sources": [
            {"type": "Command", "source": "", "destination": ""},
            {"type": "File", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "File", "location": "/proc/[PID]/maps", "identify": "Memory map of process, used to locate memory regions"},
            {"type": "File", "location": "/proc/[PID]/mem", "identify": "Memory dump of process, may contain credentials"},
            {"type": "Memory Dumps", "location": "User-space process memory", "identify": "Cached cleartext credentials or session tokens"}
        ],
        "destination_artifacts": [],
        "detection_methods": [
            "Use AuditD to alert on reads to /proc/*/maps or /proc/*/mem",
            "Detect unusual access by non-debugging processes to memory-mapped files",
            "Correlate grep or awk usage on /proc memory paths with suspicious behavior"
        ],
        "apt": [
            "APT33", "MimiPenguin", "LaZagne"
        ],
        "spl_query": [
            'index=linux_logs file_path="/proc/*/maps" OR file_path="/proc/*/mem" AND NOT user=root',
            'index=linux_logs process_name IN ("grep", "awk", "cat") AND command_line="*/proc/*/maps*"'
        ],
        "hunt_steps": [
            "Identify access to /proc/*/maps and /mem by non-root or unauthorized users",
            "Check for regex or parsing commands that target memory regions",
            "Look for execution of known tools like MimiPenguin or LaZagne variants"
        ],
        "expected_outcomes": [
            "Detection of attempts to scan or dump process memory for credentials",
            "Identification of cleartext passwords or hashes in memory",
            "Recognition of unauthorized memory inspection behavior"
        ],
        "false_positive": "Debuggers and legitimate performance profilers may read from /proc maps or mem. Validate tool origin and associated user.",
        "clearing_steps": [
            "Kill unauthorized processes accessing /proc/*/mem",
            "Secure processes holding credentials in memory (e.g., use mlock/munlock)",
            "Restart affected services to flush memory"
        ],
        "mitre_mapping": [
            {"tactic": "Credential Access", "technique": "T1555", "example": "Cleartext credentials recovered from memory inspection of browser processes"}
        ],
        "watchlist": [
            "Access to /proc/[PID]/maps or /proc/[PID]/mem by non-root users",
            "Command-line usage of grep or cut on memory paths",
            "Presence of MimiPenguin or similar memory parsing scripts"
        ],
        "enhancements": [
            "Enable AuditD rules for /proc/*/maps and /mem reads",
            "Use Linux Security Modules (AppArmor/SELinux) to limit memory access",
            "Implement process memory sanitization routines in sensitive applications"
        ],
        "summary": "Linux systems expose memory structures through the /proc filesystem. Adversaries may parse these files to extract credentials from memory.",
        "remediation": "Limit access to /proc memory files, terminate malicious processes, and rotate compromised credentials.",
        "improvements": "Harden memory handling in applications, deploy kernel-level protections, and regularly audit /proc access logs.",
        "mitre_version": "16.1"
    }
