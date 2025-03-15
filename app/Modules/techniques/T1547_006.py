def get_content():
    return {
        "id": "T1547.006",
        "url_id": "1547/006",
        "title": "Boot or Logon Autostart Execution: Kernel Modules and Extensions",
        "description": (
            "Adversaries may modify the kernel to automatically execute programs on system boot or logon."
        ),
        "tags": ["Persistence", "Privilege Escalation", "Linux", "macOS"],
        "tactic": "Persistence, Privilege Escalation",
        "protocol": "Linux, macOS",
        "os": "Linux, macOS",
        "tips": [
            "Monitor for execution of LKM-related commands such as modprobe, insmod, lsmod, rmmod, modinfo.",
            "Check for unauthorized kernel modules in /lib/modules/*.ko.",
            "On macOS, monitor kextload and inspect kext_policy database for unauthorized entries."
        ],
        "data_sources": "Command: Command Execution, File: File Creation, File: File Modification, Kernel: Kernel Module Load, Process: Process Creation",
        "log_sources": [
            {"type": "Command", "source": "Kernel Module Execution", "destination": "SIEM"},
            {"type": "File", "source": "/lib/modules", "destination": "Integrity Monitoring"}
        ],
        "source_artifacts": [
            {"type": "Kernel Module", "location": "/lib/modules/*.ko", "identify": "Unauthorized Kernel Module"}
        ],
        "destination_artifacts": [
            {"type": "Log", "location": "/var/log/kern.log", "identify": "Kernel Load Events"}
        ],
        "detection_methods": [
            "Monitor for unexpected module insertions and removals.",
            "Detect execution of modprobe, insmod, kextload, or unauthorized kernel modifications.",
            "Inspect kext_policy database in macOS for new unauthorized kernel extensions."
        ],
        "apt": ["Drovorub", "Skidmap", "Operation CuckooBees"],
        "spl_query": [
            "index=linux_logs | search command IN (modprobe, insmod, rmmod)",
            "index=macos_logs | search command=kextload"
        ],
        "hunt_steps": [
            "Identify recently loaded kernel modules that do not match known baselines.",
            "Correlate unusual kernel module activity with other suspicious system behaviors."
        ],
        "expected_outcomes": [
            "Detection of unauthorized kernel module or extension activity.",
            "Identification of adversaries using kernel-level persistence mechanisms."
        ],
        "false_positive": "Some system updates or legitimate software may load new kernel modules.",
        "clearing_steps": [
            "Unload suspicious kernel modules using 'rmmod' or 'kextunload'.",
            "Restrict unauthorized users from loading kernel modules via security policy enforcement."
        ],
        "mitre_mapping": [
            {"tactic": "Execution", "technique": "T1059", "example": "Execution via Kernel Module Injection"},
            {"tactic": "Privilege Escalation", "technique": "T1068", "example": "Gaining Root Privileges via LKM Manipulation"}
        ],
        "watchlist": [
            "Monitor for unexpected kernel module loads and modifications.",
            "Alert on unauthorized use of kextload or modprobe."
        ],
        "enhancements": [
            "Implement kernel module integrity validation.",
            "Restrict user ability to load kernel modules unless explicitly authorized."
        ],
        "summary": "Adversaries can exploit kernel modules or extensions for persistent execution and privilege escalation.",
        "remediation": "Restrict kernel module loading and enforce strict integrity checks.",
        "improvements": "Regularly audit kernel module configurations to prevent unauthorized modifications."
    }
