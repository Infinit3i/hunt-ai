def get_content():
    return {
        "id": "T1559.003",
        "url_id": "T1559/003",
        "title": "Inter-Process Communication: XPC Services",
        "description": "Adversaries may abuse macOS XPC Services to execute arbitrary code or elevate privileges. XPC allows communication between applications and system daemons, often running as root. Malicious input or exploit attempts against insecure XPC handlers can allow attackers to run commands or escalate privileges through unvalidated data execution.",
        "tags": ["xpc", "macos", "ipc", "privilege escalation", "eop", "execution", "root", "daemon abuse"],
        "tactic": "Execution",
        "protocol": "",
        "os": "macOS",
        "tips": [
            "Audit XPC handler logic to ensure input validation and protocol compliance.",
            "Monitor application communications with XPC daemons for anomalies.",
            "Harden third-party daemons and avoid over-privileged XPC channels."
        ],
        "data_sources": "Process",
        "log_sources": [
            {"type": "Process", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Process List", "location": "System Memory", "identify": "Processes communicating with privileged daemons via NSXPCConnection"},
            {"type": "Registry Hives", "location": "~/Library/Preferences", "identify": "Launch agents or services invoking XPC"},
            {"type": "File", "location": "/Library/Logs/CrashReporter", "identify": "Errors related to XPC communication or injection"}
        ],
        "destination_artifacts": [
            {"type": "Process", "location": "/System/Library/LaunchDaemons", "identify": "Privileged daemons invoked by XPC"},
            {"type": "File", "location": "/private/var/tmp or /tmp", "identify": "Payloads passed to or from XPC handlers"},
            {"type": "Script", "location": "/usr/local/bin or /Users/Shared", "identify": "Execution scripts supplied via compromised services"}
        ],
        "detection_methods": [
            "Analyze CrashReporter logs for anomalies related to XPC execution",
            "Monitor for applications interacting with XPC daemons outside normal behavior",
            "Track file and process access initiated by NSXPCConnection or C API calls"
        ],
        "apt": ["Unknown"],  # No publicly mapped APT as of now
        "spl_query": [
            "index=mac_logs sourcetype=process_audit Process_Name=*XPC* \n| stats count by ParentProcessName, Process_Name, CommandLine",
            "index=mac_logs source=/Library/Logs/CrashReporter sourcetype=syslog message=*xpc* \n| stats count by host, message"
        ],
        "hunt_steps": [
            "Search for custom or unsigned daemons listening to XPC channels",
            "Analyze XPC service definitions for improper input validation",
            "Correlate unusual privilege escalation paths to XPC handler activity"
        ],
        "expected_outcomes": [
            "Detection of privilege escalation through insecure XPC handlers",
            "Identification of exploitation attempts targeting system XPC daemons"
        ],
        "false_positive": "XPC is common for legitimate macOS inter-process comms; verify the binary origin, entitlement, and parent-child chain.",
        "clearing_steps": [
            "Remove compromised or misconfigured daemons from `/Library/LaunchDaemons`",
            "Rebuild or quarantine binaries misusing XPC for privilege abuse",
            "Revoke permissions or certificates for involved applications"
        ],
        "clearing_playbook": [],
        "mitre_mapping": [
            {"tactic": "Privilege Escalation", "technique": "T1068", "example": "Exploitation of vulnerable XPC daemon to gain root"},
            {"tactic": "Execution", "technique": "T1559.003", "example": "Malicious app requesting payload execution via XPC handler"}
        ],
        "watchlist": [
            "Apps creating NSXPCConnection to unexpected system services",
            "Launch of non-Apple daemons with root privileges via XPC"
        ],
        "enhancements": [
            "Apply code signing enforcement and notarization for all daemons",
            "Use sandboxing and hardened runtime to isolate XPC communication",
            "Review third-party tool installations that add system-level XPC daemons"
        ],
        "summary": "XPC Services on macOS are intended for secure inter-process communication. However, poorly implemented services can allow adversaries to run arbitrary code or escalate privileges by feeding malicious input to privileged XPC handlers.",
        "remediation": "Validate all XPC service interfaces, avoid exposing unfiltered input to handlers, and audit service configurations.",
        "improvements": "Integrate XPC fuzzing into macOS security reviews, and restrict userland apps from interfacing with sensitive system daemons.",
        "mitre_version": "16.1"
    }
