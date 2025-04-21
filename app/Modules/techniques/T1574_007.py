def get_content():
    return {
        "id": "T1574.007",
        "url_id": "T1574/007",
        "title": "Hijack Execution Flow: Path Interception by PATH Environment Variable",
        "description": "Adversaries may execute their own malicious payloads by exploiting the order in which the operating system resolves executable locations via the PATH environment variable. When a program is executed without a full path, the OS sequentially searches directories defined in the PATH variable to locate the executable.\n\nAn attacker can place a malicious binary with the same name as a legitimate utility (e.g., `net.exe`, `python`) in a directory that appears earlier in the PATH list, thus hijacking the execution flow. For instance, placing a malicious `net.exe` in `C:\\Users\\Public\\bin\\` and prepending that directory to the PATH variable can cause this binary to execute instead of the legitimate system utility.\n\nThis technique is applicable across Windows, Linux, and macOS systems. On Linux/macOS, attackers may modify `$PATH` via shell configuration files (e.g., `.bashrc`, `.zshrc`) or create entries in `/etc/paths.d`. On macOS, variables such as `$HOME` may also be manipulated to redirect execution flows.\n\nThis method can be used for persistence (e.g., on shell or session startup), privilege escalation (if invoked by higher-privileged processes), or defense evasion.",
        "tags": ["PATH hijack", "Environment Variable Abuse", "Persistence", "Execution Hijack"],
        "tactic": "Defense Evasion, Persistence, Privilege Escalation",
        "protocol": "",
        "os": "Windows, Linux, macOS",
        "tips": [
            "Audit and lock down write access to directories that appear early in the PATH variable.",
            "Enforce full-path invocation for high-privilege scripts and system jobs.",
            "Log and alert on abnormal environment variable changes during runtime or user login."
        ],
        "data_sources": "File: File Creation, Process: Process Creation, Windows Registry: Windows Registry Key Modification",
        "log_sources": [
            {"type": "File", "source": "Filesystem or EDR logs", "destination": ""},
            {"type": "Process", "source": "Sysmon (EID 1), Linux auditd, or macOS Unified Logs", "destination": ""},
            {"type": "Registry", "source": "HKEY_LOCAL_MACHINE or HKEY_CURRENT_USER Environment keys", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "File", "location": "Custom directories early in PATH", "identify": "Binaries with names matching common system tools"}
        ],
        "destination_artifacts": [
            {"type": "Process", "location": "Non-system directories", "identify": "Unexpected execution path with common tool name"}
        ],
        "detection_methods": [
            "Monitor PATH changes via Windows Registry or shell startup files (`.bashrc`, `.zshrc`, etc.).",
            "Look for new executable files in directories early in PATH with names like `cmd.exe`, `python`, `net`.",
            "Correlate unexpected command execution with environment manipulation or binary drop activity."
        ],
        "apt": [],
        "spl_query": [
            "index=sysmon EventCode=1 Image IN (\"*\\\\cmd.exe\", \"*\\\\net.exe\")\n| search NOT Image=\"C:\\\\Windows\\\\System32\\\\*\"\n| stats count by Image, CommandLine, User"
        ],
        "hunt_steps": [
            "Enumerate user and system PATH values across endpoints.",
            "Check user-writable directories included in PATH for suspicious or unsigned executables.",
            "Scan shell config files and `/etc/paths.d/` for unauthorized entries."
        ],
        "expected_outcomes": [
            "Discovery of environment variable abuse enabling adversary-controlled binary execution.",
            "Detection of PATH modifications or malicious binaries shadowing common system tools.",
            "Correlated execution logs revealing privilege escalation or persistence behavior."
        ],
        "false_positive": "Developers and system administrators may modify PATH for testing or local dev environments. Review intent and consistency across hosts.",
        "clearing_steps": [
            "Remove the malicious binary and restore the intended PATH structure.",
            "Delete unauthorized entries in PATH from the registry, `.bashrc`, `.zshrc`, or `/etc/paths.d`.",
            "Audit directory permissions to prevent binary drops in sensitive PATH directories."
        ],
        "mitre_mapping": [
            {"tactic": "Persistence", "technique": "T1574.007", "example": "Malware modifies PATH to launch fake `python` binary on terminal startup"},
            {"tactic": "Privilege Escalation", "technique": "T1574.007", "example": "Modified PATH used by cron job executes attacker binary as root"}
        ],
        "watchlist": [
            "Executables named like `cmd.exe`, `net.exe`, `ls`, `python`, `bash` found in user-writable PATH folders",
            "PATH entries referencing non-standard folders or user temp directories",
            "Registry modifications to PATH values or shell file changes"
        ],
        "enhancements": [
            "Apply AppLocker or WDAC to restrict execution in non-standard paths.",
            "Use EDR policies to restrict dynamic PATH changes during sessions.",
            "Harden shell initialization files with immutability attributes where supported."
        ],
        "summary": "This technique involves hijacking the execution flow by manipulating the PATH environment variable. It allows adversaries to inject malicious binaries that take precedence in execution order over legitimate system utilities.",
        "remediation": "Validate and lock down PATH values, enforce use of absolute paths, and restrict write access to directories in execution paths.",
        "improvements": "Implement runtime checks in CI/CD pipelines or shell policies to prevent unsafe path usage. Deploy environment hardening scripts during provisioning.",
        "mitre_version": "16.1"
    }
