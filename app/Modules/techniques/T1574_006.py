def get_content():
    return {
        "id": "T1574.006",
        "url_id": "T1574/006",
        "title": "Hijack Execution Flow: Dynamic Linker Hijacking",
        "description": "Adversaries may exploit environment variables used by dynamic linkers to load malicious shared libraries into target processes. On Linux and macOS, dynamic linkers use variables like `LD_PRELOAD` and `DYLD_INSERT_LIBRARIES` to inject libraries into running applications at load time. These libraries override legitimate functions if the names match, thus hijacking execution.\n\nAttackers can leverage this to gain access to process memory, escalate privileges, or stealthily monitor/alter execution within legitimate applications. This technique is also effective for evading detection, since the injected code executes under the context of trusted processes.\n\nEnvironment variables can be set directly in the shell, via startup scripts, programmatically (e.g., Python's `os.environ`), or persistently using `/etc/ld.so.preload` on Linux.\n\nOn macOS, `DYLD_INSERT_LIBRARIES` functions similarly, inserting attacker-controlled dynamic libraries before system libraries load, potentially bypassing hardened runtime protections if SIP is disabled or misconfigured.",
        "tags": ["LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "Shared Library Injection", "Dynamic Linking", "Linux", "macOS"],
        "tactic": "Defense Evasion, Persistence, Privilege Escalation",
        "protocol": "",
        "os": "Linux, macOS",
        "tips": [
            "Use environment hardening tools or policies to restrict the use of preload variables.",
            "Alert on usage of `LD_PRELOAD` and `DYLD_INSERT_LIBRARIES` outside of known safe binaries or testing contexts.",
            "Hash and monitor libraries loaded into high-privilege applications."
        ],
        "data_sources": "Command: Command Execution, File: File Creation, File: File Modification, Module: Module Load, Process: Process Creation",
        "log_sources": [
            {"type": "File", "source": "/etc/ld.so.preload, shell init scripts", "destination": ""},
            {"type": "Process", "source": "Auditd, EDR, macOS Unified Logs", "destination": ""},
            {"type": "Command", "source": "Bash/Zsh history, EDR command-line logging", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Library", "location": "Custom shared objects or dylibs", "identify": "Loaded via environment variable or preload config"}
        ],
        "destination_artifacts": [
            {"type": "Process", "location": "High-privilege application", "identify": "Injected via linker hijack"}
        ],
        "detection_methods": [
            "Monitor `/etc/ld.so.preload` and `.bashrc`, `.zshrc`, or launch agents for variable manipulation.",
            "Detect use of preload-related variables in command execution (e.g., `LD_PRELOAD=/tmp/malicious.so ls`).",
            "Compare shared library hashes and audit process memory maps for unexpected injections."
        ],
        "apt": [],
        "spl_query": [
            "index=os_logs sourcetype=linux_commands OR sourcetype=macos_logs\n| search CommandLine=\"*LD_PRELOAD=*\" OR CommandLine=\"*DYLD_INSERT_LIBRARIES=*\"\n| stats count by host, user, CommandLine"
        ],
        "hunt_steps": [
            "Check `/etc/ld.so.preload` and user shell profiles for unauthorized shared objects.",
            "Enumerate loaded modules in critical processes (e.g., sshd, sudo, loginwindow) for anomalies.",
            "Audit environment variables of long-lived or privileged processes."
        ],
        "expected_outcomes": [
            "Discovery of malicious preload configurations or injected libraries.",
            "Identification of attacker persistence via dynamic linker abuse.",
            "Improved visibility into stealthy privilege escalation vectors."
        ],
        "false_positive": "System administrators and developers may use LD_PRELOAD for debugging. Validate intent and context for any use.",
        "clearing_steps": [
            "Remove malicious entries from `/etc/ld.so.preload` or shell startup files.",
            "Unset `LD_PRELOAD`, `DYLD_INSERT_LIBRARIES` in user sessions or startup configs.",
            "Audit and remove suspicious shared objects or preload libraries."
        ],
        "mitre_mapping": [
            {"tactic": "Persistence", "technique": "T1574.006", "example": "Malicious `libcrypto.so` injected via `LD_PRELOAD` in SSH sessions"},
            {"tactic": "Privilege Escalation", "technique": "T1574.006", "example": "`DYLD_INSERT_LIBRARIES` used to hijack execution of system utility on macOS"}
        ],
        "watchlist": [
            "Execution of commands setting `LD_PRELOAD` or `DYLD_INSERT_LIBRARIES`",
            "Changes to `/etc/ld.so.preload`, `/etc/environment`, or `~/.bashrc`",
            "Library injection into processes not typically using dynamic overrides"
        ],
        "enhancements": [
            "Use kernel module signing and SIP (macOS) to enforce linker behavior.",
            "Implement runtime integrity checks for preload-sensitive apps.",
            "Leverage MAC frameworks like AppArmor or SELinux to restrict library loading paths."
        ],
        "summary": "This technique abuses dynamic linker environment variables (e.g., LD_PRELOAD, DYLD_INSERT_LIBRARIES) to inject shared libraries into processes. It enables attackers to override or hijack legitimate function calls, establishing stealthy persistence and privilege escalation.",
        "remediation": "Restrict and monitor the use of preload variables. Ensure sensitive binaries validate or hardcode library paths and disable unnecessary dynamic loading behavior.",
        "improvements": "Deploy AppArmor/SELinux or hardened runtime policies. Set `LD_PRELOAD` protections at kernel level when possible.",
        "mitre_version": "16.1"
    }
