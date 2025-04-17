def get_content():
    return {
        "id": "T1562.003",
        "url_id": "T1562/003",
        "title": "Impair Defenses: Impair Command History Logging",
        "description": "Adversaries may impair command history logging to obscure executed commands on compromised systems. Command history is a valuable forensic artifact for understanding user activity. On Unix-like systems, command history is stored in files like `~/.bash_history`, governed by variables such as `HISTFILE`, `HISTCONTROL`, and `HISTFILESIZE`. Adversaries may unset these variables, redirect the log path, or configure them to ignore specific command patterns (e.g., prepended with spaces).\n\nOn Windows, PowerShell's `PSReadLine` module maintains command history in `ConsoleHost_history.txt`. Adversaries may disable this logging via `Set-PSReadLineOption -HistorySaveStyle SaveNothing` or redirect logs to alternate paths using `-HistorySavePath`. Network devices may also support disabling CLI history using commands like `no logging`. These actions allow attackers to operate without leaving obvious trails.",
        "tags": ["command logging", "history tampering", "bash", "PowerShell", "PSReadLine", "defense evasion"],
        "tactic": "Defense Evasion",
        "protocol": "",
        "os": "Linux, Windows, macOS, Network",
        "tips": [
            "Enforce centralized logging of command execution where feasible",
            "Set restrictive permissions on shell profile scripts (.bashrc, PowerShell profile)",
            "Monitor session activity with user correlation to audit trails"
        ],
        "data_sources": "Command, Sensor Health",
        "log_sources": [
            {"type": "Command", "source": "Terminal Input", "destination": ""},
            {"type": "Sensor Health", "source": "Audit Framework, EDR, SIEM", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Environment Variable", "location": "$HISTFILE, $HISTCONTROL, $HISTFILESIZE", "identify": "Modified or unset by attacker"},
            {"type": "PowerShell Setting", "location": "Set-PSReadLineOption", "identify": "Altered history logging behavior"},
            {"type": "Shell Input", "location": "~/.bash_history or console logs", "identify": "Lack of expected history or gaps in sequence"}
        ],
        "destination_artifacts": [
            {"type": "History File", "location": "~/.bash_history, ConsoleHost_history.txt", "identify": "May be cleared, altered, or redirected"},
            {"type": "PowerShell Profile", "location": "$PROFILE", "identify": "Used to persistently disable history logging"},
            {"type": "Network Device Config", "location": "CLI Settings", "identify": "Command history disabled via CLI"}
        ],
        "detection_methods": [
            "Monitor shell profile or PowerShell profile changes that unset or alter history variables",
            "Detect PowerShell commands using `Set-PSReadLineOption` with SaveNothing or alternate paths",
            "Correlate user login sessions with absence of corresponding command activity",
            "Monitor for environment variables like HISTCONTROL, HISTFILESIZE, or PSReadLine being modified unexpectedly"
        ],
        "apt": ["BeagleBoyz", "BPFDoor Operators"],
        "spl_query": [
            "index=sysmon OR powershell EventCode=4103 OR EventCode=4104 \n| search ScriptBlockText IN (*Set-PSReadLineOption*, *HistorySaveStyle*, *HistorySavePath*) \n| stats count by host, user, ScriptBlockText",
            "index=sysmon OR auditd event_type=execve \n| search command IN (unset HISTFILE, export HISTFILESIZE=0, Set-PSReadLineOption*) \n| stats count by host, user, command"
        ],
        "hunt_steps": [
            "Check for shell sessions lacking entries in `.bash_history` post-login",
            "Search for profile or environment changes targeting HIST* variables",
            "Detect PowerShell command history manipulation commands via PSReadLine",
            "Query for gaps in command telemetry across terminal sessions"
        ],
        "expected_outcomes": [
            "Identification of shell environments configured to suppress command logging",
            "Detection of PowerShell users suppressing command trail",
            "Alerting on log redirection or tampering in history files"
        ],
        "false_positive": "System administrators may legitimately suppress or redirect command logging during scripting or automation routines. Context and timing are important.",
        "clearing_steps": [
            "Restore default shell and PowerShell environment variable configurations",
            "Re-enable PSReadLine logging with `Set-PSReadLineOption -HistorySaveStyle SaveIncrementally`",
            "Review and secure shell profile configurations to prevent unauthorized changes"
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1562.003", "example": "Unset HISTFILE and use SaveNothing to avoid history logging"},
            {"tactic": "Defense Evasion", "technique": "T1059", "example": "Shell/PowerShell abuse without record in history files"}
        ],
        "watchlist": [
            "Unset or manipulated HIST* environment variables",
            "Frequent PowerShell use without corresponding entries in command history",
            "PSReadLine configuration changes in non-admin or unusual sessions"
        ],
        "enhancements": [
            "Deploy script-block logging and process auditing",
            "Use centralized command auditing tools like auditd, osquery, or sysmon",
            "Restrict modification of shell and PowerShell logging settings via access controls"
        ],
        "summary": "T1562.003 highlights how adversaries impair visibility into their activity by disabling or manipulating command history logs. Whether on Unix-like systems or Windows PowerShell, these efforts evade forensic trails and inhibit effective response. Continuous monitoring and command telemetry can help identify and mitigate this behavior.",
        "remediation": "Audit and secure user shell configuration files. Reinstate and enforce logging defaults for command history. Validate telemetry against baseline expectations.",
        "improvements": "Integrate cross-session history validation and alert when expected terminal activity is missing from logs. Harden configuration against environmental variable tampering.",
        "mitre_version": "16.1"
    }
