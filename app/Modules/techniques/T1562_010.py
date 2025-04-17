def get_content():
    return {
        "id": "T1562.010",
        "url_id": "T1562/010",
        "title": "Impair Defenses: Downgrade Attack",
        "description": "Adversaries may perform downgrade attacks by forcing a system or application to revert to older, less secure versions of features or protocols that lack modern security protections. These techniques exploit backward compatibility mechanisms or version-specific configurations to disable or circumvent defenses.\n\nFor example, an attacker may invoke an older version of PowerShell (e.g., `powershell -v 2`) to avoid detection mechanisms like Script Block Logging introduced in later versions. Similarly, adversaries may attempt to downgrade network communications from HTTPS to HTTP, exposing traffic to interception and tampering via Adversary-in-the-Middle or Network Sniffing techniques.\n\nThis method is used to bypass visibility and logging, especially in mature environments with advanced monitoring tools or controls that apply only to modern versions of system components.",
        "tags": ["downgrade", "powershell", "SBL evasion", "http downgrade", "command evasion", "compatibility"],
        "tactic": "Defense Evasion",
        "protocol": "",
        "os": "Linux, Windows, macOS",
        "tips": [
            "Restrict access to legacy interpreters or features through allowlisting or AppLocker policies.",
            "Enforce strict transport security (HSTS) policies to prevent protocol downgrades.",
            "Alert on use of outdated scripting or command-line interface versions in production systems."
        ],
        "data_sources": "Command, Process",
        "log_sources": [
            {"type": "Command", "source": "CLI", "destination": ""},
            {"type": "Process", "source": "Host", "destination": ""},
            {"type": "Process Metadata", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Command Execution", "location": "powershell -v 2", "identify": "Explicit call to legacy PowerShell interpreter"},
            {"type": "Network Request", "location": "HTTP instead of HTTPS", "identify": "Downgraded encrypted connections"},
            {"type": "Process Metadata", "location": "Event ID 400", "identify": "Low EngineVersion field for PowerShell execution"}
        ],
        "destination_artifacts": [
            {"type": "Process Creation Logs", "location": "Sysmon EventCode=1 or WinEvent 4688", "identify": "Legacy tool invocation"},
            {"type": "Network Traffic", "location": "Web proxy, Netflow, packet capture", "identify": "Unencrypted HTTP sessions on port 80"},
            {"type": "PowerShell Logging", "location": "Windows PowerShell/Operational logs", "identify": "Disabled or missing ScriptBlockLogging"}
        ],
        "detection_methods": [
            "Monitor for `powershell -v 2` or older shell environments invoked in modern hosts",
            "Analyze network logs for HTTP sessions where HTTPS is expected",
            "Trigger alerts when the PowerShell `EngineVersion` is lower than expected in the environment",
            "Correlate parent-child process relationships to detect unusual command execution behavior"
        ],
        "apt": ["APT29", "Silent Trinity", "Various ransomware operators"],
        "spl_query": [
            "index=wineventlog EventCode=400 \n| search EngineVersion < 5 \n| stats count by host, UserID, EngineVersion",
            "index=wineventlog OR sysmon EventCode=4688 OR EventCode=1 \n| search CommandLine IN (*powershell -v 2*, *cmd*, *wscript*) \n| stats count by host, parent_process, CommandLine",
            "index=network_logs sourcetype=http \n| stats count by src_ip, dest_ip, uri_path"
        ],
        "hunt_steps": [
            "Query PowerShell logs for older EngineVersion executions (v2 or below)",
            "Inspect proxy and firewall logs for downgrade from HTTPS to HTTP",
            "Correlate downgrade indicators with script execution, privilege escalation, or lateral movement",
            "Validate downgrade attempts against change control or IT maintenance records"
        ],
        "expected_outcomes": [
            "Identification of legacy command interpreters used in high-integrity sessions",
            "Detection of suspicious HTTP traffic where encryption was expected",
            "Alerting on PowerShell downgrade and evasion of audit logging"
        ],
        "false_positive": "IT support or legacy applications may invoke older shells or HTTP traffic for compatibility. Review context, initiator, and business justification.",
        "clearing_steps": [
            "Block legacy interpreter usage via endpoint control (e.g., AppLocker, WDAC)",
            "Enforce HTTPS-only traffic through reverse proxies or application-level security controls",
            "Apply group policies enforcing minimum PowerShell versions"
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1562.010", "example": "Running PowerShell with `-v 2` to bypass logging via Script Block Logging"},
            {"tactic": "Credential Access", "technique": "T1557", "example": "HTTP downgrade enabling credential interception in transit"}
        ],
        "watchlist": [
            "EngineVersion field < 5 in PowerShell logs",
            "Repeated use of `powershell -v 2` on production endpoints",
            "Surge in HTTP traffic to previously HTTPS-only endpoints"
        ],
        "enhancements": [
            "Deploy HSTS headers and enforce SSL pinning in apps",
            "Implement SIEM logic to detect and correlate outdated interpreter usage",
            "Perform TLS downgrade attack simulations during red team exercises"
        ],
        "summary": "T1562.010 outlines how adversaries exploit outdated or less-secure versions of system components to evade detection and reduce telemetry. Downgrade attacks may target interpreters like PowerShell or network protocols like HTTPS to bypass controls.",
        "remediation": "Disable support for outdated interpreter versions, enforce encrypted transport protocols, and harden system configurations against fallback mechanisms.",
        "improvements": "Regularly audit environment for legacy compatibility dependencies. Ensure endpoint monitoring supports detection of deprecated command versions or traffic downgrades.",
        "mitre_version": "16.1"
    }
