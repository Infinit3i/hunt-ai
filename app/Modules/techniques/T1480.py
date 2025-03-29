def get_content():
    return {
        "id": "T1480",
        "url_id": "T1480",
        "title": "Execution Guardrails",
        "description": "Adversaries may use execution guardrails to constrain execution or actions based on adversary supplied and environment specific conditions that are expected to be present on the target. Guardrails ensure that a payload only executes against an intended target and reduces collateral damage from an adversary’s campaign. Values can include specific network share names, attached physical devices, files, AD domains, or IP addresses. This is distinct from Virtualization/Sandbox Evasion, which checks for analysis environments. Guardrails often seek affirmative conditions before proceeding.",
        "tags": ["guardrails", "targeted payload", "conditional execution", "defense evasion"],
        "tactic": "Defense Evasion",
        "protocol": "",
        "os": "Linux, Windows, macOS",
        "tips": [
            "Flag excessive system discovery prior to payload execution.",
            "Look for scripts or binaries checking domain, IPs, or hostname.",
            "Correlate short-lifecycle malware with system fingerprinting."
        ],
        "data_sources": "Command, Process",
        "log_sources": [
            {"type": "Command", "source": "", "destination": ""},
            {"type": "Process", "source": "Sysmon", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "script or binary", "location": "varied", "identify": "conditional execution blocks"},
            {"type": "memory dump", "location": "volatile", "identify": "code branches tied to system checks"}
        ],
        "destination_artifacts": [],
        "detection_methods": [
            "Analyze binaries/scripts for environment-based branching logic",
            "Detect conditionals checking for domains, IPs, users before execution",
            "Alert on user-agent filtering logic inside malware installers"
        ],
        "apt": [
            "Gamaredon", "Nobelium", "Turla", "Lazarus", "Agrius", "APT41", "Anchor"
        ],
        "spl_query": [
            "index=sysmon_logs ImageLoaded=*whoami* OR *nltest* OR *systeminfo*\n| stats count by ParentImage, Image, CommandLine",
            "index=security_logs process_name=*curl* OR *wget* user_agent=*\n| stats count by uri_path, user_agent, parent_process"
        ],
        "hunt_steps": [
            "Search for scripts checking for domain or network names",
            "Trace early-stage binaries that stall unless target fingerprint is met",
            "Flag unusual user-agent filtering logic"
        ],
        "expected_outcomes": [
            "Uncover payloads restricted to specific targets",
            "Find malware using local conditions to delay execution",
            "Expose region-specific, controlled malware distribution"
        ],
        "false_positive": "Some legitimate software may include hardware or license key verification steps. Focus on stealthy patterns used outside install/setup phases.",
        "clearing_steps": [
            "Isolate system and extract conditional logic from payload",
            "Sanitize configurations triggering guardrails",
            "Reset environment variables tied to malicious filters"
        ],
        "clearing_playbook": [
            "https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-malware"
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1480", "example": "Payload runs only if domain == corp.local"},
            {"tactic": "Discovery", "technique": "T1082", "example": "Gathering hostname/IP before launching malware"}
        ],
        "watchlist": [
            "Executables querying system info then exiting",
            "Scripts stalling until specific hostname/IP is found",
            "Payloads with embedded allowlist of network indicators"
        ],
        "enhancements": [
            "Use behavior analytics to detect discovery-before-execution patterns",
            "Integrate host fingerprinting logs with threat intelligence",
            "Automate flagging of user-agent-based payload filters"
        ],
        "summary": "Execution guardrails ensure malware or tools only activate in specific target environments. This reduces exposure and can evade detection in sandboxed or analyst systems.",
        "remediation": "Reverse engineer suspected guarded binaries, extract and neutralize conditions. Monitor early-stage system fingerprinting aggressively.",
        "improvements": "Correlate fingerprinting with delayed execution. Enhance sandbox emulation to match guarded triggers.",
        "mitre_version": "16.1"
    }