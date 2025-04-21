def get_content():
    return {
        "id": "T1614.001",
        "url_id": "T1614.001",
        "title": "System Location Discovery: System Language Discovery",
        "description": "Adversaries may attempt to identify the system language of a compromised host to infer the victim’s geographic region. This tactic is often used to evade legal consequences or scrutiny, particularly from countries associated with strict cybercrime enforcement. Malware may inspect environment variables, registry keys, or utilize API functions to retrieve locale and language settings. For instance, adversaries may query Windows Registry keys such as `HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Nls\\Language` or call API functions like `GetUserDefaultUILanguage`, `GetSystemDefaultUILanguage`, and `GetUserDefaultLangID`. On Unix-based systems, adversaries may retrieve locale values via the `locale` command or the `$LANG` environment variable.",
        "tags": ["locale", "language check", "regional evasion", "registry", "API call", "environment variable"],
        "tactic": "Discovery",
        "protocol": "",
        "os": "Linux, Windows, macOS",
        "tips": [
            "Watch for common locale-based evasion patterns such as avoiding execution on Russian or Ukrainian systems.",
            "Track usage of Windows API calls related to language discovery, especially during malware staging phases.",
            "On Unix systems, watch for unexpected execution of the `locale` command or access to `$LANG`."
        ],
        "data_sources": "Command: Command Execution, Process: OS API Execution, Process: Process Creation, Windows Registry: Windows Registry Key Access",
        "log_sources": [
            {"type": "Command", "source": "Auditd, Sysmon, EDR", "destination": ""},
            {"type": "Process", "source": "Sysmon, macOS Unified Logs", "destination": ""},
            {"type": "Windows Registry", "source": "Sysmon Event ID 13", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Registry Key Query", "location": "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Nls\\Language", "identify": "language codes"},
            {"type": "API Calls", "location": "Memory Trace or ETW", "identify": "GetSystemDefaultUILanguage, GetUserDefaultLangID"},
            {"type": "Shell Execution", "location": "Unix Shell", "identify": "locale or echo $LANG"}
        ],
        "destination_artifacts": [
            {"type": "Memory Data", "location": "OS API", "identify": "system locale or language returned"},
            {"type": "Registry Value", "location": "HKLM Registry", "identify": "language setting codes"},
            {"type": "Environment Variable", "location": "Process ENV", "identify": "LANG"}
        ],
        "detection_methods": [
            "Detect access to registry paths related to language settings.",
            "Monitor API calls like GetSystemDefaultUILanguage or GetUserDefaultLangID.",
            "Log usage of the `locale` command or access to `$LANG` on Linux/macOS systems.",
            "Correlate with execution of known evasive payloads that disable functions based on region."
        ],
        "apt": [
            "Ryuk: Used language checks to avoid systems in Eastern Europe.",
            "JSWorm: Avoided execution on Russian systems based on locale.",
            "Sodinokibi (REvil): Checked registry keys for language detection.",
            "Maze: Performed API-based language checks during staging."
        ],
        "spl_query": "index=sysmon EventCode=13 RegistryPath=*\\Nls\\Language* \n| stats count by Computer, User, RegistryValueName, Details",
        "spl_rule": "https://research.splunk.com/detections/tactics/discovery/",
        "elastic_rule": "https://grep.app/search?f.repo=elastic%2Fdetection-rules&q=T1614.001",
        "sigma_rule": "https://grep.app/search?f.repo=SigmaHQ%2Fsigma&q=T1614.001",
        "hunt_steps": [
            "Query process logs for invocations of `locale`, `echo $LANG`, or `GetUserDefaultLangID`.",
            "Search registry access logs for entries under `Nls\\Language`.",
            "Correlate language detection behavior with script execution or initial payload activity.",
            "Hunt for script payloads that exit early if specific locales are found."
        ],
        "expected_outcomes": [
            "Identified malware using regional evasion techniques.",
            "Insight into adversary decision logic tied to geopolitical boundaries.",
            "Detection of language-based conditional logic for execution control."
        ],
        "false_positive": "Some legitimate software or localization tools may access system language for compatibility or UX purposes.",
        "clearing_steps": [
            "Limit unnecessary access to locale APIs for untrusted applications.",
            "Deploy registry auditing for sensitive locale values.",
            "Restrict scripting environments from retrieving environment-based language data unless required."
        ],
        "mitre_mapping": [
            {"tactic": "Discovery", "technique": "T1614.001 (System Language Discovery)", "example": "Use of registry key or API calls to avoid Russian systems."}
        ],
        "watchlist": [
            "Language checks preceding script execution.",
            "Registry value queries that match `HKLM\\...\\Nls\\Language`.",
            "Language or locale lookups immediately followed by process termination."
        ],
        "enhancements": [
            "Add detection signatures for specific API sequences related to regional detection.",
            "Integrate behavioral analytics to identify evasion workflows based on locale.",
            "Deploy deceptive language settings on honeypots to identify evasive malware."
        ],
        "summary": "System Language Discovery enables adversaries to evade detection or legal consequences by avoiding infections in specific regions. This may include use of registry lookups, API calls, or environment variable parsing to determine system locale.",
        "remediation": "Audit and restrict language discovery attempts from unknown binaries, particularly those tied to initial access or execution stages. Implement process monitoring and alerting on language-based evasion.",
        "improvements": "Integrate telemetry that tracks use of locale-sensitive APIs across malicious campaigns. Expand endpoint behavioral detections to include pre-execution language checks.",
        "mitre_version": "16.1"
    }
