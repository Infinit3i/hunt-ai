def get_content():
    return {
        "id": "T1574.014",
        "url_id": "T1574/014",
        "title": "Hijack Execution Flow: AppDomainManager",
        "description": "Adversaries may execute their own malicious payloads by hijacking how the .NET `AppDomainManager` loads assemblies. The .NET framework uses this class to create and manage isolated runtime environments (application domains) inside a process. These environments host the execution of .NET applications. By exploiting this, adversaries can load arbitrary assemblies into trusted processes using configuration files, environment variables, or custom application domains.\n\nThis technique, known as *AppDomainManager injection*, can be used to gain code execution without direct process injection. A malicious actor may alter `.config` files or set specific environment variables (like `APPDOMAIN_MANAGER_ASM` and `APPDOMAIN_MANAGER_TYPE`) to force a benign .NET application to load a malicious payload at runtime.",
        "tags": [".NET", "AppDomainManager", "execution hijack", "persistence", "privilege escalation", "Windows"],
        "tactic": "Defense Evasion, Persistence, Privilege Escalation",
        "protocol": "",
        "os": "Windows",
        "tips": [
            "Monitor configuration files (.config) and related environment variables for unauthorized changes.",
            "Use .NET profiling tools to detect unexpected AppDomainManager behavior.",
            "Restrict file and environment access to sensitive applications."
        ],
        "data_sources": "File: File Creation, Module: Module Load, Process: Process Creation",
        "log_sources": [
            {"type": "File", "source": "Creation or modification of .NET config files", "destination": ""},
            {"type": "Process", "source": "Startup parameters and loaded modules", "destination": ""},
            {"type": "Module", "source": "Unusual DLLs loaded into .NET-based applications", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Modified .config files", "location": "App root directory", "identify": "APPDOMAIN_MANAGER_ASM reference"},
            {"type": "Environment variables", "location": "Process launch context", "identify": "APPDOMAIN_MANAGER_TYPE"}
        ],
        "destination_artifacts": [
            {"type": "Malicious DLL", "location": "Loaded into target .NET process", "identify": "Non-standard AppDomainManager implementation"},
            {"type": "AppDomainManager logs", "location": "Event Logs or ETW", "identify": "Unusual domain creation or module load"}
        ],
        "detection_methods": [
            "Alert on modifications to known .NET application config files",
            "Use EDR to trace execution flow from environment variables to AppDomainManager loading",
            "Monitor .NET Event Tracing for Windows (ETW) for anomalous AppDomain behavior"
        ],
        "apt": ["Yellow Liderc"],
        "spl_query": [
            "index=sysmon EventCode=1 Image=\"*.exe\" CommandLine=\"*APPDOMAIN_MANAGER_ASM*\"\n| stats count by Image, CommandLine, ParentImage"
        ],
        "hunt_steps": [
            "Search for `.config` files modified within the last 7 days",
            "Check system-wide environment variables referencing `AppDomainManager`",
            "Correlate .NET application launches with uncommon DLL loads"
        ],
        "expected_outcomes": [
            "Discovery of persistence using .NET configuration tampering",
            "Detection of stealthy execution within trusted .NET processes",
            "Uncovering privilege escalation via hijacked AppDomainManager injection"
        ],
        "false_positive": "Developers and legitimate IT tools may use AppDomainManager customization during debugging or testing. Investigate unfamiliar AppDomainManager references and DLL origins.",
        "clearing_steps": [
            "Remove malicious references from configuration files",
            "Delete rogue AppDomainManager DLLs",
            "Reset compromised environment variables"
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1574.014", "example": "Hijacking AppDomainManager through modified .NET configuration or environment variables"}
        ],
        "watchlist": [
            "Use of APPDOMAIN_MANAGER_ASM and APPDOMAIN_MANAGER_TYPE in user environment variables",
            "Unexpected changes to .NET configuration files in system-critical paths",
            "New DLLs loading into applications like `msbuild.exe`, `powershell.exe`, or `visualstudio.exe`"
        ],
        "enhancements": [
            "Enable Sysmon config to track DLL load paths and hashes",
            "Tag signed and trusted AppDomainManagers to whitelist known behavior",
            "Use AMSI or CLR instrumentation to inspect in-memory assemblies"
        ],
        "summary": "AppDomainManager injection is a powerful .NET-specific technique for loading code via hijacked runtime environments. It offers stealth and control, especially in defense evasion and persistence scenarios.",
        "remediation": "Harden environment variable usage, apply strict config file permissions, and implement trusted path execution policies for .NET apps.",
        "improvements": "Add alerts for new AppDomainManager implementations on endpoints. Incorporate .NET runtime telemetry into SOC monitoring pipelines.",
        "mitre_version": "16.1"
    }
