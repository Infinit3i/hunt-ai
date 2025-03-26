def get_content():
    return {
        "id": "T1129",
        "url_id": "T1129",
        "title": "Shared Modules",
        "description": "Adversaries may execute malicious payloads via loading shared modules, such as DLLs or .so/.dylib files, to execute code within legitimate processes and evade detection.",
        "tags": ["execution", "shared module", "dll injection", "defense evasion", "native api"],
        "tactic": "execution",
        "protocol": "",
        "os": "Linux, Windows, macOS",
        "tips": [
            "Monitor for unusual DLL or .so/.dylib loads from non-standard directories",
            "Baseline expected shared module activity per application or service",
            "Flag loads from temporary or user-writable directories"
        ],
        "data_sources": "Module, Process",
        "log_sources": [
            {"type": "Module", "source": "Sysmon", "destination": ""},
            {"type": "Process", "source": "Sysmon", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Sysmon Logs", "location": "Event ID 7", "identify": "DLLs loaded by suspicious processes"},
            {"type": "Prefetch Files", "location": "C:\\Windows\\Prefetch", "identify": "Execution of loaders or interpreters"},
            {"type": "Memory Dumps", "location": "Live memory or forensic snapshot", "identify": "Injected or loaded modules in process memory"}
        ],
        "destination_artifacts": [
            {"type": "Module", "location": "Varies by OS", "identify": "Malicious shared object or DLL written to disk"},
            {"type": "Registry Hives (NTUSER.DAT)", "location": "Windows registry", "identify": "Paths for autoloaded DLLs"},
            {"type": "Process List", "location": "Live memory", "identify": "Suspicious modules loaded into legitimate processes"}
        ],
        "detection_methods": [
            "Baseline module load behavior for common processes and flag anomalies",
            "Alert on DLL loads from `%TEMP%`, `%APPDATA%`, or user profile directories",
            "Correlate module loads with unsigned or uncommon DLLs on disk"
        ],
        "apt": [
            "FIN7", "OceanLotus", "DarkWatchman", "TajMahal", "Metamorfo", "Attor"
        ],
        "spl_query": [
            'index=sysmon EventCode=7 \n| search ImageLoaded="*\\Users\\*" OR ImageLoaded="*\\Temp\\*" \n| stats count by Image, ImageLoaded, User',
            'index=sysmon EventCode=7 \n| search ImageLoaded!="C:\\Windows\\*" AND ImageLoaded!="C:\\Program Files*" \n| stats count by ImageLoaded, Image'
        ],
        "hunt_steps": [
            "Enumerate loaded modules via Sysmon Event ID 7 or EDR telemetry",
            "Look for new module names in user-writable directories",
            "Analyze memory of long-running processes for unbacked modules"
        ],
        "expected_outcomes": [
            "Detection of DLLs or shared objects loaded from suspicious locations",
            "Identification of unauthorized module injection into trusted processes",
            "Uncover lateral movement or persistence via module load abuse"
        ],
        "false_positive": "Custom software may load modules from unusual paths—validate signatures and establish expected baselines before alerting.",
        "clearing_steps": [
            "Remove unauthorized DLLs or shared modules from disk",
            "Restart compromised services or systems to purge in-memory injections",
            "Apply ACLs or restrict write access to system module directories"
        ],
        "mitre_mapping": [
            {"tactic": "execution", "technique": "T1106", "example": "LoadLibrary or dlopen used to invoke malicious modules"},
            {"tactic": "defense-evasion", "technique": "T1055", "example": "DLL sideloading or injection"},
            {"tactic": "persistence", "technique": "T1547.001", "example": "Registry path pointing to malicious shared module"}
        ],
        "watchlist": [
            "Processes loading non-signed DLLs or .so/.dylib files from user directories",
            "Shared modules not used previously by a given binary",
            "Changes to autoloaded paths in registry or init scripts"
        ],
        "enhancements": [
            "Enforce DLL SafeSearch and disable DLL search order hijacking",
            "Use AppLocker or WDAC to block execution from non-standard paths",
            "Alert on new or renamed .dylib/.so/.dll files in sensitive areas"
        ],
        "summary": "Shared modules allow adversaries to modularize code execution and load it through trusted processes, making detection more difficult and enabling stealthy persistence.",
        "remediation": "Restrict module loading to approved paths, validate module signatures, and monitor for suspicious loading behavior across operating systems.",
        "improvements": "Incorporate memory scanning for rogue modules and apply machine learning to distinguish benign vs malicious module load patterns.",
        "mitre_version": "16.1"
    }
