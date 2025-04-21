def get_content():
    return {
        "id": "T1574.012",
        "url_id": "T1574/012",
        "title": "Hijack Execution Flow: COR_PROFILER",
        "description": "Adversaries may hijack execution by abusing the COR_PROFILER environment variable, a .NET Framework mechanism for profiling and debugging managed code. When a process loads the Common Language Runtime (CLR), it can be instructed to load a profiler DLL specified in the COR_PROFILER variable.\n\nThe profiler can be registered in the system/user environment variables (via the Registry) or set per-process in-memory. Combined with the COR_PROFILER_PATH variable, adversaries can ensure the CLR loads a specified (and potentially malicious) DLL.\n\nThis method is effective for persistence, privilege escalation (e.g., via [UAC bypass](https://attack.mitre.org/techniques/T1548/002)), and defense evasion, especially when the profiler DLL is injected into trusted .NET processes. The profiler does not need to be registered as a COM object in .NET 4+, enabling stealthier in-memory injection. It may also be used to hook sensitive APIs or impair .NET-based defenses.",
        "tags": ["COR_PROFILER", ".NET CLR", "Execution Hijack", "Persistence", "UAC Bypass", "Registry"],
        "tactic": "Defense Evasion, Persistence, Privilege Escalation",
        "protocol": "",
        "os": "Windows",
        "tips": [
            "Flag creation or modification of `COR_ENABLE_PROFILING`, `COR_PROFILER`, or `COR_PROFILER_PATH` registry values.",
            "Scrutinize suspicious DLLs loaded shortly after the CLR is initialized.",
            "Monitor for profiler configuration using tools like `reg.exe`, `setx.exe`, or WMI/PowerShell."
        ],
        "data_sources": "Command: Command Execution, Module: Module Load, Process: Process Creation, Windows Registry: Windows Registry Key Modification",
        "log_sources": [
            {"type": "Registry", "source": "HKLM/HKCU Environment keys", "destination": ""},
            {"type": "Process", "source": "Module load tracing (Profiler DLLs in .NET processes)", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Environment Variable", "location": "Registry/System/User", "identify": "COR_PROFILER and related keys"},
            {"type": "DLL", "location": "Disk/Memory", "identify": "Profiler DLL specified in COR_PROFILER_PATH"}
        ],
        "destination_artifacts": [
            {"type": "Code Injection", "location": ".NET Processes", "identify": "Profiler DLL loaded into .NET runtime"},
            {"type": "Registry Keys", "location": "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment", "identify": "COR_ENABLE_PROFILING, COR_PROFILER"}
        ],
        "detection_methods": [
            "Track registry changes to COR_PROFILER/COR_PROFILER_PATH keys using Sysmon Event ID 13.",
            "Alert on suspicious profiler DLLs loaded into sensitive processes (e.g., `powershell.exe`, `winlogon.exe`).",
            "Use AppLocker or Windows Defender Application Control to restrict unauthorized DLLs."
        ],
        "apt": ["DarkTortilla", "Mockingbird"],
        "spl_query": [
            "index=sysmon EventCode=13 TargetObject=\"*COR_PROFILER*\"\n| stats count by TargetObject, Image, User"
        ],
        "hunt_steps": [
            "Check for unusual values of `COR_PROFILER_PATH` or GUIDs in `COR_PROFILER`",
            "Scan loaded .NET processes for DLLs not part of standard Microsoft SDKs",
            "Trace execution paths leading to profiler DLL initialization"
        ],
        "expected_outcomes": [
            "Discovery of unauthorized profiler DLLs injected into .NET processes",
            "Identification of malicious persistence through registry-based profiling hooks",
            "Isolation of processes exhibiting abnormal behavior post-profiler DLL load"
        ],
        "false_positive": "Legitimate developer tools like JetBrains dotTrace or Microsoft profilers may use this variable. Verify the GUID, DLL path, and tool presence before triaging.",
        "clearing_steps": [
            "Delete suspicious COR_PROFILER registry values or unset environment variables",
            "Terminate affected .NET processes and unload malicious profiler DLLs",
            "Clean up and restore legitimate development or runtime environments"
        ],
        "mitre_mapping": [
            {"tactic": "Persistence", "technique": "T1574.012", "example": "Setting COR_PROFILER to inject malicious DLL into all .NET processes"},
            {"tactic": "Defense Evasion", "technique": "T1574.012", "example": "Using COR_PROFILER to hook API calls or impair AV telemetry"}
        ],
        "watchlist": [
            "Profiler DLLs not signed by trusted vendors",
            "High-integrity processes loading DLLs from user space paths",
            "Repeated registry changes to COR_PROFILER keys across reboots"
        ],
        "enhancements": [
            "Deploy EDR behavioral rules for profiler DLL injection via COR_PROFILER",
            "Regular audits of .NET-related environment variables and registry keys",
            "Configure AppLocker to prevent untrusted DLLs from being loaded into CLR"
        ],
        "summary": "COR_PROFILER hijacking leverages .NET's legitimate profiling functionality to inject arbitrary code into all .NET processes, allowing stealthy persistence and evasive execution.",
        "remediation": "Restrict registry access and enforce trusted paths for profiler DLLs. Educate developers on proper use of COR_PROFILER and restrict elevated execution contexts.",
        "improvements": "Develop threat hunting playbooks that combine registry change tracking with .NET profiler GUID resolution and suspicious DLL loading alerts.",
        "mitre_version": "16.1"
    }
