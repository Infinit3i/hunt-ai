def get_content():
    return {
        "id": "T1127.001",
        "url_id": "T1127/001",
        "title": "Trusted Developer Utilities Proxy Execution: MSBuild",
        "description": "Adversaries may abuse MSBuild.exe, a signed Microsoft utility, to proxy execution of malicious code through inline tasks embedded in XML project files.",
        "tags": ["defense evasion", "proxy execution", "LOLBAS", "msbuild", "signed binary abuse"],
        "tactic": "defense-evasion",
        "protocol": "",
        "os": "Windows",
        "tips": [
            "Alert on MSBuild.exe spawning child processes or launching outside of developer workstations",
            "Hunt for abnormal usage of `.proj` or `.targets` files invoking inline C# or VB code",
            "Log all command-line arguments passed to MSBuild"
        ],
        "data_sources": "Command, Process",
        "log_sources": [
            {"type": "Command", "source": "EDR", "destination": ""},
            {"type": "Process", "source": "Sysmon", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Event Logs", "location": "Sysmon Event ID 1", "identify": "Execution of msbuild.exe with suspicious project file"},
            {"type": "File Access Times (MACB Timestamps)", "location": "Project file location", "identify": "Recently accessed .xml/.proj files"},
            {"type": "Memory Dumps", "location": "RAM analysis", "identify": "Inline .NET compiled payloads or reflective shellcode"}
        ],
        "destination_artifacts": [
            {"type": "Process List", "location": "EDR telemetry", "identify": "msbuild.exe spawning cmd.exe, powershell.exe, or similar"},
            {"type": "Prefetch Files", "location": "C:\\Windows\\Prefetch", "identify": "Execution of msbuild.exe on non-dev systems"},
            {"type": "Sysmon Logs", "location": "Event ID 11", "identify": "DLLs or binaries loaded by msbuild that are unsigned"}
        ],
        "detection_methods": [
            "Monitor use of MSBuild on systems not used by developers",
            "Alert when MSBuild loads uncommon XML files or executes code inline",
            "Detect msbuild.exe spawning shells or non-build related binaries"
        ],
        "apt": [
            "PlugX", "Frankenstein", "Empire"
        ],
        "spl_query": [
            'index=sysmon EventCode=1 \n| search Image="*msbuild.exe" AND CommandLine="*.xml" OR "*.proj" \n| stats count by CommandLine, User',
            'index=sysmon EventCode=1 \n| search ParentImage="*msbuild.exe" AND (Image="*cmd.exe" OR Image="*powershell.exe") \n| stats count by ParentImage, Image, CommandLine',
            'index=process \n| search CommandLine="*usingTask*TaskFactory*" AND CommandLine="*CodeTaskFactory*" \n| stats count by CommandLine, ComputerName'
        ],
        "hunt_steps": [
            "Hunt for msbuild.exe usage outside software development workstations",
            "Check for processes spawned by MSBuild with shell, scripting, or obfuscated names",
            "Review recent modifications or additions to project files containing embedded code"
        ],
        "expected_outcomes": [
            "Detection of proxy execution through msbuild inline task abuse",
            "Identification of signed binary misused for code execution",
            "Correlation of MSBuild activity with payload staging"
        ],
        "false_positive": "Legitimate development activity. Verify project origin, contents, and user role before triage.",
        "clearing_steps": [
            "Remove malicious project files or payloads embedded via MSBuild",
            "Terminate msbuild.exe processes executing suspicious child processes",
            "Disable MSBuild execution for non-development users via AppLocker or WDAC"
        ],
        "mitre_mapping": [
            {"tactic": "execution", "technique": "T1059.001", "example": "Inline C# executed via CodeTaskFactory"},
            {"tactic": "defense-evasion", "technique": "T1218.005", "example": "LOLBAS binary msbuild.exe abused for execution"},
            {"tactic": "execution", "technique": "T1203", "example": "Crafted .proj file as initial payload delivery"}
        ],
        "watchlist": [
            "MSBuild executing outside IDE context",
            "Use of `CodeTaskFactory` or `UsingTask` in XML build files",
            "MSBuild processes generating network traffic or loading shellcode"
        ],
        "enhancements": [
            "Restrict MSBuild usage via WDAC policies on endpoints",
            "Implement PowerShell transcript and MSBuild argument logging",
            "Tag msbuild.exe activity with metadata such as project origin and user"
        ],
        "summary": "MSBuild can be abused to execute code using its inline task features, enabling attackers to run arbitrary code via a signed Microsoft utility to bypass controls.",
        "remediation": "Disable MSBuild where not needed, monitor its execution chain, and block abuse using application control solutions.",
        "improvements": "Apply allowlisting for project files, enforce logging for developer tools, and enable inline code execution alerts.",
        "mitre_version": "16.1"
    }
