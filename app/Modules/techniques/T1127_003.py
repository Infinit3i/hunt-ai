def get_content():
    return {
        "id": "T1127.003",
        "url_id": "T1127/003",
        "title": "JamPlus",
        "description": "Adversaries may use JamPlus to proxy the execution of a malicious script.",
        "tags": ["jamplus", "developer tools", "defense evasion", "proxy execution", "trusted utility"],
        "tactic": "defense-evasion",
        "protocol": "",
        "os": "Windows",
        "tips": [
            "Restrict or remove JamPlus from systems where it's not required.",
            "Inspect .jam file contents for signs of scripting or external execution.",
            "Flag unexpected invocations of jam.exe or jamplus.exe."
        ],
        "data_sources": "Process",
        "log_sources": [
            {"type": "Process", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Event Logs", "location": "Security.evtx", "identify": "jam.exe or jamplus.exe process creation with suspicious arguments"}
        ],
        "destination_artifacts": [
            {"type": "Process List", "location": "RAM", "identify": "jamplus.exe spawning script interpreters or unsigned binaries"}
        ],
        "detection_methods": [
            "Monitor process creation for JamPlus with unexpected .jam file references.",
            "Detect downstream processes launched by jamplus.exe, especially scripting engines."
        ],
        "apt": [],
        "spl_query": [
            "index=* sourcetype=WinEventLog:Security EventCode=4688 New_Process_Name=*jamplus.exe* OR New_Process_Name=*jam.exe*\n| stats count by New_Process_Name, Command_Line, Parent_Process_Name, host, user"
        ],
        "hunt_steps": [
            "Search for jamplus.exe executions across the enterprise.",
            "Review associated command-line arguments and spawned child processes.",
            "Investigate .jam files used as inputs and check for encoded or suspicious content."
        ],
        "expected_outcomes": [
            "Detection of misuse of JamPlus to execute scripts or evade application controls."
        ],
        "false_positive": "Legitimate developers may use JamPlus in build environments. Validate context and origin.",
        "clearing_steps": [
            "taskkill /f /im jamplus.exe",
            "Remove unauthorized .jam files from project directories",
            "Audit use of developer tools and limit execution rights"
        ],
        "clearing_playbook": [
            "https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-malware"
        ],
        "mitre_mapping": [
            {"tactic": "defense-evasion", "technique": "T1127", "example": "Trusted Developer Utilities Proxy Execution"},
            {"tactic": "defense-evasion", "technique": "T1218", "example": "Signed Binary Proxy Execution"}
        ],
        "watchlist": [
            "jamplus.exe spawning script interpreters",
            "Unexpected use of JamPlus in non-development machines"
        ],
        "enhancements": [
            "Create rules in EDR platforms for rare use of JamPlus or jam.exe.",
            "Scan .jam files for embedded PowerShell or cmd commands."
        ],
        "summary": "JamPlus may be leveraged by adversaries to execute scripts via a trusted developer utility, bypassing security controls such as Smart App Control.",
        "remediation": "Remove JamPlus if not used in the environment and audit developer tool usage regularly.",
        "improvements": "Enhance behavioral baselining for developer utilities and link build activity to expected user roles.",
        "mitre_version": "17.0"
    }
