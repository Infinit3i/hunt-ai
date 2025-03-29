def get_content():
    return {
        "id": "T1216",
        "url_id": "T1216",
        "title": "System Script Proxy Execution",
        "description": "Adversaries may abuse signed or trusted system scripts to proxy the execution of malicious payloads, bypassing application control and security validation.",
        "tags": ["LOLBAS", "Defense Evasion", "Script Proxy", "AppLocker Bypass"],
        "tactic": "Defense Evasion",
        "protocol": "N/A",
        "os": "Windows",
        "tips": [
            "Monitor for execution of script hosts such as `wscript.exe`, `cscript.exe`, or PowerShell executing known LOLBAS scripts.",
            "Track command-line arguments passed to known script proxies (e.g., `PubPrn.vbs`, `InstallUtil.exe`).",
            "Enable script block logging in PowerShell and constrain script execution policies."
        ],
        "data_sources": "Windows Event Logs, Sysmon, Script Execution Logs",
        "log_sources": [
            {"type": "Script", "source": "Sysmon Event ID 1 (Process Creation)", "destination": ""},
            {"type": "Command", "source": "PowerShell Operational Log", "destination": ""},
            {"type": "Process", "source": "Windows Event Logs (4688)", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Script Files", "location": "System32 or Downloaded Folder", "identify": "Signed Microsoft script used for proxying (e.g., PubPrn.vbs)"}
        ],
        "destination_artifacts": [
            {"type": "Child Process Execution", "location": "Spawned by Signed Script Host", "identify": "Malicious binary executed via script host"}
        ],
        "detection_methods": [
            "Monitor command-line arguments of script interpreters for signs of abuse.",
            "Detect execution of scripts known to be LOLBAS with suspicious parameters.",
            "Correlate signed scripts spawning unsigned or abnormal processes."
        ],
        "apt": ["APT29", "Wizard Spider"],
        "spl_query": [
            "index=sysmon EventCode=1 (ParentImage=\"*wscript.exe\" OR ParentImage=\"*cscript.exe\") CommandLine=\"*PubPrn.vbs*\" \n| stats count by ParentImage, CommandLine, Image"
        ],
        "hunt_steps": [
            "Identify usage of known LOLBAS scripts within the environment.",
            "Trace child process trees originating from `cscript.exe` or `wscript.exe`.",
            "Correlate proxy script executions with unsigned binaries or unusual parent-child chains."
        ],
        "expected_outcomes": [
            "Detection of malicious activity proxying execution via signed system scripts.",
            "No suspicious proxy executions found; refine rules or baselines."
        ],
        "false_positive": "Some legitimate administrative tasks may use these scripts, but usage should be rare and well-documented.",
        "clearing_steps": [
            "Kill any unauthorized processes spawned via signed scripts.",
            "Review and harden AppLocker or WDAC policies to block script proxy execution.",
            "Remove or restrict access to known LOLBAS scripts if not required."
        ],
        "clearing_playbook": [
            "https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-execution"
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1216", "example": "Adversary uses PubPrn.vbs to proxy execution of malware and bypass AppLocker controls."},
            {"tactic": "Execution", "technique": "T1059", "example": "Script interpreters used to launch LOLBAS scripts for proxying execution."}
        ],
        "watchlist": [
            "Execution of LOLBAS scripts like PubPrn.vbs, mshta.exe, InstallUtil.exe",
            "Scripts spawning executables in user temp or download folders",
            "Script interpreters starting unsigned child processes"
        ],
        "enhancements": [
            "Implement AppLocker/WDAC to block LOLBAS paths.",
            "Deploy PowerShell logging (Module Logging, Script Block Logging).",
            "Monitor for signed binaries used for proxy execution from non-standard locations."
        ],
        "summary": "System Script Proxy Execution allows adversaries to abuse trusted signed scripts to execute malicious payloads and evade security controls.",
        "remediation": "Restrict execution of non-essential scripting tools, enforce strong execution policies, and block known proxying scripts via application control.",
        "improvements": "Enhance detection for script misuse and integrate LOLBAS rules into EDR/SIEM platforms.",
        "mitre_version": "16.1"
    }
