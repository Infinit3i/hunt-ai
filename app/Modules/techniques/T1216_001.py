def get_content():
    return {
        "id": "T1216.001",
        "url_id": "T1216/001",
        "title": "System Script Proxy Execution: PubPrn",
        "description": "Adversaries may abuse the signed PubPrn.vbs script to proxy the execution of remote malicious code. PubPrn.vbs is a legitimate Microsoft-signed Visual Basic script for publishing printers in Active Directory. However, older versions allow for the second parameter to reference a remote scriptlet (.sct) via the `script:` moniker, enabling execution of remote payloads. This technique can evade application control and signature validation mechanisms.",
        "tags": ["LOLBAS", "PubPrn", "Defense Evasion", "Signed Binary Proxy Execution", "Scriptlet"],
        "tactic": "Defense Evasion",
        "protocol": "HTTP/HTTPS",
        "os": "Windows",
        "tips": [
            "Block or remove PubPrn.vbs from systems if not required operationally.",
            "Alert on use of PubPrn.vbs with the `script:` parameter.",
            "Deploy allowlist policies for approved scripts and command-line arguments."
        ],
        "data_sources": "Script Execution, Windows Event Logs, Process Monitoring",
        "log_sources": [
            {"type": "Script", "source": "Sysmon Event ID 1 (Process Creation)", "destination": ""},
            {"type": "Command", "source": "CommandLine Audit Logs (4688)", "destination": ""},
            {"type": "Process", "source": "Windows Event Logs", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Script File", "location": "System32", "identify": "PubPrn.vbs invoked with remote scriptlet URL"}
        ],
        "destination_artifacts": [
            {"type": "Child Process", "location": "Spawns from cscript.exe", "identify": "Remote .sct payload executed"}
        ],
        "detection_methods": [
            "Monitor for `cscript.exe` or `wscript.exe` executing `PubPrn.vbs` with `script:` in the command-line.",
            "Detect outbound connections to uncommon domains triggered from script execution.",
            "Alert on any network-based `.sct` file retrievals initiated by `cscript.exe`."
        ],
        "apt": ["APT32", "G0060"],
        "spl_query": [
            "index=windows (CommandLine=\"*pubprn.vbs*\" AND CommandLine=\"*script:*\") \n| stats count by _time, host, ParentImage, CommandLine"
        ],
        "hunt_steps": [
            "Search for execution of `pubprn.vbs` with unexpected parameters such as `script:`.",
            "Analyze child processes launched by `cscript.exe` or `wscript.exe` invoking PubPrn.",
            "Investigate connections to suspicious domains hosting `.sct` files."
        ],
        "expected_outcomes": [
            "Execution of remote scripts via PubPrn is identified and blocked.",
            "No malicious behavior detected; whitelist validated executions."
        ],
        "false_positive": "Low likelihood unless legacy scripts or testing environments replicate this behavior intentionally.",
        "clearing_steps": [
            "Remove or block access to PubPrn.vbs where unnecessary.",
            "Terminate processes spawned via malicious scriptlets.",
            "Apply Windows Defender Application Control (WDAC) rules to block `script:` abuse."
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1216.001", "example": "PubPrn used with a scriptlet URL to load remote code and bypass AppLocker controls."}
        ],
        "watchlist": [
            "Monitor for use of PubPrn.vbs with command-line arguments containing external URLs or `script:`.",
            "Look for `.sct` payloads downloaded and executed by Windows script interpreters.",
            "Detect execution chains involving signed scripts spawning untrusted processes."
        ],
        "enhancements": [
            "Upgrade systems to newer versions of Windows where PubPrn blocks remote execution.",
            "Integrate LOLBAS project signatures into EDR and SIEM tools.",
            "Deploy threat hunting rules that track legacy script proxying behavior."
        ],
        "summary": "PubPrn.vbs can be exploited by adversaries to execute remote payloads, especially in older Windows versions. This abuse may bypass defenses based on signed script trust.",
        "remediation": "Restrict or remove PubPrn.vbs if not required, enforce strict execution policies, and monitor for any use of remote scriptlet references.",
        "improvements": "Apply Microsoft-recommended block rules, extend LOLBAS detection coverage, and refine telemetry on script-based proxy execution.",
        "mitre_version": "2.0"
    }
