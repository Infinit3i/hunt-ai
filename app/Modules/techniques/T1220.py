def get_content():
    return {
        "id": "T1220",
        "url_id": "T1220",
        "title": "XSL Script Processing",
        "description": "Adversaries may bypass application control and obscure execution of code by embedding scripts inside XSL files. These files can be executed using msxsl.exe or via WMI with the /FORMAT switch, allowing script execution from local or remote sources.",
        "tags": ["xsl", "msxsl", "wmic", "squiblytwo", "proxy execution", "LOLBAS", "defense evasion"],
        "tactic": "Defense Evasion",
        "protocol": "HTTP",
        "os": "Windows",
        "tips": [
            "Alert on msxsl.exe or wmic.exe using XSL stylesheets with .xsl, .jpeg, or remote URLs.",
            "Hunt for suspicious process creations with unusual file extensions or command-line switches like /FORMAT.",
            "Monitor for use of msxsl.exe on endpoints where it is not typically installed."
        ],
        "data_sources": "Module, Process",
        "log_sources": [
            {"type": "Process", "source": "Sysmon", "destination": ""},
            {"type": "Module", "source": "Sysmon", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Sysmon Logs", "location": "C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Sysmon%4Operational.evtx", "identify": "Event ID 1 (Process Creation) involving msxsl.exe or wmic.exe with /FORMAT"}
        ],
        "destination_artifacts": [],
        "detection_methods": [
            "Detect execution of msxsl.exe or wmic.exe with script-laced .xsl files",
            "Alert on /FORMAT usage in WMI commands",
            "Look for unusual parent-child relationships involving scripting engines"
        ],
        "apt": [
            "Lazarus", "Cobalt Group", "Astaroth", "Higaisa"
        ],
        "spl_query": [
            "index=sysmon EventCode=1 Image=*\\msxsl.exe OR *\\wmic.exe\n| search CommandLine=\"*.xsl\" OR CommandLine=\"*/FORMAT:*\"\n| stats count by CommandLine, ParentImage, User"
        ],
        "hunt_steps": [
            "Search for msxsl.exe or wmic.exe with .xsl, .jpeg, or remote references",
            "Inspect the contents of used XSL files for embedded JavaScript or VBScript",
            "Look for wmic.exe accessing remote URLs"
        ],
        "expected_outcomes": [
            "Identification of script execution through unexpected binaries",
            "Detection of the 'Squiblytwo' technique using WMI",
            "Discovery of malicious XSL payloads hosted remotely or locally"
        ],
        "false_positive": "Some administrators may use msxsl.exe or /FORMAT with WMI for legitimate XML processing. Validate the context and source files.",
        "clearing_steps": [
            "taskkill /IM msxsl.exe /F",
            "taskkill /IM wmic.exe /F",
            "Delete or quarantine suspicious .xsl files",
            "Audit registry and task scheduler for persistence involving XSL"
        ],
        "clearing_playbook": [
            "https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-malware"
        ],
        "mitre_mapping": [
            {"tactic": "Execution", "technique": "T1059.007", "example": "JavaScript embedded in XSL file executed via msxsl.exe"},
            {"tactic": "Defense Evasion", "technique": "T1218.010", "example": "Proxy execution using trusted utility msxsl.exe"},
            {"tactic": "Defense Evasion", "technique": "T1047", "example": "WMI abuse with /FORMAT:evil.xsl"}
        ],
        "watchlist": [
            "msxsl.exe or wmic.exe executing .xsl or .jpeg extensions",
            "Remote URLs accessed with /FORMAT",
            "Presence of msxsl.exe on systems not used for XML transformation"
        ],
        "enhancements": [
            "Whitelist msxsl.exe only in dev environments",
            "Implement alerts for WMI processes with /FORMAT and HTTP URLs",
            "Scan .xsl files for embedded script tags"
        ],
        "summary": "XSL script processing allows attackers to execute arbitrary code through script-embedded stylesheet files using msxsl.exe or WMI. This technique can be used to bypass defenses via trusted signed binaries and fileless execution.",
        "remediation": "Remove msxsl.exe unless needed. Restrict outbound WMI and monitor use of the /FORMAT switch. Use EDR tools to flag LOLBAS misuse.",
        "improvements": "Improve telemetry on msxsl.exe and wmic.exe execution, and correlate usage with network activity and file system changes.",
        "mitre_version": "16.1"
    }
