def get_content():
    return {
        "id": "T1218.015",
        "url_id": "T1218/015",
        "title": "System Binary Proxy Execution: Electron Applications",
        "description": "Adversaries may abuse components of the Electron framework to execute malicious code. Electron hosts many common applications such as Signal, Slack, and Microsoft Teams and allows execution of arbitrary code via JavaScript and Node.js integration.",
        "tags": ["electron", "teams.exe", "chrome.exe", "javascript injection", "gpu-launcher", "proxy execution", "defense evasion"],
        "tactic": "Defense Evasion",
        "protocol": "",
        "os": "Linux, Windows, macOS",
        "tips": [
            "Look for execution of suspicious commands via --gpu-launcher or --no-sandbox flags.",
            "Detect JavaScript files embedded in Electron apps that call native binaries.",
            "Hunt for unusual child processes spawned from electron-based apps like Teams or Slack."
        ],
        "data_sources": "Command, Process",
        "log_sources": [
            {"type": "Command", "source": "Sysmon", "destination": ""},
            {"type": "Process", "source": "Sysmon", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Sysmon Logs", "location": "C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Sysmon%4Operational.evtx", "identify": "Event ID 1 (Process Creation) for teams.exe or chrome.exe with suspicious arguments"}
        ],
        "destination_artifacts": [],
        "detection_methods": [
            "Monitor for --gpu-launcher or --disable-gpu-sandbox flags in chrome.exe or teams.exe processes",
            "Alert on Electron-based apps spawning system shells like cmd.exe or bash",
            "Detect code injection into Electron’s main.js or preload.js files"
        ],
        "apt": [
            "FIN7", "Lazarus", "APT41"
        ],
        "spl_query": [
            "index=sysmon EventCode=1 Image=*\\chrome.exe OR *\\teams.exe\n| search CommandLine=\"*gpu-launcher*\" OR CommandLine=\"*cmd.exe*\"\n| stats count by CommandLine, ParentImage, User",
            "index=sysmon EventCode=1 Image=*\\node.exe OR *\\electron.exe\n| stats count by CommandLine, ParentImage"
        ],
        "hunt_steps": [
            "Identify all instances of teams.exe or chrome.exe launching with gpu-launcher",
            "Review Electron apps for modified preload.js or injected scripts",
            "Search for JavaScript files dropped in temp folders with native API calls"
        ],
        "expected_outcomes": [
            "Detection of malicious process execution via Electron-based apps",
            "Identification of embedded JavaScript payloads used for code execution",
            "Exposure of misuse of trusted binaries (electron, teams, chrome)"
        ],
        "false_positive": "Electron-based development environments or legitimate debugging may use gpu-launcher. Validate script origin and parent-child process relationships.",
        "clearing_steps": [
            "Terminate the offending Electron app process (e.g., taskkill /IM teams.exe /F)",
            "Delete or replace compromised JavaScript files in the app's installation directory",
            "Reinstall trusted version of affected application"
        ],
        "clearing_playbook": [
            "https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-malware"
        ],
        "mitre_mapping": [
            {"tactic": "Execution", "technique": "T1059.007", "example": "Execution of JavaScript payload in preload.js"},
            {"tactic": "Defense Evasion", "technique": "T1218", "example": "Using trusted binaries like chrome.exe for proxy execution"},
            {"tactic": "Persistence", "technique": "T1546.015", "example": "Modified JavaScript config file re-executed on app start"}
        ],
        "watchlist": [
            "teams.exe or chrome.exe using gpu-launcher or loading suspicious DLLs",
            "JavaScript files in Electron apps with suspicious process execution calls",
            "Electron applications spawning PowerShell, cmd.exe, bash, or curl"
        ],
        "enhancements": [
            "Use application allowlisting to restrict execution paths for Electron-based apps",
            "Monitor integrity of Electron application files",
            "Implement EDR rules for known abused Electron arguments"
        ],
        "summary": "Electron is a popular framework used in many enterprise apps. Adversaries can exploit it by injecting malicious JavaScript or abusing runtime flags to execute code as child processes of trusted applications like Teams or Chrome.",
        "remediation": "Restrict execution of electron apps to signed binaries. Monitor for argument abuse. Reinstall any Electron-based app if compromise is suspected.",
        "improvements": "Enhance telemetry for chrome.exe, teams.exe, and Electron-specific process trees. Correlate command-line and parent-child behaviors.",
        "mitre_version": "16.1"
    }
