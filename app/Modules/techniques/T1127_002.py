def get_content():
    return {
        "id": "T1127.002",
        "url_id": "T1127/002",
        "title": "Trusted Developer Utilities Proxy Execution: ClickOnce",
        "description": "Adversaries may use ClickOnce applications to proxy execution of code through a trusted Windows utility without requiring administrative privileges.",
        "tags": ["defense evasion", "clickonce", "proxy execution", "LOLBAS", "signed binary abuse"],
        "tactic": "defense-evasion",
        "protocol": "HTTP/HTTPS",
        "os": "Windows",
        "tips": [
            "Alert on execution of `dfsvc.exe` or `rundll32.exe dfshim.dll,ShOpenVerbApplication1` in non-dev environments",
            "Detect `.application` or `.appref-ms` file execution outside of ClickOnce-approved deployment servers",
            "Correlate `dfsvc.exe` with the launching of unknown or unsigned binaries"
        ],
        "data_sources": "Command, Process, Module",
        "log_sources": [
            {"type": "Command", "source": "EDR", "destination": ""},
            {"type": "Process", "source": "Sysmon", "destination": ""},
            {"type": "Module", "source": "Sysmon", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Event Logs", "location": "Sysmon Event ID 1, 7, 11", "identify": "Execution or DLL load involving dfsvc.exe or dfshim.dll"},
            {"type": "Prefetch Files", "location": "C:\\Windows\\Prefetch", "identify": "ClickOnce apps executed recently"},
            {"type": "Recent Files", "location": "User Download Folder", "identify": ".appref-ms or .application file downloads"}
        ],
        "destination_artifacts": [
            {"type": "Registry Hives (NTUSER.DAT)", "location": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "identify": "ClickOnce path persistence"},
            {"type": "Startup Folder Contents", "location": "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup", "identify": "ClickOnce dropped shortcut"},
            {"type": "Process List", "location": "Live memory or EDR", "identify": "DFSVC.EXE or RUNDLL32.EXE executing malware"}
        ],
        "detection_methods": [
            "Monitor for ClickOnce executions launching unsigned or non-approved binaries",
            "Alert on rundll32 usage involving dfshim.dll",
            "Track `.application` and `.appref-ms` files created or accessed from untrusted sources"
        ],
        "apt": [
            "FIN7", "Static Kitten"
        ],
        "spl_query": [
            'index=process EventCode=1 \n| search Image="*dfsvc.exe" \n| stats count by ParentImage, CommandLine, User',
            'index=process EventCode=1 \n| search CommandLine="*dfshim.dll,ShOpenVerbApplication1*" \n| stats count by CommandLine, ParentImage, User',
            'index=file EventCode=11 \n| search TargetFilename="*.appref-ms" OR TargetFilename="*.application" \n| stats count by TargetFilename, ProcessId'
        ],
        "hunt_steps": [
            "Search for ClickOnce apps in user temp and download directories",
            "Look for DFSVC.EXE or RUNDLL32.EXE spawning suspicious child processes",
            "Hunt persistence in startup folders involving .appref-ms or .application files"
        ],
        "expected_outcomes": [
            "Detection of signed developer tool used for code proxying",
            "Indicators of malware delivery via ClickOnce popups",
            "Discovery of persistence via startup folder injection"
        ],
        "false_positive": "ClickOnce is used in legitimate app deployment pipelines—validate signer, publisher, and command usage context.",
        "clearing_steps": [
            "Remove malicious ClickOnce deployment files from user folders",
            "Delete entries from startup folder and registry keys under HKCU/Run",
            "Block ClickOnce protocol or deployment via AppLocker or WDAC"
        ],
        "mitre_mapping": [
            {"tactic": "defense-evasion", "technique": "T1218.011", "example": "Rundll32 abusing dfshim.dll"},
            {"tactic": "persistence", "technique": "T1547.001", "example": "Startup folder ClickOnce payload"},
            {"tactic": "execution", "technique": "T1204", "example": "User execution of web-hosted ClickOnce application"}
        ],
        "watchlist": [
            "User execution of ClickOnce deployments from unknown or external sources",
            "`rundll32.exe dfshim.dll,ShOpenVerbApplication1` in process lineage",
            "DFSVC.EXE running non-Microsoft signed payloads"
        ],
        "enhancements": [
            "Create allowlist of approved ClickOnce sources",
            "Enable command-line argument and DLL load monitoring on dfsvc.exe",
            "Detect new .application files written to disk in real time"
        ],
        "summary": "ClickOnce allows attackers to proxy execution using trusted Microsoft tools like `dfsvc.exe`, facilitating defense evasion without needing elevated privileges.",
        "remediation": "Restrict usage of ClickOnce applications via GPO or AppLocker, monitor for abnormal usage of `dfshim.dll` and `dfsvc.exe`, and remove persistence mechanisms from startup.",
        "improvements": "Track file origin, correlate download behavior with process activity, and apply behavioral baselines to ClickOnce usage.",
        "mitre_version": "16.1"
    }
