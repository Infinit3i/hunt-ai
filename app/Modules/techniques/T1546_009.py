def get_content():
    return {
        "id": "T1546.009",
        "url_id": "T1546/009",
        "title": "Event Triggered Execution: AppCert DLLs",
        "description": "Adversaries may abuse AppCert DLLs to gain persistence or elevate privileges by injecting malicious DLLs into processes using common Windows API functions.",
        "tags": ["AppCertDLLs", "DLL injection", "persistence", "privilege escalation", "registry abuse"],
        "tactic": "Persistence, Privilege Escalation",
        "protocol": "",
        "os": "Windows",
        "tips": [
            "Monitor registry key modifications under HKLM\\System\\CurrentControlSet\\Control\\Session Manager\\AppCertDLLs.",
            "Use Autoruns alternatives or advanced EDR tools to identify stealth AppCertDLL-based persistence.",
            "Track unexpected DLL loads in high-integrity processes such as lsass.exe, winlogon.exe, or svchost.exe."
        ],
        "data_sources": "Command: Command Execution, Module: Module Load, Process: OS API Execution, Process: Process Creation, Windows Registry: Windows Registry Key Modification",
        "log_sources": [
            {"type": "Windows Registry", "source": "HKLM\\...\\AppCertDLLs", "destination": "Registry key for DLL load paths"},
            {"type": "Module", "source": "", "destination": "DLLs loaded into newly created processes"},
            {"type": "Command", "source": "CLI or script", "destination": "Reg.exe or PowerShell for AppCertDLL registry edits"},
            {"type": "Process", "source": "", "destination": "Injection targets via CreateProcess family of APIs"}
        ],
        "source_artifacts": [
            {"type": "Registry Key", "location": "HKLM\\System\\CurrentControlSet\\Control\\Session Manager\\AppCertDLLs", "identify": "Points to malicious DLL path"},
            {"type": "File", "location": "C:\\Windows\\System32\\malicious.dll", "identify": "DLL written to disk by attacker"}
        ],
        "destination_artifacts": [
            {"type": "Process", "location": "System processes (e.g., svchost.exe, winlogon.exe)", "identify": "Abnormal loaded DLLs"},
            {"type": "Network", "location": "Outbound C2 initiated by injected DLL", "identify": "Unexpected external communication"}
        ],
        "detection_methods": [
            "Registry monitoring for AppCertDLL modifications",
            "Process behavior analysis for unauthorized DLL loads",
            "Monitoring API calls: RegSetValueEx, RegCreateKeyEx affecting AppCertDLLs",
            "Correlation of new DLLs loaded into trusted Windows processes"
        ],
        "apt": ["FIN8"],
        "spl_query": [
            'index=main Registry.path="*AppCertDLLs*" \n| stats count by Registry.path, Registry.value, Image, User'
        ],
        "hunt_steps": [
            "Enumerate registry key AppCertDLLs for unauthorized DLLs",
            "Check file hash and signature of DLLs listed in AppCertDLLs",
            "Trace process trees where injected DLLs are loaded",
            "Correlate suspicious DLL loads with registry modification timeline"
        ],
        "expected_outcomes": [
            "Detection of persistence via DLL loaded into multiple processes",
            "Process injection behavior from AppCertDLLs abuse",
            "Elevated privilege execution of malicious DLL"
        ],
        "false_positive": "Very rare legitimate use. Most enterprise environments do not use AppCertDLLs. Any presence should be investigated thoroughly.",
        "clearing_steps": [
            "Delete malicious DLLs from disk",
            "Clean or remove AppCertDLL registry keys pointing to unauthorized DLLs",
            "Reboot the system to clear in-memory DLL injections",
            "Restore registry keys from known good backup or GPO baseline"
        ],
        "mitre_mapping": [
            {"tactic": "Privilege Escalation", "technique": "T1055", "example": "Injection via AppCert DLLs to run code in trusted process"},
            {"tactic": "Defense Evasion", "technique": "T1112", "example": "Registry modification to enable DLL persistence"}
        ],
        "watchlist": [
            "AppCertDLLs key creation or modification",
            "DLL loads into multiple unrelated processes",
            "Command execution involving reg.exe or PowerShell touching AppCertDLLs"
        ],
        "enhancements": [
            "Disable the AppCertDLLs feature via group policy or security templates",
            "Use whitelisting solutions to control DLL loads",
            "Implement registry auditing and change control"
        ],
        "summary": "AppCertDLLs allow adversaries to inject DLLs into every process that uses CreateProcess APIs, granting persistence or privilege escalation.",
        "remediation": "Remove rogue entries in AppCertDLLs, delete injected DLLs, and perform full host compromise analysis.",
        "improvements": "Enforce least privilege, monitor sensitive registry locations, and baseline DLL load behavior across critical systems.",
        "mitre_version": "16.1"
    }
