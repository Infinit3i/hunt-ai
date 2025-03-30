def get_content():
    return {
        "id": "T1505.004",
        "url_id": "T1505/004",
        "title": "Server Software Component: IIS Components",
        "description": "Adversaries may abuse Internet Information Services (IIS) components such as ISAPI filters, ISAPI extensions, and IIS modules to gain persistent access and manipulate web server behavior. These components run as DLLs and integrate with IIS to inspect and manipulate HTTP requests and responses. Malicious components may allow execution of commands, observation of traffic, and stealthy command and control via HTTP/S. IIS modules introduced in IIS 7.0 can be native DLLs or .NET modules with access to full ASP.NET APIs, further enhancing their capabilities.",
        "tags": ["iis", "webserver", "persistence", "isapi", "modules", "T1505.004"],
        "tactic": "Persistence",
        "protocol": "HTTP/HTTPS",
        "os": "Windows",
        "tips": [
            "Monitor for creation or modification of DLLs in IIS directories.",
            "Audit the `applicationhost.config` for unauthorized IIS module additions.",
            "Log usage of `AppCmd.exe` with flags indicating module configuration.",
            "Verify loaded ISAPI filters/extensions using PowerShell or AppCmd."
        ],
        "data_sources": "Command, File",
        "log_sources": [
            {"type": "Command", "source": "Command Execution", "destination": ""},
            {"type": "File", "source": "File Creation", "destination": ""},
            {"type": "File", "source": "File Modification", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "DLL", "location": "%SystemRoot%\\System32\\inetsrv\\", "identify": "Unexpected or unsigned DLLs"},
            {"type": "Config File", "location": "%windir%\\System32\\inetsrv\\config\\applicationhost.config", "identify": "Added modules/filters not part of baseline"},
            {"type": "Process", "location": "", "identify": "Execution of AppCmd.exe with /add module"}
        ],
        "destination_artifacts": [
            {"type": "File", "location": "Web root or IIS module directories", "identify": "Dropped or copied DLLs"},
            {"type": "Registry", "location": "HKLM\\Software\\Microsoft\\InetStp\\Components", "identify": "Component registrations"},
            {"type": "Network", "location": "Inbound HTTP requests", "identify": "Trigger traffic to backdoored endpoints"}
        ],
        "detection_methods": [
            "Monitor DLL creation in IIS module paths.",
            "Detect unexpected modifications to `applicationhost.config`.",
            "Log and review `AppCmd.exe` usage.",
            "Correlate abnormal HTTP traffic with backdoored module endpoints."
        ],
        "apt": ["Lazarus Group", "TG-3390", "RGDoor", "IceApple"],
        "spl_query": [
            'index=wineventlog EventCode=4688\n| search CommandLine="*AppCmd.exe*" AND CommandLine="*add module*"\n| stats count by User, host, CommandLine',
            'index=os_logs sourcetype=ossec\n| search file_path="*inetsrv*/*.dll" AND action=created\n| stats count by file_path, user',
            'index=network sourcetype=iis\n| search uri="/hidden-backdoor-path/" OR uri_query="*cmd="'
        ],
        "hunt_steps": [
            "Check DLLs loaded by IIS for mismatched hashes or unexpected names.",
            "Analyze `applicationhost.config` for manually added modules.",
            "Review IIS logs for abnormal URL patterns.",
            "Query loaded modules using AppCmd or PowerShell."
        ],
        "expected_outcomes": [
            "Identification of unauthorized DLLs used for persistent access.",
            "Detection of malicious manipulation of HTTP responses.",
            "Elimination of stealthy C2 channels via IIS.",
            "Hardened configuration of IIS components."
        ],
        "false_positive": "Legitimate IIS extensions and monitoring tools may register modules. Verify publisher and origin before acting on DLLs.",
        "clearing_steps": [
            "Remove the malicious DLL from IIS directories.",
            "Revert unauthorized changes in `applicationhost.config`.",
            "Restart IIS services to unload suspicious modules.",
            "Audit system access logs to identify point of compromise."
        ],
        "mitre_mapping": [
            {"tactic": "Persistence", "technique": "T1505", "example": "IIS ISAPI filter used for backdoor persistence"},
            {"tactic": "Execution", "technique": "T1059.001", "example": "Commands executed via DLL invoked by HTTP request"},
            {"tactic": "Command and Control", "technique": "T1071.001", "example": "HTTP beaconing embedded in web traffic"}
        ],
        "watchlist": [
            "AppCmd.exe used to install modules or filters",
            "Unknown or unsigned DLLs in IIS module paths",
            "Outbound requests triggered via odd GET parameters",
            "Access to hidden IIS endpoints repeatedly from same IP"
        ],
        "enhancements": [
            "Implement code signing for all IIS modules.",
            "Restrict permissions to AppCmd and IIS config files.",
            "Use baseline comparison for module registrations.",
            "Enable command line auditing for IIS service context."
        ],
        "summary": "Malicious IIS components such as ISAPI filters/extensions and modules can offer stealthy persistence and traffic manipulation on compromised web servers. These DLLs are difficult to detect once installed and may serve as C2 proxies, command launchers, or data exfiltration tunnels.",
        "remediation": "Remove any unauthorized IIS modules, clean up associated artifacts, and re-secure access to the server and configuration tools. Ensure applicationhost.config is restored from a known-good backup and only approved DLLs remain loaded.",
        "improvements": "Use a central change auditing system to track DLL and config file changes in IIS. Periodically hash and validate loaded components. Apply principle of least privilege to reduce abuse of administrative tools like AppCmd.",
        "mitre_version": "16.1"
    }
