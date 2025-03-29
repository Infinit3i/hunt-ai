def get_content():
    return {
        "id": "T1218.007",
        "url_id": "T1218/007",
        "title": "System Binary Proxy Execution: Msiexec",
        "tactic": "Defense Evasion",
        "protocol": "MSI, HTTP, HTTPS, SMB",
        "os": "Windows",
        "tips": [
            "Monitor `msiexec.exe` for unusual or unexpected invocations, especially with remote URLs.",
            "Correlate with parent processes like `powershell.exe`, `cmd.exe`, or suspicious scripting tools.",
            "Check for abuse of AlwaysInstallElevated policy to escalate privileges during MSI execution."
        ],
        "data_sources": "Command Execution, Module Load, Network Connection Creation, Process Creation",
        "log_sources": [
            {"type": "Process Creation", "source": "Sysmon (Event ID 1)", "destination": "SIEM"},
            {"type": "Command Execution", "source": "Windows Security Logs (Event ID 4688)", "destination": "SIEM"},
            {"type": "Network Traffic", "source": "Firewall, Proxy, EDR", "destination": "SIEM"},
            {"type": "Module Load", "source": "Sysmon (Event ID 7)", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "MSI or DLL file", "location": "Remote share or web server", "identify": "Installer package used for payload delivery"}
        ],
        "destination_artifacts": [
            {"type": "Child process", "location": "Memory", "identify": "Executed binary or loader spawned via msiexec.exe"}
        ],
        "detection_methods": [
            "Monitor msiexec.exe command-line parameters for remote sources or suspicious installation paths.",
            "Analyze lateral movement attempts tied to msiexec usage with elevated privileges.",
            "Track AlwaysInstallElevated policy status across endpoints to prevent privilege escalation."
        ],
        "apt": ["G0035", "G0092", "G0060", "G0131", "G1006"],
        "spl_query": [
            "index=windows EventCode=4688 New_Process_Name=*msiexec.exe*",
            "index=sysmon EventCode=1 Image=*\\msiexec.exe CommandLine=*http* OR CommandLine=*\\\\*",
            "index=network dest_port=445 OR dest_url=*msi | stats count by src_ip, dest_ip, dest_url"
        ],
        "hunt_steps": [
            "Search for msiexec.exe executions with remote paths in command line.",
            "Correlate process tree to identify suspicious parent or child relationships.",
            "Audit group policy for the AlwaysInstallElevated setting.",
            "Review MSI files executed for embedded payloads or malicious logic.",
            "Flag unauthorized use of msiexec.exe from non-admin or unknown user accounts."
        ],
        "expected_outcomes": [
            "Detection of malicious MSI-based payload execution via msiexec.exe.",
            "Blocking of lateral movement or privilege escalation attempts through Windows Installer abuse.",
            "Improved understanding of software installation behaviors in the environment."
        ],
        "false_positive": "Msiexec may be legitimately used by IT teams or software deployments. Verify source, signature, and context before raising alerts.",
        "clearing_steps": [
            "Terminate the msiexec.exe process if tied to unauthorized or malicious activity.",
            "Delete related installer files or DLLs used during execution.",
            "Disable AlwaysInstallElevated via Group Policy.",
            "Reimage or restore the compromised system if unauthorized escalation occurred."
        ],
        "mitre_mapping": [
            {
                "tactic": "Defense Evasion",
                "technique": "T1218.007 (System Binary Proxy Execution: Msiexec)",
                "example": "Using msiexec.exe to install malicious packages from remote servers."
            }
        ],
        "watchlist": [
            "Trigger alerts when msiexec.exe executes with URLs in the command line.",
            "Detect DLL loading via msiexec.exe in non-standard scenarios.",
            "Monitor installations from user directories or temp paths via msiexec."
        ],
        "enhancements": [
            "Apply AppLocker or WDAC policies to restrict msiexec.exe usage.",
            "Disable AlwaysInstallElevated in Group Policy.",
            "Enable command-line logging for detailed visibility of msiexec usage."
        ],
        "summary": "Msiexec.exe is a signed Windows utility that can be abused to execute malicious MSI or DLL files, potentially bypassing security controls and gaining SYSTEM privileges if misconfigured.",
        "remediation": "Restrict msiexec.exe usage through application control, enforce least privilege, and audit installer sources. Disable risky configurations like AlwaysInstallElevated.",
        "improvements": "Increase visibility into msiexec usage across the network, and incorporate MSI abuse signatures into EDR and SIEM solutions.",
        "mitre_version": "16.1"
    }
