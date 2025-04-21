def get_content():
    return {
        "id": "T1574.011",
        "url_id": "T1574/011",
        "title": "Hijack Execution Flow: Services Registry Permissions Weakness",
        "description": "Adversaries may hijack execution by exploiting weak permissions on service-related registry keys. Windows stores configuration data for services in the registry under `HKLM\\SYSTEM\\CurrentControlSet\\Services`. If these keys are improperly permissioned, adversaries can modify values like `ImagePath`, `FailureCommand`, `ServiceDll`, or inject malicious DLLs via the `Performance` key.\n\nOnce a service is restarted or fails and restarts, the modified path or injected DLL may be loaded, executing adversary-controlled code. This provides opportunities for persistence and privilege escalation under SYSTEM or other service accounts.\n\nOther subkeys like `Parameters` may also be added by attackers to configure custom service settings. Use of `svchost.exe` and service hijacking through DLL redirection is also possible. Adversaries may use native tools like `reg.exe`, `PowerShell`, or Windows Management Instrumentation (WMI) to apply these changes.",
        "tags": ["Registry Persistence", "Service Hijack", "Weak ACLs", "Privilege Escalation", "svchost", "ServiceDLL"],
        "tactic": "Defense Evasion, Persistence, Privilege Escalation",
        "protocol": "",
        "os": "Windows",
        "tips": [
            "Identify services that run under SYSTEM or high-privilege accounts and audit their registry ACLs.",
            "Monitor for creation or modification of `FailureCommand`, `Performance`, or `ServiceDll` registry keys.",
            "Correlate registry modifications with service restarts or crashes."
        ],
        "data_sources": "Command: Command Execution, Process: Process Creation, Service: Service Modification, Windows Registry: Windows Registry Key Modification",
        "log_sources": [
            {"type": "Registry", "source": "HKLM\\SYSTEM\\CurrentControlSet\\Services", "destination": ""},
            {"type": "Service", "source": "SCM logs", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Registry", "location": "HKLM\\SYSTEM\\CurrentControlSet\\Services\\<ServiceName>", "identify": "ImagePath, FailureCommand, Performance, ServiceDll"}
        ],
        "destination_artifacts": [
            {"type": "Executable", "location": "Attacker-controlled path or DLL", "identify": "Modified binary launched by service"},
            {"type": "DLL", "location": "Injected via Performance key or ServiceDll", "identify": "Custom profiler or persistence DLL"}
        ],
        "detection_methods": [
            "Monitor for modifications to service-related registry keys using Sysmon Event ID 13 or Windows Event ID 4657.",
            "Use Sysinternals Autoruns to detect non-standard service image paths or performance DLLs.",
            "Alert on service creation or modification where the ImagePath references user directories, temp folders, or non-standard executables."
        ],
        "apt": ["Honeybee"],
        "spl_query": [
            "index=sysmon EventCode=13 TargetObject=\"HKLM\\\\SYSTEM\\\\CurrentControlSet\\\\Services*\"\n| stats count by TargetObject, Image, User"
        ],
        "hunt_steps": [
            "Enumerate services and audit their registry permissions (e.g., via `accesschk`)",
            "Check for registry values under services that deviate from vendor defaults",
            "Investigate unexpected DLLs referenced in ServiceDll or Performance keys"
        ],
        "expected_outcomes": [
            "Discovery of registry abuse granting persistence via services",
            "Detection of untrusted or unknown binaries running as Windows services",
            "Isolation of processes tied to suspicious service paths or DLLs"
        ],
        "false_positive": "Legitimate software may modify services during updates. Verify publisher and service context (e.g., SYSTEM vs. User) before triage.",
        "clearing_steps": [
            "Reset affected registry keys to vendor defaults",
            "Audit service binary paths and permissions",
            "Delete any malicious binaries or injected DLLs referenced in those keys"
        ],
        "mitre_mapping": [
            {"tactic": "Persistence", "technique": "T1574.011", "example": "Modifying ImagePath in a service registry key to point to malicious executable"},
            {"tactic": "Privilege Escalation", "technique": "T1574.011", "example": "Setting FailureCommand to spawn elevated shell"}
        ],
        "watchlist": [
            "Services with write permissions granted to Authenticated Users or Everyone",
            "Performance key creations or ServiceDll pointing to non-Windows paths",
            "Services using binaries in temp or user-controlled locations"
        ],
        "enhancements": [
            "Harden registry ACLs using security baselines",
            "Restrict usage of reg.exe and PowerShell for unauthorized users",
            "Integrate registry integrity checks in EDR or configuration management platforms"
        ],
        "summary": "This technique exploits misconfigured registry permissions to hijack service execution, enabling adversaries to gain elevated code execution or persistence on Windows systems.",
        "remediation": "Apply Group Policy or security templates to enforce restrictive registry ACLs. Regularly audit service configurations using tools like Autoruns or `accesschk`.",
        "improvements": "Implement file integrity monitoring on sensitive registry paths. Track abnormal registry access patterns from low-privileged accounts.",
        "mitre_version": "16.1"
    }
