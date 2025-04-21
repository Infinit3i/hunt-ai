def get_content():
    return {
        "id": "T1574.005",
        "url_id": "T1574/005",
        "title": "Hijack Execution Flow: Executable Installer File Permissions Weakness",
        "description": "Adversaries may exploit weak file or directory permissions in installer workflows to replace legitimate binaries with malicious payloads. This hijack can occur if installers fail to set proper permissions for executable files (e.g., EXEs or DLLs) they temporarily extract to directories like `%TEMP%`, allowing attackers to insert or replace components.\n\nIf the installer runs with elevated privileges (e.g., SYSTEM), any malicious payload executed during installation can inherit those privileges, leading to privilege escalation. Attackers may exploit this behavior for persistence, especially if the binary is executed at boot, during updates, or service restarts.\n\nThis weakness often overlaps with [DLL Search Order Hijacking](https://attack.mitre.org/techniques/T1574/001) or [Bypass User Account Control](https://attack.mitre.org/techniques/T1548/002). Exploiting vulnerable self-extracting installers or software updates is common in this attack scenario. Multiple real-world examples have been reported and disclosed by researchers to vendors like Mozilla and others.",
        "tags": ["Installer Exploitation", "Temp Directory Abuse", "Binary Replacement", "Privilege Escalation", "File Permissions"],
        "tactic": "Defense Evasion, Persistence, Privilege Escalation",
        "protocol": "",
        "os": "Windows",
        "tips": [
            "Audit software installers for unpacking behavior in unprotected directories (e.g., `%TEMP%`).",
            "Use signed installers and enforce integrity validation at install-time.",
            "Block user-writeable permissions on sensitive directories or enforce AppLocker/SRP policies."
        ],
        "data_sources": "File: File Creation, File: File Modification, Module: Module Load, Process: Process Creation, Service: Service Metadata",
        "log_sources": [
            {"type": "File", "source": "%TEMP%, %ProgramData%", "destination": ""},
            {"type": "Process", "source": "EDR, Sysmon", "destination": ""},
            {"type": "Module", "source": "Sysmon Event ID 7", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Binary", "location": "%TEMP%\\<InstallerSubfolder>", "identify": "Overwritten or planted executable/dll by attacker"}
        ],
        "destination_artifacts": [
            {"type": "Process", "location": "Elevated installer runtime", "identify": "Executes attacker binary from writable location"}
        ],
        "detection_methods": [
            "Monitor for file writes in temporary directories during installer execution.",
            "Alert on new executables appearing in `%TEMP%` or `%APPDATA%` folders.",
            "Hash binaries loaded by installers and compare against known good values."
        ],
        "apt": [],
        "spl_query": [
            "index=windows_logs sourcetype=sysmon EventCode=11 OR EventCode=1\n| search TargetFilename=\"*\\\\Temp\\\\*\" OR CommandLine=\"*setup*\"\n| stats count by ComputerName, User, TargetFilename, CommandLine"
        ],
        "hunt_steps": [
            "Search Sysmon/Event Logs for executables created in user-writable directories during elevated installer runs.",
            "Correlate installer execution timestamps with module loads or process launches from unusual paths.",
            "Review update or setup binaries for missing code-signing and permission misconfigurations."
        ],
        "expected_outcomes": [
            "Discovery of installer-executed malicious payloads from insecure locations.",
            "Evidence of privilege escalation during installer hijack.",
            "Improved detection of software packaging weaknesses in enterprise deployments."
        ],
        "false_positive": "Software update or installation processes may naturally write to `%TEMP%`. Correlate with signing, hashes, and execution context.",
        "clearing_steps": [
            "Remove or quarantine the replaced installer files or binaries.",
            "Restrict access to `%TEMP%` and enforce execution control via AppLocker or SRP.",
            "Notify IT of installer vulnerabilities and replace with secure deployment options."
        ],
        "mitre_mapping": [
            {"tactic": "Privilege Escalation", "technique": "T1574.005", "example": "Installer drops vulnerable executable in `%TEMP%`, replaced with backdoor."}
        ],
        "watchlist": [
            "New or unsigned binaries written to `%TEMP%` during software installs",
            "Processes launched by `msiexec.exe`, `setup.exe`, or similar with unverified paths",
            "Installer actions modifying or launching executables with user-writeable ACLs"
        ],
        "enhancements": [
            "Implement software whitelisting via Windows Defender Application Control or AppLocker.",
            "Use tools like Process Monitor or Sysmon to track all writes to `%TEMP%` during install sessions.",
            "Educate dev teams to package secure, signed, non-writable installers."
        ],
        "summary": "Installers that extract or use executables from user-writable locations like `%TEMP%` can be hijacked if access controls are not properly set. This enables adversaries to inject payloads that execute under elevated contexts, often leading to persistence or privilege escalation.",
        "remediation": "Use secure packaging formats that verify integrity of all components. Avoid installer use of user-writable directories, and enforce strong filesystem ACLs.",
        "improvements": "Transition to MSI with integrated signing and enforced ACLs. Adopt secure software supply chain standards across update and deployment pipelines.",
        "mitre_version": "16.1"
    }
