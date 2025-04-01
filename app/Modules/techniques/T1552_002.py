def get_content():
    return {
        "id": "T1552.002",
        "url_id": "T1552/002",
        "title": "Unsecured Credentials: Credentials in Registry",
        "description": "Adversaries may search the Registry on compromised systems for insecurely stored credentials.",
        "tags": ["credentials", "registry", "infostealer", "passwords", "persistence"],
        "tactic": "Credential Access",
        "protocol": "",
        "os": "Windows",
        "tips": [
            "Restrict access to sensitive registry keys using proper ACLs.",
            "Use Sysmon and Windows Security auditing to monitor registry access.",
            "Avoid storing credentials in the registry whenever possible."
        ],
        "data_sources": "Command, Process, Windows Registry",
        "log_sources": [
            {"type": "Command", "source": "", "destination": ""},
            {"type": "Process", "source": "", "destination": ""},
            {"type": "Windows Registry", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Registry Hives (NTUSER.DAT, SYSTEM, SOFTWARE)", "location": "HKLM and HKCU", "identify": "Registry keys with stored credentials or password strings"},
            {"type": "Sysmon Logs", "location": "Event ID 13 (Registry value set), 1 (Process Create)", "identify": "Access or modification of credential-related registry keys"}
        ],
        "destination_artifacts": [
            {"type": "Registry Hives (NTUSER.DAT, SYSTEM, SOFTWARE)", "location": "Remote registry or cloned hives", "identify": "Exported registry keys containing credentials"}
        ],
        "detection_methods": [
            "Monitor for use of `reg query` or registry-related tools",
            "Detect common password-related queries or strings in registry access",
            "Correlation of registry access with credential dumping tools"
        ],
        "apt": [
            "OceanLotus", "IceApple", "Trickbot", "Cobalt Kitty", "RedCurl", "Valak", "Agent Tesla"
        ],
        "spl_query": [
            'index=main process_name=reg.exe command_line="*HKLM*password*" OR command_line="*HKCU*password*"\n| stats count by host, user, command_line',
            'index=main EventCode=13 registry_path="*\\password*"\n| stats count by registry_path, Image, user'
        ],
        "hunt_steps": [
            "Search for command-line use of `reg query` targeting `HKLM` or `HKCU` with password strings.",
            "Hunt for registry key access related to auto-logon or software with stored credentials.",
            "Review exported `.reg` files or signs of hive dumping."
        ],
        "expected_outcomes": [
            "Identification of adversary reading password-related registry keys",
            "Detection of tools or commands interacting with sensitive credential data"
        ],
        "false_positive": "Legitimate tools may query registry keys for configuration. Validate context and correlate with user intent.",
        "clearing_steps": [
            "Delete or encrypt insecurely stored credentials in the registry",
            "Audit and rotate any exposed credentials",
            "Enable registry auditing to track future access attempts"
        ],
        "clearing_playbook": [
            "https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-credential-theft"
        ],
        "mitre_mapping": [
            {"tactic": "Discovery", "technique": "T1012", "example": "Querying registry for system or user data"},
            {"tactic": "Persistence", "technique": "T1547.001", "example": "Storing credentials in registry for reuse at startup"}
        ],
        "watchlist": [
            "reg.exe", "reg query", "HKLM\\*password*", "HKCU\\*password*"
        ],
        "enhancements": [
            "Deploy Sysmon with registry event logging enabled (Event ID 13)",
            "Use YARA or regex rules to scan for plaintext passwords in registry"
        ],
        "summary": "Adversaries may query the Windows Registry to locate credentials stored insecurely by software or auto-logon mechanisms.",
        "remediation": "Ensure sensitive data is not stored in plaintext in registry. Use secure storage APIs or vaults.",
        "improvements": "Enhance EDR rules to detect common credential lookup patterns in registry queries.",
        "mitre_version": "16.1"
    }
