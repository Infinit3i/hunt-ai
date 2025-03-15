def get_content():
    return {
        "id": "T1547.014",
        "url_id": "1547/014",
        "title": "Boot or Logon Autostart Execution: Active Setup",
        "description": (
            "Adversaries may achieve persistence by adding a Registry key to the Active Setup of the local machine."
            " Active Setup is a Windows mechanism used to execute programs when a user logs in. The value stored in the"
            " Registry key will be executed after a user logs into the computer. These programs will run under the user's"
            " context and with the account's associated permission level."
        ),
        "tags": ["Persistence", "Privilege Escalation", "Windows"],
        "tactic": "Persistence, Privilege Escalation",
        "protocol": "Windows",
        "os": "Windows",
        "tips": [
            "Monitor Registry key additions and modifications to HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Active Setup\\Installed Components.",
            "Use Sysinternals Autoruns to detect system changes related to Active Setup.",
            "Investigate newly registered Active Setup keys that appear suspicious or out of place."
        ],
        "data_sources": "Command: Command Execution, Process: Process Creation, Windows Registry: Windows Registry Key Creation, Windows Registry: Windows Registry Key Modification",
        "log_sources": [
            {"type": "Windows Registry", "source": "Registry Key Modification", "destination": "SIEM"},
            {"type": "Process", "source": "Process Creation", "destination": "Security Monitoring"}
        ],
        "source_artifacts": [
            {"type": "Registry Key", "location": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Active Setup\\Installed Components\\*", "identify": "Active Setup Persistence Key"}
        ],
        "destination_artifacts": [
            {"type": "Log", "location": "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx", "identify": "Windows Security Event Log"}
        ],
        "detection_methods": [
            "Monitor for new Active Setup registry key modifications.",
            "Identify processes executing from unexpected registry-defined paths.",
            "Correlate suspicious registry modifications with process execution events."
        ],
        "apt": ["Tropic Trooper", "Poison Ivy"],
        "spl_query": [
            "index=windows_registry | search registry_path=\\HKLM\\SOFTWARE\\Microsoft\\Active Setup\\Installed Components",
            "index=process_creation | search process_name contains 'StubPath'"
        ],
        "hunt_steps": [
            "Identify Active Setup entries that have unusual or uncommon paths.",
            "Correlate registry changes with recent suspicious process executions."
        ],
        "expected_outcomes": [
            "Detection of unauthorized registry modifications under Active Setup.",
            "Identification of adversaries using Active Setup for persistence."
        ],
        "false_positive": "Legitimate software installations may create new Active Setup keys.",
        "clearing_steps": [
            "Remove unauthorized Active Setup registry entries.",
            "Disable suspicious Active Setup configurations through Group Policy."
        ],
        "mitre_mapping": [
            {"tactic": "Execution", "technique": "T1059", "example": "Execution via Active Setup StubPath"},
            {"tactic": "Privilege Escalation", "technique": "T1068", "example": "Elevating Privileges using Active Setup"}
        ],
        "watchlist": [
            "Monitor for unexpected process execution from Active Setup locations.",
            "Alert on unauthorized changes to the Active Setup registry keys."
        ],
        "enhancements": [
            "Implement Group Policy restrictions to prevent Active Setup abuse.",
            "Enable registry auditing to detect unauthorized modifications."
        ],
        "summary": "Adversaries can abuse Active Setup registry keys to achieve persistence and execute malicious code upon user logon.",
        "remediation": "Restrict unauthorized modifications to Active Setup registry keys using policy enforcement.",
        "improvements": "Regularly audit Active Setup configurations for unauthorized modifications."
    }
