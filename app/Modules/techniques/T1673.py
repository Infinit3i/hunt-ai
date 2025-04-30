def get_content():
    return {
        "id": "T1673",
        "url_id": "T1673",
        "title": "Virtual Machine Discovery",
        "description": "Adversaries may attempt to enumerate running virtual machines (VMs) after gaining access to a host or hypervisor.",
        "tags": ["vm", "esxi", "discovery", "hypervisor", "enumeration"],
        "tactic": "discovery",
        "protocol": "",
        "os": "ESXi, Linux, Windows, macOS",
        "tips": [
            "Review shell logs for hypervisor CLI usage.",
            "Look for unusual VM list commands outside expected admin workflows.",
            "Use least privilege principles to restrict VM enumeration commands."
        ],
        "data_sources": "Command",
        "log_sources": [
            {"type": "Command", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Command History", "location": "/var/log/shell.log", "identify": "esxcli or vim-cmd with VM listing operations"},
            {"type": "Command History", "location": "Auditd/sysmon logs", "identify": "virsh, VBoxManage, Get-VM used for discovery"}
        ],
        "destination_artifacts": [],
        "detection_methods": [
            "Monitor ESXi shell_log for VM enumeration commands.",
            "Review auditd/sysmon logs for known hypervisor management tools.",
            "Alert when non-admin users enumerate VMs."
        ],
        "apt": ["Cheerscrypt"],
        "spl_query": [
            "index=esxi_logs sourcetype=shell_log(command=\"esxcli vm process list\" OR command=\"vim-cmd vmsvc/getallvms\")\n| stats count by host, user, command, _time\n| where user != \"expected_admin_user\" OR like(command, \"%unexpected_path%\")\n| sort -_time",
            "sourcetype=auditd OR sourcetype=sysmon(process_name IN (\"virsh\", \"VBoxManage\", \"qemu-img\") AND command=\"list\" OR command=\"info\")\n| stats count by host, user, command, parent_process_name, _time\n| where user!=\"root\" AND NOT match(command, \"known_admin_script\")\n| sort -_time",
            "sourcetype=WinEventLog:Sysmon EventCode=1(Image=\"powershell.exe\" OR Image=\"vmrun.exe\" OR Image=\"VBoxManage.exe\") (CommandLine=\"Get-VM\" OR CommandLine=\"list vms*\")\n| stats count by host, user, Image, CommandLine, ParentImage, _time\n| where user!=\"expected_admin\" AND NOT match(CommandLine, \"routine_script.ps1\")\n| sort -_time"
        ],
        "hunt_steps": [
            "Search for known VM listing commands in logs.",
            "Correlate command usage with user role and session context.",
            "Look for temporal proximity to destructive commands like VM termination."
        ],
        "expected_outcomes": [
            "Detection of adversaries attempting to enumerate VMs for targeting."
        ],
        "false_positive": "System administrators performing legitimate management tasks.",
        "clearing_steps": [
            "Revoke access to suspicious user accounts.",
            "Audit and rotate admin credentials.",
            "Review audit logs for lateral movement or privilege escalation."
        ],
        "clearing_playbook": [
            "https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-malware"
        ],
        "mitre_mapping": [
            {"tactic": "discovery", "technique": "T1569.003", "example": "Systemctl abuse after VM discovery"},
            {"tactic": "impact", "technique": "T1486", "example": "Data Encrypted for Impact after identifying VM targets"}
        ],
        "watchlist": [
            "Unauthorized enumeration of VMs via esxcli or VBoxManage",
            "PowerShell Get-VM command used by non-admins"
        ],
        "enhancements": [
            "Flag VM enumeration commands executed outside business hours.",
            "Correlate discovery activity with ransomware tooling behavior."
        ],
        "summary": "Virtual Machine Discovery enables attackers to identify VM targets for subsequent destructive or evasive operations such as shutdown, encryption, or data collection.",
        "remediation": "Restrict access to VM management interfaces and tools. Monitor VM enumeration commands and correlate with suspicious access patterns.",
        "improvements": "Enable logging for all hypervisor and VM management tools. Establish user behavior baselines to identify anomalies in virtual infrastructure access.",
        "mitre_version": "17.0"
    }
