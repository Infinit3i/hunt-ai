def get_content():
    return {
        "id": "T1059.012",
        "url_id": "T1059/012",
        "title": "Hypervisor CLI",
        "description": "Adversaries may abuse hypervisor command line interpreters (CLIs) to execute malicious commands.",
        "tags": ["hypervisor", "esxi", "vim-cmd", "esxcli", "cli", "command-line", "execution"],
        "tactic": "execution",
        "protocol": "",
        "os": "ESXi",
        "tips": [
            "Monitor shell.log and other hypervisor logs for suspicious esxcli or vim-cmd activity.",
            "Look for patterns involving VM enumeration, termination, or firewall changes.",
            "Review command history for admin accounts on ESXi."
        ],
        "data_sources": "Command",
        "log_sources": [
            {"type": "Command", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Event Logs", "location": "/var/log/shell.log", "identify": "CLI commands like esxcli and vim-cmd used in sequence to impact VM state"}
        ],
        "destination_artifacts": [
            {"type": "Process List", "location": "/proc", "identify": "Shell commands executed with hypervisor tools"}
        ],
        "detection_methods": [
            "Audit CLI command usage on hypervisors using logs like /var/log/shell.log.",
            "Correlate esxcli or vim-cmd commands with abnormal VM shutdown or reconfiguration."
        ],
        "apt": ["Cheerscrypt", "Royal"],
        "spl_query": [
            "index=esxi_logs sourcetype=shell_log\n| rex field=_raw \"(?i)(?(esxcli|vim-cmd)\\s+[\\w-/]+)\"\n| search command=\"esxcli\" OR command=\"vim-cmd\"\n| eval suspicious=if(like(command, \"%firewall%\") OR like(command, \"%loghost%\") OR like(command, \"%vmsvc%\"), 1, 0)\n| stats count by command, user, host, _time, suspicious\n| where suspicious=1"
        ],
        "hunt_steps": [
            "Extract all esxcli and vim-cmd executions from shell.log.",
            "Search for actions affecting firewall, logging, or VM state.",
            "Correlate timestamps with any system impact or lateral movement."
        ],
        "expected_outcomes": [
            "Identification of CLI-based abuse of hypervisor management commands."
        ],
        "false_positive": "Admins may use these commands legitimately; correlate usage with role and time.",
        "clearing_steps": [
            "Clear shell.log entries if malicious command history is confirmed.",
            "Reset firewall and logging configurations to defaults.",
            "Restore any shutdown VMs and revoke unauthorized access."
        ],
        "clearing_playbook": [
            "https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-malware"
        ],
        "mitre_mapping": [
            {"tactic": "execution", "technique": "T1059", "example": "Command and Scripting Interpreter"},
            {"tactic": "impact", "technique": "T1486", "example": "Data Encrypted for Impact"}
        ],
        "watchlist": [
            "Repeated use of esxcli or vim-cmd in short time spans",
            "Commands involving 'vmsvc/power' or 'firewall set' from unusual users"
        ],
        "enhancements": [
            "Forward hypervisor logs to central SIEM for better monitoring.",
            "Limit shell access to ESXi hosts and enforce role-based controls."
        ],
        "summary": "Hypervisor CLI access gives attackers control over virtual machines and host settings, allowing for stealthy post-exploitation and impact techniques.",
        "remediation": "Restrict access to hypervisor CLIs and monitor shell usage for suspicious patterns.",
        "improvements": "Improve visibility into hypervisor activity with log forwarding and user session tracking.",
        "mitre_version": "17.0"
    }
