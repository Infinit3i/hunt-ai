def get_content():
    return {
        "id": "T1053",
        "url_id": "T1053",
        "title": "Scheduled Task/Job",
        "tactic": "Execution, Persistence, Privilege Escalation",
        "description": "Adversaries may abuse task scheduling functionality to facilitate initial or recurring execution of malicious code. Scheduled tasks can be used to maintain persistence, execute malicious payloads, and/or run processes under the context of a specified account. Adversaries may use task scheduling to execute programs at system startup or on a scheduled basis for persistence, to conduct remote Execution as part of Lateral Movement, or to gain SYSTEM privileges.",
        "tags": ["Scheduled Task", "Task Scheduler", "Cron", "Crontab", "at", "systemd timers"],
        "tips": [
            "Monitor scheduled task creation and modification events.",
            "Analyze command-line execution for suspicious scheduled task commands."],
        "data_sources": "Windows Event Logs, Process Monitoring, Command Execution, File Monitoring",
        "protocol": "N/A",
        "os": "Windows, Linux, macOS",
        "log_sources": [
            {"type": "Windows Event Logs", "source": "Event ID 4698 (Task Created), Event ID 4702 (Task Updated), Event ID 4699 (Task Deleted)"},
            {"type": "Process Monitoring", "source": "Sysmon Event ID 1 (Process Creation)"},
            {"type": "Command Execution", "source": "Audit command-line activity related to schtasks.exe, crontab, at, systemd timers"},
            {"type": "File Monitoring", "source": "Monitor changes to scheduled task XML files and cron job files"}
        ],
        "detection_methods": [
            "Monitor for scheduled task creation or modification events.",
            "Analyze command-line execution for suspicious scheduled task commands.",
            "Identify persistence mechanisms through automated or hidden scheduled tasks.",
            "Detect execution of scripts or executables from unusual locations via scheduled tasks."
        ],
        "apt": [ "Earth Lusca", ],
        "spl_query": ["index=windows EventCode=4698 OR EventCode=4702 OR EventCode=4699 \n| stats count by TaskName, User, Command",
                      'index=security (sourcetype="WinEventLog:Security" OR sourcetype="linux_secure" OR sourcetype="macos_secure" OR sourcetype="container_logs")\n| eval CommandLine = coalesce(CommandLine, process)\n| where (sourcetype="WinEventLog:Security" AND EventCode IN (4697, 4702, 4698)) OR (sourcetype="linux_secure" AND CommandLine LIKE "%cron%" OR CommandLine LIKE "%at%") OR (sourcetype="macos_secure" AND CommandLine LIKE "%launchctl%" OR CommandLine LIKE "%cron%") OR (sourcetype="container_logs" AND (CommandLine LIKE "%cron%" OR CommandLine LIKE "%at%"))\n| where (sourcetype="WinEventLog:Security" AND (CommandLine LIKE "%/create%" OR CommandLine LIKE "%/delete%" OR CommandLine LIKE "%/change%")) OR (sourcetype="linux_secure" AND (CommandLine LIKE "%-f%" OR CommandLine LIKE "%-m%" OR CommandLine LIKE "%--env%")) OR (sourcetype="macos_secure" AND (CommandLine LIKE "%/Library/LaunchDaemons%" OR CommandLine LIKE "%/Library/LaunchAgents%" OR CommandLine LIKE "%/System/Library/LaunchDaemons%" OR CommandLine LIKE "%/System/Library/LaunchAgents%")) OR (sourcetype="container_logs" AND (CommandLine LIKE "%-f%" OR CommandLine LIKE "%--schedule%" OR CommandLine LIKE "%--env%"))',
                      'index=container_logs sourcetype="docker_events" OR sourcetype="kubernetes_events"\n| eval event_action=coalesce(action, status)\n| where (event_action="create" OR event_action="start")\n| search event_type="container"\n| search (parameters="--privileged" OR parameters="--cap-add=" OR parameters="--volume=" OR parameters="--network=host" OR parameters="--device")',
                      'index=security_logs OR index=system_logs(sourcetype="docker_events" OR sourcetype="kubernetes_events" OR sourcetype="wineventlog:security" OR sourcetype="linux_secure" OR sourcetype="syslog" OR sourcetype="file_monitoring")\n| eval platform=case( sourcetype=="docker_events" OR sourcetype=="kubernetes_events", "Containers", sourcetype=="wineventlog:security", "Windows", sourcetype=="linux_secure" OR sourcetype=="syslog", "Linux", sourcetype=="mac_os_events", "macOS")\n| search ( (platform="Containers" AND (event_type="file_create" AND (file_path="/etc/cron.d/" OR file_path="/etc/systemd/system/"))) OR (platform="Windows" AND EventCode=4663 AND (ObjectName="C:\Windows\System32\Tasks\" OR ObjectName="C:\Windows\Tasks\")) OR (platform="Linux" AND (file_path="/etc/cron.d/" OR file_path="/etc/systemd/system/")) OR (platform="macOS" AND (file_path="/Library/LaunchDaemons/" OR file_path="/Library/LaunchAgents/")))',
                      'index=security_logs OR index=system_logs(sourcetype="docker_events" OR sourcetype="kubernetes_events" OR sourcetype="wineventlog:security" OR sourcetype="linux_secure" OR sourcetype="syslog" OR sourcetype="file_monitoring")\n| eval platform=case( sourcetype=="docker_events" OR sourcetype=="kubernetes_events", "Containers", sourcetype=="wineventlog:security", "Windows", sourcetype=="linux_secure" OR sourcetype=="syslog", "Linux", sourcetype=="mac_os_events", "macOS")\n| search ( (platform="Containers" AND (event_type="file_modify" AND (file_path="/etc/cron.d/" OR file_path="/etc/systemd/system/" OR file_path="/etc/crontab"))) OR (platform="Windows" AND EventCode=4663 AND (ObjectName="C:\Windows\System32\Tasks\" OR ObjectName="C:\Windows\Tasks\")) OR (platform="Linux" AND (file_path="/etc/cron.d/" OR file_path="/etc/systemd/system/" OR file_path="/etc/crontab")) OR (platform="macOS" AND (file_path="/Library/LaunchDaemons/" OR file_path="/Library/LaunchAgents/")))',
                      '(sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" OR sourcetype="WinEventLog:Security" OR sourcetype="linux_auditd" OR sourcetype="syslog") \n| where Image IN ("schtasks.exe", "at.exe", "Taskeng.exe", "cron", "crontab", "systemd-timers")',
                      '(index=windows_logs OR index=sysmon) ((source="WinEventLog:Security" EventCode IN (4698, 4702, 4699)) OR (source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 AND (CommandLine="*schtasks*" OR CommandLine="*at*" OR Image="*taskeng.exe*"))) \n| table _time, host, user, EventCode, Image, CommandLine, TaskName, TaskContent \n| sort -_time'
                      ],
        "sigma_rule": "https://grep.app/search?f.repo=SigmaHQ%2Fsigma&q=T1053",
        "hunt_steps": [
            "Run Queries in SIEM to detect newly created or modified scheduled tasks.",
            "Investigate task names, execution commands, and associated user accounts.",
            "Check if scheduled tasks execute scripts or binaries from unauthorized locations.",
            "Validate scheduled tasks against normal administrative activity.",
            "Escalate suspicious findings to incident response for further analysis."
        ],
        "expected_outcomes": [
            "Detection of unauthorized scheduled task creation or modification.",
            "Identification of adversaries using scheduled tasks for persistence.",
            "Prevention of unauthorized code execution via scheduled tasks."
        ],
        "clearing_steps": [],  # Steps for remediation and clearing traces - do commands also on machines locally
        "mitre_mapping": [
            {"tactic": "Execution", "technique": "T1059 (Command & Scripting Interpreter)", "example": "Adversaries may abuse command-line interfaces and scripting environments to execute malicious code."},
            {"tactic": "Initial Access", "technique": "T1566 (Phishing)", "example": "Attackers may send malicious emails with links or attachments to gain initial access to a target system."},
            {"tactic": "Defense Evasion", "technique": "T1036 (Masquerading)", "example": "Threat actors may rename or modify malicious files to appear as legitimate software to evade detection."}
        ],
        "watchlist": [
            "Monitor scheduled task creation by unauthorized users.",
            "Detect scheduled tasks executing from suspicious directories.",
            "Analyze task execution frequency for hidden persistence mechanisms."
        ],
        "clearing_steps": [
            "🔍 Identify Malicious Scheduled Tasks: List all scheduled tasks and compare against known authorized tasks.",
            
            "🪟 Windows: Remove Malicious Scheduled Tasks",
            "schtasks /query /fo LIST /v > C:\\Windows\\Temp\\scheduled_tasks.txt",
            "schtasks /delete /tn <task_name> /f",  
            "wevtutil cl Microsoft-Windows-TaskScheduler/Operational",  
            "wevtutil cl Security",

            "🐧 Linux: Remove Malicious Cron Jobs & Systemd Timers**",
            "crontab -l > /tmp/cron_backup.txt",
            "crontab -r",  
            "rm -f /etc/cron.d/<malicious_task>",  
            "systemctl disable <malicious_timer>.timer",  
            "rm -f /etc/systemd/system/<malicious_timer>.timer",  

            "🍏 macOS: Remove Malicious LaunchDaemons/LaunchAgents",
            "launchctl list | grep <malicious_task>",
            "launchctl remove <malicious_task>",
            "rm -f /Library/LaunchAgents/<malicious_task>.plist",
            "rm -f /Library/LaunchDaemons/<malicious_task>.plist",

            "📜 Log Cleanup & Traces Removal",
            "Clear logs to remove traces of the malicious task:",
            "rm -f /var/log/cron",
            "truncate -s 0 /var/log/syslog",
            "log stream --predicate 'eventMessage contains \"task\"' --debug",

            "🔒 Post-Clearing Security Measures",
            "✅ Implement restrictive permissions on scheduled tasks.",
            "✅ Enable logging and SIEM alerts for unauthorized task modifications.",
            "✅ Conduct forensic analysis to ensure no backdoors remain.",
            "✅ Audit all scheduled tasks periodically."
        ],
        "enhancements": [
            "Restrict task creation to authorized administrators only.",
            "Implement logging for all scheduled task executions.",
            "Regularly audit scheduled task configurations for anomalies."
        ],
        "summary": "Monitor scheduled task creation and modification to detect adversarial persistence.",
        "remediation": "Investigate unauthorized scheduled tasks, disable malicious tasks, and improve access controls.",
        "improvements": "Enhance monitoring of task creation events and implement stricter execution policies."
    }
