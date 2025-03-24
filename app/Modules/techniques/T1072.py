def get_content():
    return {
        "id": "T1072",
        "url_id": "T1072",
        "title": "Software Deployment Tools",
        "description": "Adversaries may gain access to and use centralized software suites installed within an enterprise to execute commands and move laterally through the network. Configuration management and software deployment applications may be used in an enterprise network or cloud environment for routine administration purposes.",
        "tags": ["execution", "lateral movement", "deployment tools", "cloud", "CI/CD", "SCCM", "SSM", "intune"],
        "tactic": "execution, lateral-movement",
        "protocol": "HTTP, HTTPS, SMB",
        "os": "Windows, Linux, macOS, Network, SaaS",
        "tips": [
            "Monitor deployment systems for abnormal usage patterns or login activity",
            "Review software distribution logs for anomalous scripts or binaries",
            "Isolate admin functions from regular user accounts with role-based access"
        ],
        "data_sources": "Application Log, Process",
        "log_sources": [
            {"type": "Application Log", "source": "", "destination": ""},
            {"type": "Process", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Application Log", "location": "SCCM server logs", "identify": "Script execution history"},
            {"type": "Process", "location": "Deployment server", "identify": "Unexpected processes executed via deployment system"},
            {"type": "Application Log", "location": "Intune/Azure Arc activity logs", "identify": "Command or script delivery records"}
        ],
        "destination_artifacts": [
            {"type": "Process", "location": "Endpoints targeted by deployment", "identify": "Processes spawned via deployment tools"},
            {"type": "Application Log", "location": "/var/log/ssm-agent.log", "identify": "AWS SSM execution records"}
        ],
        "detection_methods": [
            "Analyze process execution trees for anomalous initiators (e.g., SCCM, Intune, SSM)",
            "Correlate logs from deployment tools with EDR or system process telemetry",
            "Alert on unscheduled or irregular deployment patterns",
            "Audit login and privilege usage on configuration management tools"
        ],
        "apt": ["APT32", "Silence", "Avos", "TG-1314", "Prestige"],
        "spl_query": [
            "index=sccm_logs ScriptName=* \n| stats count by ScriptName, AccountName, ComputerName",
            "index=intune_logs Operation=\"ExecuteCommand\" \n| stats count by User, TargetDevice, Command",
            "index=process_logs ParentImage=\"*ccmexec.exe\" OR ParentImage=\"*SSMAgent.exe\" \n| stats count by Image, ParentImage, host"
        ],
        "hunt_steps": [
            "Identify command execution patterns tied to software deployment tools",
            "Review logs for previously unused deployment agents now issuing commands",
            "Correlate remote command execution with login anomalies on deployment systems"
        ],
        "expected_outcomes": [
            "Unauthorized or unexpected software/scripts deployed across systems",
            "Command execution as SYSTEM or root across multiple endpoints",
            "Evidence of lateral movement via legitimate tools"
        ],
        "false_positive": "IT staff may legitimately use deployment tools for routine tasks. Confirm activity is documented and aligns with change management tickets.",
        "clearing_steps": [
            "Review deployment tool audit logs for suspect activity",
            "Revoke unauthorized admin credentials used on deployment platforms",
            "Stop and quarantine scheduled jobs or deployments issued by threat actors"
        ],
        "mitre_mapping": [
            {"tactic": "execution", "technique": "T1059", "example": "Script execution through SCCM"},
            {"tactic": "lateral-movement", "technique": "T1021.002", "example": "Remote Service execution via Intune or SSM"},
            {"tactic": "execution", "technique": "T1651", "example": "Cloud administrative command via SaaS platform"}
        ],
        "watchlist": [
            "Unusual logins to SCCM, Intune, or SSM systems",
            "Execution of unsigned binaries through deployment mechanisms",
            "Deployment of scripts not seen in prior usage history"
        ],
        "enhancements": [
            "Enable full audit logging on software deployment platforms",
            "Deploy EDRs with integration into third-party deployment solutions",
            "Use behavioral baselines to detect sudden spikes in deployment activity"
        ],
        "summary": "Software Deployment Tools can be misused by adversaries to move laterally or execute commands in the environment using legitimate administrative mechanisms.",
        "remediation": "Limit admin access to deployment platforms, review recent job executions, and validate script sources. Lock down remote access from these tools.",
        "improvements": "Centralize third-party deployment logs, implement alerts on non-standard usage, and apply MFA and role separation to prevent lateral abuse.",
        "mitre_version": "16.1"
    }
