def get_content():
    return {
        "id": "T1505.001",
        "url_id": "T1505/001",
        "title": "Server Software Component: SQL Stored Procedures",
        "description": "Adversaries may abuse SQL stored procedures to establish persistent access to systems. SQL stored procedures are code that can be saved and reused, allowing database users to avoid rewriting common queries. Malicious stored procedures may persist in SQL servers and invoke actions like OS command execution or arbitrary code execution.",
        "tags": ["sql", "mssql", "persistence", "xp_cmdshell", "stored procedure", "CLR", "T1505.001"],
        "tactic": "Persistence",
        "protocol": "TDS",
        "os": "Windows, Linux",
        "tips": [
            "Audit use of xp_cmdshell and restrict permissions to trusted DBAs only.",
            "Regularly review stored procedures for unauthorized changes or new entries.",
            "Use SQL Server auditing to log stored procedure executions and startup procedures.",
            "Disable unused features like CLR integration or xp_cmdshell unless explicitly required."
        ],
        "data_sources": "Application Log",
        "log_sources": [
            {"type": "Application Log", "source": "Application Log Content", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Registry Hives (SOFTWARE)", "location": "HKLM\\Software\\Microsoft\\MSSQLServer", "identify": "Startup procedures or CLR execution settings"},
            {"type": "Event Logs", "location": "Application", "identify": "xp_cmdshell enabled or CLR procedure events"},
            {"type": "Process List", "location": "SQL Server host", "identify": "Unexpected child processes spawned from sqlservr.exe"}
        ],
        "destination_artifacts": [
            {"type": "File", "location": "MSSQL\\Data", "identify": "Custom or unknown CLR DLLs or stored procedure files"},
            {"type": "Windows Defender Logs", "location": "Event Viewer", "identify": "Detection of known malicious behavior from stored procedures"},
            {"type": "Event Logs", "location": "SQL Error Logs", "identify": "Abnormal procedure execution or errors during command execution"}
        ],
        "detection_methods": [
            "Detect use of xp_cmdshell by auditing SQL Server configuration changes.",
            "Review stored procedures for suspicious content or unauthorized updates.",
            "Monitor for startup stored procedures that initiate command execution.",
            "Alert on creation or modification of CLR assemblies in the database."
        ],
        "apt": ["Lazarus Group", "APT41"],
        "spl_query": [
            'index=db_logs sourcetype=mssql_application\n| search "xp_cmdshell" OR "sp_configure" OR "clr enabled"\n| stats count by user, command',
            'index=host_logs sourcetype=process_creation\n| search parent_process_name=sqlservr.exe AND process_name IN ("cmd.exe", "powershell.exe")\n| stats count by host, process_name',
            'index=db_logs sourcetype=mssql_audit\n| search "CREATE PROCEDURE" OR "ALTER PROCEDURE"\n| stats count by user, object_name'
        ],
        "hunt_steps": [
            "Enumerate all stored procedures using `sp_helptext` and inspect for unusual or obfuscated commands.",
            "Check SQL Server configuration for xp_cmdshell or CLR integration enabled.",
            "Scan SQL databases for suspicious CLR assemblies.",
            "Review logs for execution of high-risk procedures like xp_cmdshell."
        ],
        "expected_outcomes": [
            "Discovery of unauthorized or malicious stored procedures.",
            "Detection of SQL-based persistence or command execution mechanisms.",
            "Identification of exploitation through enabled CLR assemblies or startup procedures."
        ],
        "false_positive": "Legitimate administrators may use xp_cmdshell or custom procedures during maintenance. Validate via user context, timing, and change logs.",
        "clearing_steps": [
            "Drop unauthorized stored procedures using `DROP PROCEDURE`.",
            "Disable xp_cmdshell with `sp_configure 'xp_cmdshell', 0` followed by `RECONFIGURE`.",
            "Review and remove unauthorized CLR assemblies via `sp_dropextendedproc` or `DROP ASSEMBLY`.",
            "Reset permissions on SQL accounts to prevent further abuse."
        ],
        "clearing_playbook": ["https://learn.microsoft.com/en-us/sql/relational-databases/security/sql-server-attack-surface-area-configuration"],
        "mitre_mapping": [
            {"tactic": "Execution", "technique": "T1059.005", "example": "Command execution through xp_cmdshell"},
            {"tactic": "Persistence", "technique": "T1505", "example": "Stored procedures executed on server startup"},
            {"tactic": "Privilege Escalation", "technique": "T1548.002", "example": "Abuse of database service account privileges"}
        ],
        "watchlist": [
            "New stored procedures created outside change windows",
            "xp_cmdshell enabled or executed",
            "CLR assemblies loaded into the database",
            "Database service account initiating unusual external connections"
        ],
        "enhancements": [
            "Implement strict role-based access controls on all stored procedure modifications.",
            "Disable unsafe features (CLR, xp_cmdshell) by default and monitor for re-enablement.",
            "Regular audits of SQL procedures and DB-level anomaly detection.",
            "Alert when server startup stored procedures are modified."
        ],
        "summary": "SQL Stored Procedures can be abused for persistence in database environments, allowing attackers to execute system-level commands or implant logic to be invoked automatically on service restart. Features like xp_cmdshell and CLR integration provide particularly powerful execution avenues.",
        "remediation": "Disable high-risk features like xp_cmdshell and CLR. Remove unauthorized procedures, review database permissions, and enforce auditing of stored procedure changes.",
        "improvements": "Automate detection of risky stored procedures and periodically scan all databases for persistence mechanisms. Alert on abnormal procedure creation patterns.",
        "mitre_version": "16.1"
    }
