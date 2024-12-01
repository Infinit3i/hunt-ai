def get_content():
    """
    Returns structured content for Windows event log analysis.
    """
    return [
        {
            "title": "Important Event IDs",
            "content": """
- Logon Events: 4624, 4634, 4672.
- Administrative Shares: 5140.
- RDP Session Events: 4778, 4779.
            """
        },
        {
            "title": "PowerShell Logs",
            "content": """
- 4104: Script block logging.
- Transcript logs: Logs all commands and their output.
            """
        },
        {
            "title": "System Logs for Analysis",
            "content": """
- Security Logs: Detect process execution.
- Application Logs: Identify crashes and anomalies.
            """
        },
        {
            "title": "Key Event IDs",
            "content": """
- 4624: Logon method (e.g., console, network, RDP).
- 4672: Logon with admin privileges.
- 5140: Identifies administrative shares potentially mounted by attackers.
            """
        },
        {
            "title": "RDP Events",
            "content": """
- TerminalServices-RDPClient: Logs destination hostname/IP for outgoing RDP sessions.
- 4778/4779: Tracks reconnect and disconnect events, including remote machine IP and hostname.
            """
        },
        {
            "title": "System and Application Logs",
            "content": """
- Useful for identifying malware execution through warning and error events.
- Security Logs: Can track process execution, file access, and PsExec usage.
            """
        },
        {
            "title": "PowerShell Event Logs",
            "content": """
- Event 4104: Logs PowerShell script block execution.
- Transcript logs: Capture all commands typed and their output.
            """
        }
    ]
