def get_content():
    """
    Returns structured content for analyzing PowerShell activity.
    """
    return [
        {
            "title": "PowerShell Logging",
            "content": """
- Command logs: ConsoleHost_history.txt (last 4096 commands).
- Operational logs: Script block logging (4104).
            """
        },
        {
            "title": "Remote Execution",
            "content": """
- Enter-PSSession: Interactive remote shell.
- Invoke-Command: Executes parallel tasks remotely.
            """
        },
        {
            "title": "Key Features of PowerShell",
            "content": """
- Automation of complex tasks.
- Logs suspicious script activities automatically (v5 and later).
            """
        }
    ]
