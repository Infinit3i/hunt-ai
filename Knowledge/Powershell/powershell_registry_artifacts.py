def get_content():
    """
    Returns structured content for PowerShell, registry artifacts, and related forensics.
    """
    return [
        {
            "title": "PowerShell v5 Logging",
            "content": """
- Automatically logs suspicious scripts for analysis.
- ConsoleHost_history.txt records the last 4096 PowerShell commands.
            """
        },
        {
            "title": "Registry Artifacts",
            "content": """
- MountPoints2: Lists all systems a user account connects to.
- ShimCache: Backward compatibility artifact, shows whether an application has executed.
- Windows Error Reporting: Provides SHA1 hashes of malware, especially for poorly written samples.
            """
        },
        {
            "title": "AppCompatCache Tracking",
            "content": """
- Tracks full path and last modification time of executables on Windows 10+ systems.
            """
        },
        {
            "title": "Amcache Analysis",
            "content": """
- Logs executable name/path, first execution time, and SHA1 hash (remove leading zeros for VirusTotal lookup).
- Important Note: Entries do not always indicate execution.
            """
        }
    ]
