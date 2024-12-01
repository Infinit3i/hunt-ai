def get_content():
    """
    Returns structured content for the Autostart persistence method.
    """
    return [
        {
            "title": "Registry Run Keys",
            "content": """
The most common ASEPs (AutoStart Extension Points) are the “Run” Registry keys:
- NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
- NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce
- Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce
- Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run

These keys are executed when a user logs on. Monitoring these keys is crucial for detecting persistence mechanisms.
"""
        },
        {
            "title": "Winlogon Userinit",
            "content": """
The Winlogon Userinit key can be used to maintain persistence:
- SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit

This key typically contains:
- C:\\Windows\\system32\\userinit.exe

However, it can be modified to include malicious binaries:
- Example: C:\\Windows\\system32\\userinit.exe,C:\\Temp\\malicious.exe
"""
        },
        {
            "title": "Startup Folder",
            "content": """
The Startup folder allows for persistence by placing shortcuts in this folder:
- %AppData%\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup

Files in this folder automatically execute when a user logs on. Malware often uses this location for persistence.
"""
        },
        {
            "title": "Investigative Notes",
            "content": """
Investigating ASEPs across multiple systems can help identify compromised hosts. Key notes:
- ASEPs are numerous and diverse, requiring thorough examination.
- Tools like Registry Explorer and RegRipper can retrieve additional ASEPs from Registry hives.
- Analyzing data across systems may reveal outliers indicative of malicious activity.
"""
        }
    ]
