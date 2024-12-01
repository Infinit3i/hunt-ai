def get_content():
    """
    Returns structured content for Basic Persistence Mechanisms.
    """
    return [
        {
            "title": "BootExecute Key",
            "content": r"""
### BootExecute Key
The BootExecute registry key launches processes before the subsystem initializes.

**Key Path**:
- `HKEY_LOCAL_MACHINE\SYSTEM\ControlSet002\Control\Session`
            """
        },
        {
            "title": "WinLogon Process Keys",
            "content": r"""
### WinLogon Process Keys
1. **Userinit Key**:
    - Launches login scripts during the user logon process.
    - **Key Path**: `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`
2. **Notify Key**:
    - Handles the `Ctrl+Alt+Del` event.
    - **Key Path**: `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify`
3. **Explorer.exe Key**:
    - Points to `explorer.exe` and can be abused for persistence.
    - **Key Path**: `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell`
            """
        },
        {
            "title": "Startup Keys",
            "content": r"""
### Startup Keys
Startup keys allow programs to launch when a user logs on.

**Key Paths**:
- `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`
- `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`
            """
        },
        {
            "title": "Services Keys",
            "content": r"""
### Services Keys
Services keys enable services to boot automatically at startup.

**Key Paths**:
- `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services`
- `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce`
- `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServices`
            """
        },
        {
            "title": "Browser Helper Objects",
            "content": r"""
### Browser Helper Objects
Browser Helper Objects can be used for persistence or malicious activity.

**Key Path**:
- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
            """
        },
        {
            "title": "AppInit_DLLs",
            "content": r"""
### AppInit_DLLs
The AppInit_DLLs registry key specifies DLLs that are loaded into every user-mode process that loads `user32.dll`.

**Key Path**:
- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs`
            """
        },
        {
            "title": "Persistence Using Global Flags",
            "content": r"""
### Persistence Using Global Flags
Global flags in the Image File Execution Options registry key can be abused for persistence.

**Example Commands**:
- `reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe" /v GlobalFlag /t REG_DWORD /d 512`
- `reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\notepad.exe" /v ReportingMode /t REG_DWORD /d 1`
- `reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\notepad.exe" /v MonitorProcess /d "C:\temp\evil.exe"`
            """
        }
    ]
