def get_content():
    """
    Returns structured content for the DCOM-based persistence method.
    """
    return [
        {
            "title": "DCOM Execution Overview",
            "content": """
### DCOM Execution (dcomexec.py):
- **Command**: `dcomexec.py -object [ShellWindows | ShellBrowserWindow | MMC20] domain/username:password@[hostname | IP] command`
    - Specify a command to run or leave blank for shell.
    - Executes a semi-interactive shell using DCOM objects.
    - Must specify 'ShellWindows', 'ShellBrowserWindow', or 'MMC20' via the `-object` parameter.
    - Uses the first 5 digits of the UNIX Epoch Time in commands.

**Features**:
- Not detected or blocked by Windows Defender by default.
            """
        },
        {
            "title": "Windows Event Log Residue",
            "content": """
### Event Log Residue:
- Two rounds of:
    - Event ID `4776` in Security on target (for user specified in command).
    - Event ID `4672` in Security on target (for user specified in command).
    - Event ID `4624` Type 3 in Security on target (for user specified in command).

#### If Enabled:
- Event ID `4688` in Security on target:
    - `svchost.exe → mmc.exe -Embedding`.
    - `mmc.exe → cmd.exe /Q /c cd \\ 1> \\127.0.0.1\\ADMIN$\\__sssss 2>&1` (where “s” is the first 5 digits of the UNIX Epoch Time).
    - `cmd.exe → conhost.exe 0xffffffff -ForceV1`.

#### User Specified Commands:
- Event ID `4688` in Security on target:
    - `mmc.exe → cmd.exe /Q /c command 1> \\127.0.0.1\\ADMIN$\\__sssss 2>&1`.
    - `cmd.exe → conhost.exe 0xffffffff -ForceV1`.

- Two rounds of:
    - Event ID `4634` Type 3 in Security on target (for user specified in command).
            """
        },
        {
            "title": "Analysis of Commands Executed via DCOM",
            "content": """
### Command Execution Details:
- DCOM execution involves creating a semi-interactive shell or running specific commands via DCOM objects.
- Commands use `mmc.exe` and `cmd.exe`:
    - `mmc.exe → cmd.exe /Q /c command 1> \\127.0.0.1\\ADMIN$\\__sssss 2>&1`.
    - The temporary file (__sssss) is created in the ADMIN$ share and cleaned up after execution.

**Key Indicators**:
- Look for temporary files in the ADMIN$ share with names matching the pattern `__sssss`.
- Monitor suspicious use of `mmc.exe` with the `-Embedding` flag.
            """
        },
        {
            "title": "Detection and Mitigation",
            "content": """
### Detection:
- Monitor `security.evtx` and `system.evtx` for:
    - Event ID `4688` showing `mmc.exe` or `cmd.exe` with unusual arguments.
    - Event ID `4624` and `4672` indicating logon attempts.
    - Event ID `4634` showing logoff events.

- Use tools like Sysmon to log detailed command-line activity:
    - Enable logging for `mmc.exe`, `cmd.exe`, and `conhost.exe`.
    - Look for suspicious command-line parameters, such as the `-Embedding` flag.

### Mitigation:
- Restrict DCOM usage via GPO:
    - Navigate to: `Computer Configuration > Administrative Templates > Windows Components > DCOM`.
    - Disable DCOM or restrict to trusted applications.

- Regularly audit temporary files in ADMIN$ shares.
- Use endpoint protection solutions to detect unusual DCOM activity.
            """
        }
    ]
