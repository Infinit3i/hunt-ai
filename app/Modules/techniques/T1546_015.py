def get_content():
    """
    Returns structured content for the DCOM-based persistence method.
    """
    return {
        "id": "T1546.015",
        "url_id": "T1546/015",
        "title": "Event Triggered Execution: Component Object Model Hijacking",
        "tactic": "Persistence, Privilege Escalation",
        "data_sources": "Windows Event Logs, Process Monitoring, Registry, Sysmon Logs",
        "protocol": "DCOM",
        "os": "Windows",
        "objective": "Leverage DCOM objects to execute commands remotely and persist on a system.",
        "scope": "Monitor DCOM object usage and registry modifications for hijacked execution paths.",
        "threat_model": "Adversaries can abuse DCOM objects to execute code remotely without dropping files on disk, making detection challenging.",
        "hypothesis": [
            "Are unauthorized DCOM objects being leveraged for remote execution?",
            "Are registry entries being modified to redirect DCOM execution paths?",
            "Is there an unusual increase in DCOM-based executions within the environment?"
        ],
        "tips": [
            "Monitor for svchost.exe spawning unusual child processes such as mmc.exe.",
            "Enable advanced logging for COM object execution.",
            "Correlate event logs with known attack patterns involving DCOM abuse."
        ],
        "log_sources": [
            {"type": "Windows Event Logs", "source": "Security.evtx", "destination": "SIEM"},
            {"type": "Process Monitoring", "source": "Sysmon Event ID 1", "destination": "SIEM"},
            {"type": "Registry", "source": "Sysmon Event ID 13", "destination": "SIEM"}
        ],
        "source_artifacts": [
            {"type": "Registry Key", "location": "HKCU\\Software\\Classes\\CLSID\\{COM GUID}", "identify": "Modified CLSID entry"},
            {"type": "Event Logs", "location": "Security.evtx", "identify": "Event ID 4688 showing mmc.exe execution"}
        ],
        "destination_artifacts": [
            {"type": "Temporary File", "location": "ADMIN$\\__sssss", "identify": "Temporary command output file"}
        ],
        "detection_methods": [
            "Monitor Windows Event ID 4688 for mmc.exe execution with -Embedding flag.",
            "Detect Event ID 4624 and 4672 for anomalous authentication events.",
            "Analyze registry modifications related to CLSID keys in HKCU\\Software\\Classes\\CLSID."
        ],
        "apt": [
            "G0007 - APT28: Known to abuse DCOM for lateral movement and persistence."
        ],
        "spl_query": [
            "index=windows EventCode=4688 | search ParentProcessName=svchost.exe ProcessName=mmc.exe"
        ],
        "hunt_steps": [
            "Identify unusual executions of mmc.exe with -Embedding flag.",
            "Investigate registry modifications for CLSID keys redirecting execution paths.",
            "Correlate Event ID 4688 with DCOM-based lateral movement attempts."
        ],
        "expected_outcomes": [
            "Detection of unauthorized DCOM-based remote code execution.",
            "Identification of persistent registry modifications for CLSID hijacking."
        ],
        "false_positive": "Legitimate administrative scripts may use DCOM execution, requiring context-based analysis.",
        "clearing_steps": [
            "Remove unauthorized CLSID modifications from the Windows registry.",
            "Audit administrative user activity to ensure proper use of DCOM.",
            "Apply group policies to restrict DCOM execution paths."
        ],
        "mitre_mapping": [
            {"tactic": "Persistence", "technique": "T1547 (Boot or Logon Autostart Execution)", "example": "DCOM abuse may be combined with logon scripts for persistence."},
            {"tactic": "Lateral Movement", "technique": "T1021 (Remote Services)", "example": "Adversaries may use DCOM to execute commands on remote systems."}
        ],
        "watchlist": [
            "Monitor execution of mmc.exe with unexpected parent processes.",
            "Detect newly created CLSID registry keys redirecting execution."
        ],
        "enhancements": [
            "Disable DCOM if not required for business operations.",
            "Enforce strict access controls on CLSID registry entries.",
            "Enable Sysmon logging for process creation and registry modifications."
        ],
        "summary": "DCOM-based persistence leverages Component Object Model (COM) hijacking to maintain unauthorized access.",
        "remediation": "Restrict DCOM usage, monitor registry modifications, and enforce endpoint logging.",
        "improvements": "Implement advanced monitoring with EDR solutions and apply least privilege principles."
    }



'''
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
'''