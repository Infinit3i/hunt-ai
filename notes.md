https://www.elastic.co/security-labs/continuation-on-persistence-mechanisms

https://buymeacoffee.com/bitlemonsoftware/e/362123

https://github.com/Koen1999/suricata-check
    
https://www.elastic.co/security-labs/continuation-on-persistence-mechanisms

- [Red Canary: Threat Detection Report](https://redcanary.com/threat-detection-report/trends/by-industry/)
- Summit the Pyramid focuses on actionable defense strategies.

            "title": "Threat-Informed Defense",
            "content": """
- Know your threats to focus detection efforts.
- Be realistic about available log sources and noise levels.


itle": "MITRE's Summit the Pyramid",
            "content": """
- A framework to prioritize and address threats effectively.
- Aligns detection and response efforts with adversarial TTPs.
            """



Malvertising - Injecting malicious code into trusted websites.


Common File Format Attacks
- Exploits weaknesses in how applications handle file requests.
- Examples: PDF, DOC(X), RTF, WMF.

Common Client-Side Attack Vectors
- Web browsers, browser extensions.
- Document and image rendering applications.


            "title": "PICERL Framework",
            "content": """
- Phases: Preparation, Identification, Containment, Eradication, Recovery, Lessons Learned.
- Example: Containment using decoys or monitoring tools.
            """,
        },
        {
            "title": "Containment Challenges",
            "content": """
- Rapid containment avoids losing critical intelligence.
- No containment leads to prolonged adversary presence (whack-a-mole).
            """,
        },
        {
            "title": "Hunt vs. Reactive Teams",
            "content": """
- Reactive (Incident Response): Firefighting approach, putting out fires.
- Hunt Teams: Proactive, leveraging threat intelligence to predict and disrupt.
            """,
        },
        {
            "title": "Detection Engineering",
            "content": """
- Focus on enabling actionable and collaborative processes.
- Outsource or automate repetitive tasks while maintaining oversight of critical alerts.
            """,
        },
        {
            "title": "Advanced Forensic Tools",
            "content": """
- Volatility: Memory analysis.
- Splunk and Loggly: Advanced log analysis and monitoring.
- MFT Analysis: Tools like MFTECmd for NTFS evidence.
            """,
        }
    ]


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


def get_content():
    """
    Returns structured content for NTFS, journaling, and anti-forensics artifacts.
    """
    return [
        {
            "title": "NTFS Metadata and Attributes",
            "content": """
- MFT Attributes: Tracks MAC timestamps, $File_Name, $Data (resident or non-resident).
- $LogFile and $UsnJrnl: Log file changes and deletions.
            """
        },
        {
            "title": "Timeline Analysis",
            "content": """
- $SI and $FN timestamps: Can indicate timestomping or anti-forensic techniques.
- Exiftool: Verifies discrepancies in timestamps and metadata.
            """
        },
        {
            "title": "Advanced Analysis Tools",
            "content": """
- LogfileParser: Extracts NTFS transactional logs.
- Mftecmd: Parses MFT entries and supports Volume Shadow Copies.
- Icat: Extracts data streams like Zone.Identifier for ADS.
            """
        },
        {
            "title": "Deleted File Evidence",
            "content": """
- MFT metadata persists even after deletion.
- $INDEX_ROOT and $INDEX_ALLOCATION track directory changes.
            """
        }
    ]


def get_content():
    """
    Returns structured content for GMON security insights.
    """
    return [
        {
            "title": "511.1.1 - Botnet Evolution",
            "content": """
- Botnets mark the transition from traditional to modern attack techniques.
- Emphasis on denying adversaries' goals by understanding key organizational priorities.
            """
        },
        {
            "title": "511.1.4 - New Security Paradigm",
            "content": """
- Detect adversaries and respond rapidly.
- Define desired outcomes to act effectively.
            """
        },
        {
            "title": "511.1.5 - Decline of Server Exploits",
            "content": """
- Modern attacks favor client-side over server-side exploits.
- Early malware primarily focused on spreading, with newer approaches targeting credentials and persistence.
            """
        },
        {
            "title": "511.2.1 - People and Processes",
            "content": """
- Emphasizing processes over tools: Prevent -> Detect -> Respond.
- Telemetry and behavioral analysis as foundational elements of modern security.
            """
        }
    ]


def get_content():
    """
    Returns structured content for case studies and specific incidents.
    """
    return [
        {
            "title": "Golden Ticket Attack",
            "content": """
- Resolution: Change `krbtgt` account password twice.
            """
        },
        {
            "title": "SQL Injection Defense",
            "content": """
- Parameterized queries as the most effective mitigation.
            """
        },
        {
            "title": "Cloud Security Issues",
            "content": """
- Misconfigured buckets: Files can be enumerated and downloaded.
- IMDSv2: Mitigates SSRF exploitation.
            """
        }
    ]


def get_content():
    """
    Returns structured content for memory forensics and tools.
    """
    return [
        {
            "title": "Live Memory Capture Tools",
            "content": """
- WinPmem: Memory acquisition.
- Magnet RAM Capture: Free tool for acquiring live memory.
- Belkasoft RAM Capturer: Simplifies RAM imaging.
- F-Response: Advanced forensic data acquisition.
            """
        },
        {
            "title": "Memory Artifacts",
            "content": """
- Hibernation Files: Compressed RAM image located at %SystemDrive%\\hiberfil.sys.
- Page File/Swap Space: Located at %SystemDrive%\\pagefile.sys or %SystemDrive%\\swapfile.sys.
- Kernel-Mode Dump Files: Located at %SystemRoot%\\MEMORY.DMP.
            """
        },
        {
            "title": "Volatility Plugins",
            "content": """
- PsList/PsScan: Identifies processes.
- Malfind: Scans process memory sections for hidden code.
- LdrModules: Detects unlinked DLLs or injected code.
- SSDT: Identifies hooked system API functions.
            """
        }
    ]

def get_content():
    """
    Returns structured content for network defense strategies and tools.
    """
    return [
        {
            "title": "Web Proxy Types",
            "content": """
- Open Source: Squid, Nginx, Apache Traffic Server.
- Commercial: Symantec Web Filter, Forcepoint, Zscaler.
            """
        },
        {
            "title": "NetFlow and IPFIX",
            "content": """
- Session data for L3/L4 troubleshooting.
- Enables rapid detection without full packet captures.
            """
        },
        {
            "title": "SOC Essentials",
            "content": """
- Functions: Detection, Auditing, Response, Operations/Maintenance.
- Outsourcing vs. internal teams: Benefits and trade-offs.
            """
        }
    ]



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


- [ ] T-code - pass the hash - is local account

      block these for pass the has
      S-1-5-113: NT AUTHORITY\Local account
      S-1-5-114: NT AUTHORITY\Local account in Administrators group

      pass the pass (word) - wdigest, live, tspkg, kerberos - SeDebugPrivilege or SYSTEM priviledges
