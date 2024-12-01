def get_content():
    """
    Returns structured content for the PsExec persistence method.
    """
    return [
        {
            "title": "Source Event Logs",
            "content": """
### Source Event Logs
- **security.evtx**
    - `4648` - Logon specifying alternate credentials
        - Current logged-on User Name
        - Alternate User Name
        - Destination Host Name/IP
        - Process Name
            """
        },
        {
            "title": "Destination Event Logs",
            "content": """
### Destination Event Logs
- **security.evtx**
    - `4648` Logon specifying alternate credentials
        - Connecting User Name
        - Process Name
    - `4624` Logon Type 3 (and Type 2 if “-u” Alternate Credentials are used)
        - Source IP/Logon User Name
    - `4672`
        - Logon User Name
        - Logon by a user with administrative rights
        - Requirement for access default shares such as **C$** and **ADMIN$**
    - `5140` – Share Access
        - **ADMIN$** share used by PsExec
- **system.evtx**
    - `7045` Service installation: 4-character mixed-case alpha name referencing an 8-character mixed-case alpha .exe file
        - %systemroot%\\xxxxxxxx.exe
    - `7036` Service start/stop events
- **If Enabled**:
    - `4688` in Security: tracks service and cmd.exe execution
            """
        },
        {
            "title": "Source Registry",
            "content": """
### Source Registry
- **NTUSER.DAT**
    - Software\\SysInternals\\PsExec\\EulaAccepted
- **ShimCache** – SYSTEM
    - psexec.exe
- **BAM_DAM** – SYSTEM – Last Time Executed
    - psexec.exe
- **AmCache.hve** – First Time Executed
    - psexec.exe
            """
        },
        {
            "title": "Destination Registry",
            "content": """
### Destination Registry
- New service creation configured in `SYSTEM\\CurrentControlSet\\Services\\PSEXESVC`
    - “-r” option can allow attacker to rename service
- **ShimCache** – SYSTEM
    - psexesvc.exe
- **AmCache.hve**
    - First Time Executed
        - psexesvc.exe
            """
        },
        {
            "title": "Source File System",
            "content": """
### Source File System
- **Prefetch** – C:\\Windows\\Prefetch\\
    - psexec.exe-{hash}.pf
    - Possible references to other files accessed by psexec.exe, such as executables copied to target system with the “-c” option
- **File Creation**
    - psexec.exe file downloaded and created on the local host as the file is not native to Windows
            """
        },
        {
            "title": "Destination File System",
            "content": """
### Destination File System
- **Prefetch** – C:\\Windows\\Prefetch\\
    - psexesvc.exe-{hash}.pf
    - evil.exe-{hash}.pf
- **File Creation**
    - User profile directory structure created unless "-e" option used
    - psexesvc.exe will be placed in **ADMIN$** (\\Windows) by default, as well as other executables (evil.exe) pushed by PsExec
- **User Access Logging (Servers only)**
    - C:\\Windows\\System32\\LogFiles\\Sum
        - User Name
        - Source IP Address
        - First and Last Access Time
            """
        },
        {
            "title": "Service Installation Details",
            "content": """
### Service Installation Details
- PsExec creates a temporary Windows service for execution:
    - Service name: Random 4-character mixed-case alpha name
    - Executable: Random 8-character mixed-case alpha .exe file
- Registry Path:
    - SYSTEM\\CurrentControlSet\\Services\\<ServiceName>
- Event Log Evidence:
    - Event ID 7045 in `system.evtx` logs the service installation.
    - Includes:
        - Service Name
        - Executable Path
        - Service Type and Start Mode
- Forensic Insights:
    - Compare service names and paths across multiple systems to detect outliers.
    - Look for services with short, random names.
            """
        },
        {
            "title": "Network Artifacts",
            "content": """
### Network Artifacts
- **Network Connections**:
    - PsExec uses SMB for communication and file transfer.
    - Ports:
        - 445 (SMB over TCP/IP)
        - 139 (NetBIOS over TCP/IP)
- **Shared Resources**:
    - Default shares such as **ADMIN$** and **C$** are utilized.
    - Logs in `security.evtx`:
        - Event ID 5140: Share access.
        - Event ID 5145: Access to specific shared files.

- **Forensic Tips**:
    - Monitor for abnormal access to ADMIN$ or C$ from unexpected hosts.
    - Analyze SMB traffic for PsExec file transfers.
            """
        },
        {
            "title": "Eviction Techniques",
            "content": """
### Eviction Techniques
- **Detection**:
    - Use centralized logging solutions (e.g., Splunk, ELK) to correlate Event IDs across systems.
    - Enable advanced audit policies to log service and process creation events.

- **Eviction**:
    - Audit and remove unauthorized services under:
        - SYSTEM\\CurrentControlSet\\Services\\
    - Verify the integrity of executables in:
        - C:\\Windows\\System32
        - C:\\Windows\\Prefetch
    - Block unauthorized access to default shares like ADMIN$ and C$.

- **Prevention**:
    - Use endpoint protection tools to block PsExec executables.
    - Restrict access to administrative shares to trusted hosts and accounts only.
            """
        },
        {
            "title": "Malware Case Study",
            "content": """
### Malware Case Study
- **Real-World Example**:
    - Malware Name: Emotet
    - Attack Vector: Lateral Movement
    - Emotet leveraged PsExec to deploy secondary payloads across compromised networks.

- **Tactics**:
    - Copied malicious payloads to ADMIN$ share.
    - Used PsExec to execute payloads on remote systems.
    - Cleaned up by removing PsExec artifacts (e.g., services and files).

- **Forensic Indicators**:
    - Sudden increase in Event IDs 4624, 4672, and 5140 across multiple systems.
    - Unusual services with short, random names.
    - Files with mismatched creation and modification times in ADMIN$.
            """
        }
    ]
