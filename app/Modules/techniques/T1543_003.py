def get_content():
    """
    Returns structured content for the Service-based persistence method.
    """
    return {
        "id": "T1543.003",
        "url_id": "T1543/003",
        "title": "Create or Modify System Process: Windows Service",
        "tactic": "Persistence, Privilege Escalation",
        "description": "Adversaries may create or modify Windows services to execute malicious payloads for persistence or privilege escalation. Windows services perform background system functions and can be configured to start at boot. Attackers may install new services, modify existing ones, or exploit vulnerable drivers to execute malicious code.",
        "tags": ["Persistence", "Privilege Escalation", "Windows", "Windows Service"],
        "tactic": "Persistence, Privilege Escalation",
        "protocol": "Windows API, Windows Service Control Manager",
        "os": ["Windows"],
        "tips": [
            "Monitor processes and command-line arguments for actions that create or modify services.",
            "Detect execution of 'sc.exe', 'PowerShell', or 'wmic' for service modifications.",
            "Monitor Windows Registry modifications related to service configuration."
        ],
        "data_sources": "Process Creation, Windows Registry, Service Creation, Command Execution, Driver Load",
        "tips": [
            "Monitor Event ID 7045 (service installation) and 4697 (non-default service creation).",
            "Check for services with unusual startup types (e.g., auto-start with unsigned binaries).",
            "Detect suspicious service binaries placed in writable directories."
        ],
        "log_sources": [
            {"type": "Windows Security", "source": "", "destination": "4624 - type 3, 4697"},
            {"type": "Windows System", "source": "", "destination": "7034, 7035, 7036, 7040, 7045"},
            {"type": "Registry", "source": "SYSTEM\\CurrentControlSet\\Services"},
            {"type": "File System", "source": "Prefetch, Service Executables"},
        ],
        "source_artifacts": [
            {"type": "Prefetch", "location": "C:\\Windows\\Prefetch", "identify": "sc.exe, services.exe"}
        ],
        "destination_artifacts": [
            {"type": "Service Executables", "location": "C:\\Windows\\System32", "identify": "Malicious service binaries"}
        ],
        "detection_methods": [
            "Monitor new services registered in the registry.",
            "Analyze service executable paths for anomalies.",
            "Check for unsigned service executables."
        ],
        "apt": ["ZxShell", "Bankshot", "Hydraq", "Sednit", "BlackEnergy", "Lotus Blossom", "Sunburst", "Grim Spider", "AcidBox", "Carbanak", "WastedLocker", "Cuba", "Kazuar", "APT41", "DarkVishnya", "Winnti"],
        "spl_query": [
            "index=windows (EventCode=7045 OR EventCode=4697) \n| table Time, ServiceName, ImagePath",
        ],
        "hunt_steps": [
            "Search for recently created services in the registry.",
            "Check for suspicious or unsigned service binaries.",
            "Investigate service accounts with abnormal privileges."
        ],
        "expected_outcomes": [
            "Unauthorized service detected and mitigated.",
            "No suspicious activity found, improving baseline detection."
        ],
        "false_positive": "Legitimate administrators may create new services as part of IT operations.",
        "clearing_steps": [
            "sc delete <ServiceName>",
            "Remove malicious binaries from C:\\Windows\\System32."
        ],
        "mitre_mapping": [
            {"tactic": "Persistence", "technique": "T1547.001 (Registry Run Keys)", "example": "Adversaries may use registry keys for persistence."}
        ],
        "watchlist": [
            "Monitor service creation and modification attempts.",
            "Detect unauthorized service startup entries."
        ],
        "enhancements": [
            "Enable logging for service creation and modification.",
            "Restrict service installation permissions."
        ],
        "summary": "Attackers may create or modify Windows services for persistence or privilege escalation.",
        "remediation": "Remove unauthorized services and audit permissions on service-related registry keys.",
        "improvements": "Enhance monitoring for suspicious service creation and execution."
    }


'''
     
          
        {
            "title": "Source Registry",
            "content": """
### Source Registry
Registry Artifacts:
- [[ShimCache]] - SYSTEM
    - Tracks `sc.exe`.
- [[BAM_DAM]] - SYSTEM - Last Time Executed
    - Tracks `sc.exe`.
- [[AmCache.hve]]
    - Tracks first execution of `sc.exe`.
            """
        },
        {
            "title": "Destination Registry",
            "content": """
### Destination Registry
Registry Artifacts:
- SYSTEM
    - `\\CurrentControlSet\\Services\\` - New service creation.
- [[ShimCache]] - SYSTEM
    - Tracks `evil.exe`.
- [[AmCache.hve]] - First Time Executed
    - Tracks `evil.exe`.
            """
        },
        {
            "title": "Source File System",
            "content": """
### Source File System
Prefetch Artifacts:
- Prefetch - `C:\\Windows\\Prefetch\\`
    - `sc.exe-{hash}.pf`.
            """
        },
        {
            "title": "Destination File System",
            "content": """
### Destination File System
File Creation Artifacts:
- Malicious executables or DLLs:
    - `evil.exe` or `evil.dll`.
- Prefetch - `C:\\Windows\\Prefetch\\`
    - Tracks execution of `evil.exe` or service DLLs.
            """
        },
        {
            "title": "Service Replacement Examples",
            "content": """
### Service Replacement Examples
Service replacement involves modifying legitimate services to execute malicious payloads.

#### Example 1: Binary Path Manipulation
Modify the `ImagePath` registry key to point to a malicious executable:
- Key Path: `HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\<ServiceName>\\ImagePath`
- New Value: `C:\\temp\\evil.exe`

#### Example 2: DLL Hijacking in Services
Replace a legitimate service DLL with a malicious one:
- Locate service DLL in `\\CurrentControlSet\\Services\\<ServiceName>\\Parameters\\ServiceDll`.
- Replace the file with `evil.dll`.

#### Example 3: Startup Type Abuse
Change the `Start` registry key to automatically start a malicious service:
- Key Path: `HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\<ServiceName>\\Start`
- Value: `2` (Automatic Start).

#### Example 4: Service Install Command
Use `sc` to create and start a malicious service:
- Command: `sc \\host create servicename binpath="c:\\temp\\evil.exe"`
            """
        },
        {
            "title": "Exploitation of Windows Services",
            "content": """
### Exploitation of Windows Services
Windows services can be exploited in the following ways:

#### 1. Privilege Escalation via Insecure Permissions
- Services with weak `DACL` permissions can be reconfigured by low-privileged users.
- Example: Modify `ImagePath` to point to a malicious binary.

#### 2. DLL Search Order Hijacking
- Service executable dynamically loads a DLL without specifying a full path.
- Place a malicious DLL in the service's working directory.

#### 3. Service Control Abuse
- Use `sc` or similar tools to start/stop services, potentially disrupting legitimate operations.

#### 4. Unquoted Service Paths
- If the binary path contains spaces and is unquoted, an attacker can place a malicious executable in the path.
- Example:
    - Path: `C:\\Program Files\\Legitimate Service\\binary.exe`.
    - Malicious executable: `C:\\Program.exe`.

#### 5. Creating New Services
- Install a new malicious service using `sc` or `psexec`.
- Example:
    - `sc create maliciousservice binpath="c:\\temp\\evil.exe" start=auto`

#### 6. Abusing Trusted Services
- Replace binaries or DLLs of highly trusted services, such as antivirus or backup services.

#### Detection Tips:
- Monitor `system.evtx` for service start/stop events.
- Check `security.evtx` for suspicious service creation.
- Regularly audit `\\CurrentControlSet\\Services\\` for unexpected entries.
            """
        }
    ]
    
{
            "title": "Drivers",
            "content": """
### Drivers
Malicious drivers can be used to escalate privileges or maintain persistence.

#### Detection Techniques:
1. **Registry Key**:
   - `HKLM\\SYSTEM\\CurrentControlSet\\Services\\<DriverName>`
   - Look for unsigned or newly installed drivers.
2. **Event IDs**:
   - Event ID `7045` (Service Installed): Tracks driver installation.
3. **Artifacts**:
   - Examine `C:\\Windows\\System32\\drivers` for unauthorized or unsigned drivers.
"""
        },
    
'''