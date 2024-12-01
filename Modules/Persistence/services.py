def get_content():
    """
    Returns structured content for the Service-based persistence method.
    """
    return [
        {
            "title": "Source Event Logs",
            "content": """
No specific source event logs are generated for service-based persistence.
            """
        },
        {
            "title": "Destination Event Logs",
            "content": """
### Destination Event Logs
- **security.evtx**
    - `4624` Logon Type 3
        - Source IP/Logon User Name
    - `4697`
        - Records service installation (non-default)
    - Useful for centralized log monitoring.

- **system.evtx**
    - `7034` - Service crashed unexpectedly.
    - `7035` - Service sent a Start/Stop control.
    - `7036` - Service started or stopped.
    - `7040` - Start type changed (Boot | On Request | Disabled).
    - `7045` - A service was installed on the system.
            """
        },
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
