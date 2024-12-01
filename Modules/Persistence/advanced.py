def get_content():
    """
    Returns structured content for the Advanced persistence method.
    """
    return [
        {
            "title": "BIOS Flashing",
            "content": """
### BIOS Flashing
Advanced persistence through BIOS flashing involves modifying firmware to execute malicious code before the operating system loads.

#### Detection Techniques:
1. **Registry Key**:
   - Check for tools/scripts associated with flashing (e.g., `HKCU\\Software\\OEM\\FirmwareTools`).
2. **Event IDs**:
   - Monitor Event ID `1100` (Windows Audit Log Cleared) before suspected flashing activity.
3. **Artifacts**:
   - Examine for mismatched firmware versions compared to vendor-provided firmware binaries.
"""
        },
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
        {
            "title": "Local Group Policy",
            "content": """
### Local Group Policy
Manipulating group policies can enable persistence by enforcing malicious configurations.

#### Detection Techniques:
1. **Registry Key**:
   - `HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\<PolicyKey>`
   - Look for suspicious changes in security policy settings.
2. **Artifacts**:
   - Review the `C:\\Windows\\System32\\GroupPolicy\\Machine` directory for unauthorized changes.
3. **Event IDs**:
   - Event ID `4719` (System Audit Policy Changed): Tracks group policy changes.
"""
        },
        {
            "title": "MS Office Add-In",
            "content": """
### MS Office Add-In
Persistence via MS Office add-ins involves placing malicious macros or scripts that execute when Office applications are opened.

#### Detection Techniques:
1. **Registry Key**:
   - `HKCU\\Software\\Microsoft\\Office\\<Version>\\AddIns\\<AddInName>`
   - Monitor for unusual add-in registrations.
2. **Artifacts**:
   - Inspect the `C:\\Users\\<Username>\\AppData\\Roaming\\Microsoft\\AddIns` directory for unknown files.
3. **Event IDs**:
   - Event ID `800` (PowerShell Script Block Logging): Detects execution of scripts, potentially related to add-ins.
"""
        }
    ]
