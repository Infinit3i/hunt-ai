def get_content():
    """
    Returns structured content for the DLL Hijacking persistence method.
    """
    return [
        {
            "title": "File System Analysis",
            "content": """
### File System Analysis
- Look for new or unsigned `.exe` and `.dll` files in unusual locations.
- Example Indicators:
    - Timestamp: 2021-02-18 03:42:31
        - Impact: -
        - Method: mach Meta
        - File Name: `c:/ProgramData/mcoemcpy.exe` (size: 77824)
    - File: `c:/ProgramData/McUtil.dll` (size: 131072)
            """
        },
        {
            "title": "Memory Analysis",
            "content": """
### Memory Analysis
- Identify system processes or DLLs loaded from unusual locations.
- Pay attention to:
    - Processes running unexpected code.
    - DLLs loaded from locations outside expected directories.
- Newly created DLLs and executables can indicate malicious activity.
            """
        },
        {
            "title": "Command Line Analysis",
            "content": """
### Command Line Analysis
- Review suspicious command-line execution patterns.
    - Example:
        - Command: `C:\\ProgramData\\ncoenchy.exe 0x4`
        - Method: mach Meta
- Check for signs of injection or other manipulation.
            """
        },
        {
            "title": "SANS DFIR Insights",
            "content": """
### SANS DFIR Insights
- Nearly all DLL hijacks require placing a new DLL or executable onto the file system.
- Investigative Techniques:
    - **File Timeline Analysis**:
        - Focus on newly created files during times of interest.
    - **Memory Forensics**:
        - Analyze running processes for unexpected DLL locations.
- Obscure DLLs are more likely to be targeted since common DLLs are usually preloaded into memory.
- Other anomalous actions like network beaconing or named pipe creation can lead to detection.
            """
        }
    ]
