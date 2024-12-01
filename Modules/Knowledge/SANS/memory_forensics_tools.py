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
