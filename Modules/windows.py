from Modules.Persistence.persistence import get_persistence_menu

def get_windows_content():

    persistence_menu = get_persistence_menu()
    
    return [
        {
            "title": "Malware Names",
            "content": """
                - svchost.exe - misspelled
                - iexplore.exe
                - explorer.exe
                - lsass.exe - should only be one
                - win.exe
                - winlogon.exe
                - a.exe
                - ab.exe - shorter names since mal devs are lazy
            """,
            "resources": [
                "https://malwaredb.malwarebytes.com/",
                "https://www.trendmicro.com/vinfo/us/security/definition/malware"
            ]
        },
        {
            "title": "Malware Locations",
            "content": """
                - \\Temp
                - C:\\Users\\*\\Downloads
                - \\AppData
                  - C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\Recent
                - \\$Recycle.Bin
                - \\ProgramData
                - \\Windows
                - \\Windows\\System32
                - \\WinSxS
                - \\System Volume Information
                - \\Program Files
                - \\Program Files (x86)
                - [Added Directories by APTs]
            """,
            "resources": [
                "https://www.microsoft.com/en-us/wdsi",
                "https://www.bleepingcomputer.com/"
            ]
        },
        {
            "title": "File Types",
            "content": """
                ### Scripts
                - `.ps1`, `.vbs`, `.py`, `.bat`

                ### Windows Binaries
                - `.exe`, `.msi`, `.dll`

                ### Archives
                - `.rar`, `.zip`, `.cab`, `.7z`, `.Eo1`, `.iso`, `.ova`, `.ovf`, `.vmdk`, `.vdk`

                Other:
                - `.eval`
                - `.xls`
                - `.doc`
                - ActiveXObject
                - CommandLineTemplate
                - ScriptText
            """,
            "resources": [
            ]
        },
        {
            "title": "Security Events",
            "content": """
                - 4698 A scheduled task was created
                - 4720 A user account was created
                - 4768 A Kerberos authentication ticket (TGT) was requested
                - 4769 A Kerberos service ticket was requested
                - 5140 A network share object was accessed
                - 7045 A new service was installed in the system
                - 4688 A new process has been created
                - 7036 Service changed
                - 7040 Service startup type changed
            """,
            "resources": [
                "https://www.ultimatewindowssecurity.com/",
                "https://www.splunk.com/en_us/blog.html"
            ]
        },
        {
            "title": "Sysmon Events",
            "content": """
                1. **Event ID 1**: Process creation.
                   - Captures command-line arguments for every executed process.
                2. **Event ID 3**: Network connections.
                   - Logs every TCP/UDP connection initiated by a monitored process.
                3. **Event ID 6**: Driver loading.
                   - Tracks unsigned or unexpected kernel modules.
                4. **Event ID 7**: Image loading.
                   - Detects DLLs or libraries loaded from unusual locations.
                5. **Event ID 10**: WMI activity.
                   - Monitors suspicious or unauthorized WMI queries.
            """,
            "resources": [
                "https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon",
                "https://thedfirreport.com/"
            ]
        },
        {
            "title": persistence_menu["title"],
            "content": persistence_menu["description"],
            "resources": [
                "",
            ],
            "links": [
                {"name": method["name"], "url": method["url"]} for method in persistence_menu["methods"]
            ]
        },
    ]
