def get_content():
    return {
        "id": "T1137.001",
        "url_id": "T1137/001",
        "title": "Office Application Startup: Office Template Macros",
        "description": "Adversaries may abuse Microsoft Office templates (e.g., Normal.dotm, PERSONAL.XLSB) to obtain persistence by embedding VBA macros that execute when Office applications start.",
        "tags": ["persistence", "vba", "office", "template", "macro", "registry"],
        "tactic": "persistence",
        "protocol": "",
        "os": "Office Suite, Windows",
        "tips": [
            "Monitor template files like Normal.dotm and PERSONAL.XLSB for unauthorized changes",
            "Audit GlobalDotName registry key for unauthorized paths or tampering",
            "Restrict macro execution to signed macros only in enterprise environments"
        ],
        "data_sources": "Command, File, Process, Windows Registry",
        "log_sources": [
            {"type": "File", "source": "Windows Security", "destination": ""},
            {"type": "Process", "source": "Sysmon", "destination": ""},
            {"type": "Windows Registry", "source": "Sysmon", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Registry Hives (NTUSER.DAT)", "location": "HKCU\\Software\\Microsoft\\Office\\<version>\\Word\\Options", "identify": "GlobalDotName key"},
            {"type": "File Access Times (MACB Timestamps)", "location": "%APPDATA%\\Microsoft\\Templates\\Normal.dotm", "identify": "Template modified"},
            {"type": "Prefetch Files", "location": "C:\\Windows\\Prefetch", "identify": "WinWord.exe or Excel.exe launching templates"}
        ],
        "destination_artifacts": [
            {"type": "File", "location": "%APPDATA%\\Microsoft\\Templates\\Normal.dotm", "identify": "Embedded malicious macro"},
            {"type": "File", "location": "%APPDATA%\\Microsoft\\Excel\\XLSTART\\PERSONAL.XLSB", "identify": "Malicious template file"},
            {"type": "Windows Registry", "location": "HKCU\\Software\\Microsoft\\Office\\<version>\\Word\\Options\\GlobalDotName", "identify": "Path to malicious template"}
        ],
        "detection_methods": [
            "Monitor registry key modifications to GlobalDotName",
            "Inspect Office templates for embedded macros or unauthorized content",
            "Alert on Office processes spawning unusual child processes"
        ],
        "apt": [
            "MuddyWater", "Cobalt Strike operators", "BackConfig"
        ],
        "spl_query": [
            'index=wineventlog EventCode=13 OR EventCode=12 \n| search TargetObject="*\\GlobalDotName"',
            'index=sysmon EventCode=11 \n| search TargetFilename="*\\Normal.dotm" OR TargetFilename="*\\PERSONAL.XLSB"',
            'index=sysmon EventCode=1 \n| search ParentImage="*\\WINWORD.EXE" OR ParentImage="*\\EXCEL.EXE" \n| stats count by Image, CommandLine'
        ],
        "hunt_steps": [
            "Identify recent modifications to Normal.dotm and PERSONAL.XLSB",
            "Look for Office processes spawning PowerShell or CMD",
            "Check GlobalDotName registry values for unusual paths"
        ],
        "expected_outcomes": [
            "Detection of malicious macros embedded in template files",
            "Persistence mechanisms via Office startup templates",
            "Office spawning unexpected child processes"
        ],
        "false_positive": "Legitimate users may create or modify templates for automation—validate macro signatures and origin before alerting.",
        "clearing_steps": [
            "Delete or replace compromised template files (Normal.dotm, PERSONAL.XLSB)",
            "Reset GlobalDotName registry key to default",
            "Enforce macro execution policy via GPO"
        ],
        "mitre_mapping": [
            {"tactic": "persistence", "technique": "T1137", "example": "GlobalDotName used to load template from remote or alternate location"},
            {"tactic": "execution", "technique": "T1059.005", "example": "Office macros used to execute malicious code"},
            {"tactic": "defense-evasion", "technique": "T1564.004", "example": "Hide macro inside a trusted Office location"}
        ],
        "watchlist": [
            "Template files with recent or unexpected modifications",
            "Office macros from untrusted authors",
            "Registry writes to GlobalDotName"
        ],
        "enhancements": [
            "Enable macro warning banners and disallow unsigned macros",
            "Log and alert on Office spawning script interpreters",
            "Baseline template hash values and monitor changes"
        ],
        "summary": "Malicious Office templates provide stealthy persistence by embedding macros that automatically execute when Word or Excel is launched.",
        "remediation": "Reset template files to clean versions, remove malicious macros, monitor registry changes, and enforce signed macro policies.",
        "improvements": "Implement EDR alerts for Office child process behavior and monitor template files with file integrity monitoring tools.",
        "mitre_version": "16.1"
    }
