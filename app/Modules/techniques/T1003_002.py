def get_content():
    return {
        "id": "T1003.002",
        "url_id": "T1003/002",
        "title": "OS Credential Dumping: Security Account Manager",
        "description": "Adversaries may extract credential hashes from the Security Account Manager (SAM) database using in-memory or registry-dumping techniques.",
        "tags": ["sam", "hash dumping", "mimikatz", "reg save", "creddump7", "pwdump", "gsecdump"],
        "tactic": "Credential Access",
        "protocol": "",
        "os": "Windows",
        "tips": [
            "Monitor for Registry save attempts of HKLM\\sam and HKLM\\system",
            "Track creation of files named 'sam', 'system', or 'ntds.dit' in user-accessible paths",
            "Use Sysmon Event ID 11 for access to sensitive SAM files"
        ],
        "data_sources": "Sysmon, Command, File, Windows Registry",
        "log_sources": [
            {"type": "Command", "source": "", "destination": ""},
            {"type": "File", "source": "", "destination": ""},
            {"type": "Windows Registry", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "File", "location": "C:\\Windows\\System32\\config\\SAM", "identify": "Access or export of the SAM hive"},
            {"type": "Windows Registry Hives", "location": "HKLM\\SAM", "identify": "Dump attempts using reg.exe or PowerShell"},
            {"type": "File Access Times (MACB Timestamps)", "location": "%TEMP% or attacker-staged folders", "identify": "sam/system dump files"}
        ],
        "destination_artifacts": [],
        "detection_methods": [
            "Detect `reg save HKLM\\sam` and `HKLM\\system` commands",
            "Watch for access to `C:\\Windows\\System32\\config\\SAM` file",
            "Detect execution of known tools like secretsdump.py, pwdumpx, and mimikatz targeting SAM"
        ],
        "apt": [
            "APT1", "APT29", "APT33", "APT41", "BRONZE UNION", "Daggerfly", "Elephant Beetle", "Ke3chang", "ProjectSauron", "Soft Cell", "The Dukes", "Union", "CozyDuke"
        ],
        "spl_query": [
            'index=windows_logs sourcetype=Sysmon EventCode=11 TargetFilename="*\\config\\SAM"',
            'index=windows_logs sourcetype=WinRegistry registry_path="HKLM\\\\SAM" action=save',
            'index=windows_logs sourcetype=ProcessTracking process_name="reg.exe" OR process_name="secretsdump.py" command_line="*save*HKLM\\sam*"'
        ],
        "hunt_steps": [
            "Look for registry export activity related to HKLM\\sam and HKLM\\system",
            "Check for recent access to SAM database files",
            "Scan for password hash extraction tools on disk or in memory"
        ],
        "expected_outcomes": [
            "Identification of attempts to dump local account hashes",
            "Discovery of exported SAM and SYSTEM registry hives",
            "Detection of adversary use of credential dumping tools"
        ],
        "false_positive": "Some forensic or IT operations may access SAM for legitimate recovery purposes. Validate tool signatures and timing with expected activity.",
        "clearing_steps": [
            "Remove dumped SAM and SYSTEM files: `del /f /q C:\\Users\\Public\\sam`",
            "Clear any temporary hash dumping tools dropped on disk",
            "Rotate local account credentials if hashes may have been exposed"
        ],
        "mitre_mapping": [
            {"tactic": "Credential Access", "technique": "T1078", "example": "Use of stolen SAM hashes to authenticate as valid accounts"}
        ],
        "watchlist": [
            "File creation named 'sam', 'system', or similar in user directories",
            "Reg.exe and regedit.exe using /save flag on SAM keys",
            "Execution of gsecdump, pwdumpx, or secretsdump.py"
        ],
        "enhancements": [
            "Apply permissions restricting access to HKLM\\SAM and \\SYSTEM",
            "Deploy Sysmon with logging of registry access and file creation",
            "Use LSA protection features and Credential Guard to mitigate hash access"
        ],
        "summary": "The SAM registry hive stores local account hashes that can be dumped via tools like reg.exe or mimikatz and used for offline cracking or lateral movement.",
        "remediation": "Delete exported hives, rotate local credentials, restrict registry access, and harden the system with LSA protection or Credential Guard.",
        "improvements": "Deploy GPOs to restrict use of reg.exe for sensitive key exports and monitor registry access patterns at scale.",
        "mitre_version": "16.1"
    }
