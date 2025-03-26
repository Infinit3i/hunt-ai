def get_content():
    return {
        "id": "T1127",
        "url_id": "T1127",
        "title": "Trusted Developer Utilities Proxy Execution",
        "description": "Adversaries may take advantage of trusted developer utilities to proxy execution of malicious payloads by abusing signed, legitimate tools like WinDbg, MSBuild, or cdb.",
        "tags": ["defense evasion", "living off the land", "proxy execution", "signed binary", "bypass"],
        "tactic": "defense-evasion",
        "protocol": "",
        "os": "Windows",
        "tips": [
            "Track use of developer utilities in environments without known software engineering activity",
            "Create baselines for expected dev tools in each business unit",
            "Alert on MSBuild or cdb loading non-standard DLLs or shellcode"
        ],
        "data_sources": "Command, Module, Process",
        "log_sources": [
            {"type": "Command", "source": "endpoint", "destination": ""},
            {"type": "Process", "source": "Sysmon", "destination": ""},
            {"type": "Module", "source": "Sysmon", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Loaded DLLs", "location": "User profile temp directories", "identify": "Unsigned or unusual DLLs loaded by cdb.exe, dnx.exe, etc."},
            {"type": "Event Logs", "location": "Sysmon Event ID 7 or 1", "identify": "Proxy execution using signed dev binaries"},
            {"type": "Process List", "location": "EDR process tree", "identify": "Developer tools spawning command interpreters"}
        ],
        "destination_artifacts": [
            {"type": "Prefetch Files", "location": "C:\\Windows\\Prefetch", "identify": "Unexpected use of cdb.exe, msbuild.exe, or xwizard.exe"},
            {"type": "Recent Files", "location": "AppData\\Local\\Temp or DevTools folders", "identify": "Shellcode loaders or reflectively injected binaries"},
            {"type": "Sysmon Logs", "location": "Event ID 11", "identify": "Loaded DLLs not signed by Microsoft in dev tools"}
        ],
        "detection_methods": [
            "Detect execution of tools like cdb.exe, msbuild.exe, or dnx.exe from non-development systems",
            "Alert on unusual command-line arguments or DLLs passed to dev utilities",
            "Compare module load paths to known signed versions"
        ],
        "apt": [
            "FIN7", "Cobalt Group", "APT29", "Lazarus Group"
        ],
        "spl_query": [
            'index=sysmon EventCode=1 \n| search Image="*cdb.exe" OR Image="*msbuild.exe" OR Image="*rcsi.exe" \n| stats count by Image, CommandLine, User',
            'index=sysmon EventCode=7 \n| search ImageLoaded="*\\AppData\\*.dll" \n| where Image="*msbuild.exe" OR Image="*cdb.exe" \n| stats count by Image, ImageLoaded',
            'index=wineventlog OR index=process \n| search CommandLine="*shellcode*" OR CommandLine="*reflective*" \n| stats count by ParentProcessName, CommandLine'
        ],
        "hunt_steps": [
            "Identify dev tools running on endpoints not associated with developers",
            "Trace command-line arguments and child processes from tools like msbuild.exe or dnx.exe",
            "Correlate module loads from non-standard directories with suspicious parent processes"
        ],
        "expected_outcomes": [
            "Identification of adversary leveraging legitimate binaries to bypass security tools",
            "Detection of dev tools running in environments they should not exist in",
            "Link between execution flow and payload delivery"
        ],
        "false_positive": "Developer environments may use these tools legitimately. Consider baselining activity per role or business unit.",
        "clearing_steps": [
            "Remove unauthorized binaries or DLLs dropped by proxy tools",
            "Kill processes spawned via dev tool proxy execution",
            "Block or restrict access to proxyable binaries via AppLocker or WDAC"
        ],
        "mitre_mapping": [
            {"tactic": "execution", "technique": "T1059", "example": "cdb.exe spawns cmd.exe or powershell.exe"},
            {"tactic": "defense-evasion", "technique": "T1218", "example": "MSBuild used to load embedded malicious task"},
            {"tactic": "defense-evasion", "technique": "T1140", "example": "Malicious DLL decrypted by legitimate signed binary"}
        ],
        "watchlist": [
            "MSBuild.exe spawning child processes",
            "cdb.exe loading modules from temp directories",
            "Unusual developer tool usage outside normal build/test workflows"
        ],
        "enhancements": [
            "Create allowlists for dev tools per department",
            "Enable command-line and DLL load logging in Sysmon",
            "Block signed-but-abusable tools with Microsoft Defender ASR or WDAC"
        ],
        "summary": "Adversaries abuse trusted developer utilities like cdb.exe, dnx.exe, or msbuild.exe to execute payloads under the guise of legitimate processes, bypassing defenses.",
        "remediation": "Restrict usage of signed developer utilities on non-dev systems. Monitor for abnormal process usage and remove payloads they execute.",
        "improvements": "Use file integrity monitoring (FIM) for modules loaded into dev utilities. Audit rare usage and use context-aware allowlists to detect abuse.",
        "mitre_version": "16.1"
    }
