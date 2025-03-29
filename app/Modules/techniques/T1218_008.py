def get_content():
    return {
        "id": "T1218.008",
        "url_id": "T1218/008",
        "title": "System Binary Proxy Execution: Odbcconf",
        "tactic": "Defense Evasion",
        "protocol": "Local Execution",
        "os": "Windows",
        "tips": [
            "Look for `odbcconf.exe` usage with `/A {REGSVR` or unexpected DLL paths.",
            "Correlate execution with unsigned or uncommon DLLs being registered.",
            "Baseline normal use of `odbcconf.exe` across your environment to identify anomalies."
        ],
        "data_sources": "Command Execution, Module Load, Process Creation",
        "log_sources": [
            {"type": "Process Creation", "source": "Sysmon (Event ID 1)", "destination": "SIEM"},
            {"type": "Command Execution", "source": "Security Event Logs (Event ID 4688)", "destination": "SIEM"},
            {"type": "Module Load", "source": "Sysmon (Event ID 7)", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "DLL", "location": "Public folders or temp directories", "identify": "Malicious DLL registered via odbcconf.exe"}
        ],
        "destination_artifacts": [
            {"type": "Registered module", "location": "Registry and memory", "identify": "Malicious module registered and executed"}
        ],
        "detection_methods": [
            "Monitor for `odbcconf.exe` command lines registering suspicious DLLs.",
            "Compare execution patterns with known good baselines.",
            "Check for DLLs loaded from unusual or non-standard directories."
        ],
        "apt": ["G0032", "G1006", "G0004"],
        "spl_query": [
            "index=windows sourcetype=WinEventLog:Security EventCode=4688 New_Process_Name=*odbcconf.exe*",
            "index=sysmon EventCode=1 Image=*odbcconf.exe* CommandLine=*REGSVR*",
            "index=sysmon EventCode=7 ImageLoaded=*\\Users\\Public\\*.dll"
        ],
        "hunt_steps": [
            "Query SIEM for odbcconf.exe executions using REGSVR flag.",
            "Identify any DLLs registered from suspicious directories like Public or Temp.",
            "Validate legitimacy of those DLLs through signature and behavioral analysis.",
            "Check if child processes or registry modifications followed DLL registration.",
            "Review lateral movement paths where odbcconf may be used as proxy execution."
        ],
        "expected_outcomes": [
            "Malicious DLL execution via odbcconf is identified and neutralized.",
            "Gaps in application control or DLL whitelisting policies are revealed.",
            "Further compromise paths through LOLBAS (Living Off the Land Binaries and Scripts) are better understood."
        ],
        "false_positive": "Legitimate usage may occur in some driver installation workflows. Validate context and DLL origin before escalating.",
        "clearing_steps": [
            "Kill any related processes spawned from unauthorized odbcconf usage.",
            "Remove malicious DLLs from system and unregister them if necessary.",
            "Update AppLocker or WDAC rules to block odbcconf usage where appropriate."
        ],
        "mitre_mapping": [
            {
                "tactic": "Defense Evasion",
                "technique": "T1218.008 (System Binary Proxy Execution: Odbcconf)",
                "example": "Using odbcconf.exe to register and execute a DLL via REGSVR flag."
            }
        ],
        "watchlist": [
            "Alert on odbcconf.exe executions with unexpected command-line flags.",
            "Track DLLs being registered through REGSVR, especially from user-writable paths.",
            "Audit systems for presence of unsigned or strange DLLs in ProgramData, Temp, or Public folders."
        ],
        "enhancements": [
            "Implement application control rules to restrict odbcconf.exe usage.",
            "Digitally sign all internal DLLs and monitor for unsigned or modified ones.",
            "Educate teams on LOLBAS and implement detection rules across other similar binaries."
        ],
        "summary": "Odbcconf.exe is a signed Windows utility that can be abused to register and execute malicious DLLs, bypassing traditional application control and monitoring mechanisms.",
        "remediation": "Audit all use of odbcconf.exe, remove malicious DLLs, and update policies to restrict this LOLBAS technique.",
        "improvements": "Broaden detection coverage to include DLL abuse across other Windows trusted binaries. Enhance EDR logic to monitor misuse of legitimate administrative tools.",
        "mitre_version": "16.1"
    }
