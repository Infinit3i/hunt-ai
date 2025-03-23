def get_content():
    return {
        "id": "T1027.008",
        "url_id": "T1027/008",
        "title": "Obfuscated Files or Information: Stripped Payloads",
        "description": "Adversaries may use stripped payloads by removing symbols, strings, and human-readable information to hinder analysis.",
        "tags": ["stripped binaries", "defense evasion", "obfuscation", "apple script", "static analysis evasion"],
        "tactic": "Defense Evasion",
        "protocol": "",
        "os": "Linux, Network, Windows, macOS",
        "tips": [
            "Use heuristics and sandboxing to analyze behavior of stripped payloads.",
            "Compare similar payloads with and without symbols to identify stripped versions.",
            "Correlate behavior with known TTPs even if the file lacks readable indicators."
        ],
        "data_sources": "File: File Metadata",
        "log_sources": [
            {"type": "File", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "File Access Times (MACB Timestamps)", "location": "Filesystem", "identify": "Newly dropped stripped binaries"},
            {"type": "Memory Dumps", "location": "Runtime memory", "identify": "Extracted symbols during execution"},
            {"type": "Registry Hives", "location": "HKCU\\Software\\Classes\\", "identify": "Run-only AppleScript execution references"}
        ],
        "destination_artifacts": [
            {"type": "Windows Defender Logs", "location": "C:\\ProgramData\\Microsoft\\Windows Defender\\", "identify": "Unusual executable without typical metadata"},
            {"type": "Sysmon Logs", "location": "Microsoft-Windows-Sysmon/Operational", "identify": "Execution of binaries with no command-line arguments or signature"},
            {"type": "Windows Error Reporting (WER)", "location": "C:\\ProgramData\\Microsoft\\Windows\\WER", "identify": "Crashes due to malformed stripped payloads"}
        ],
        "detection_methods": [
            "Behavioral analysis and sandbox execution",
            "Heuristic analysis of binary structure and entropy",
            "Detection of missing symbol tables and stripped headers"
        ],
        "apt": [
            "Cuckoo", "Lazarus", "APT32"
        ],
        "spl_query": [
            'index=sysmon EventCode=1\n| search ImageLoaded=*\\*.exe\n| eval stripped=if(strlen(CommandLine)<20 AND SignatureStatus="Unsigned", "Yes", "No")\n| where stripped="Yes"',
            'index=sysmon EventCode=11\n| search TargetFilename="*.scpt" OR TargetFilename="*.exe"\n| stats count by TargetFilename, User, Image'
        ],
        "hunt_steps": [
            "Identify binaries with no imports or debugging symbols",
            "Search for run-only AppleScript files or ELF binaries with stripped sections",
            "Correlate memory-resident strings with malware signatures",
            "Perform YARA-based scans for stripped sections in common formats"
        ],
        "expected_outcomes": [
            "Detection of stripped executables used to avoid static inspection",
            "Discovery of stealth malware with obfuscated metadata",
            "Increased reliance on behavioral indicators for identification"
        ],
        "false_positive": "Some legitimate commercial software may be stripped for size or IP protection, especially in embedded systems.",
        "clearing_steps": [
            "Quarantine and reverse engineer the stripped binary using dynamic analysis",
            "Extract runtime memory indicators to generate signatures",
            "Alert on additional machines that executed the payload"
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1140", "example": "Deobfuscation of stripped payloads during runtime"},
            {"tactic": "Execution", "technique": "T1059.002", "example": "Execution of run-only AppleScript payloads"}
        ],
        "watchlist": [
            "Executables with no digital signature or symbol table",
            "Binaries with extremely high entropy and no strings",
            "Run-only `.scpt` files on macOS endpoints"
        ],
        "enhancements": [
            "Deploy behavior-based EDRs with memory scanning",
            "Use compiler-level instrumentation to detect unauthorized stripping",
            "Alert on the use of tools like `strip`, `objcopy`, or `upx -d`"
        ],
        "summary": "Stripped payloads remove symbols and readable strings to make reverse engineering more difficult and evade static detection.",
        "remediation": "Perform dynamic and memory analysis to extract indicators and identify behavior. Use YARA rules targeting stripped binaries.",
        "improvements": "Enhance detection rules to catch anomalies in binary structure and develop symbol-stripping heuristics.",
        "mitre_version": "16.1"
    }
