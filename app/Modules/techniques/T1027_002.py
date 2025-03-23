def get_content():
    return {
        "id": "T1027.002",
        "url_id": "T1027/002",
        "title": "Obfuscated Files or Information: Software Packing",
        "description": "Adversaries may use software packing or virtual machine protection to obfuscate code and evade detection.",
        "tags": ["evasion", "packing", "anti-analysis", "virtual machine", "binary obfuscation"],
        "tactic": "Defense Evasion",
        "protocol": "",
        "os": "Linux, Windows, macOS",
        "tips": [
            "Use unpacking tools to analyze packed binaries before static analysis.",
            "Apply YARA rules to detect known packer signatures in executables.",
            "Cross-reference packed binaries with known-good software baselines."
        ],
        "data_sources": "File: File Metadata",
        "log_sources": [
            {"type": "File", "source": "Endpoint Agent", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "File Metadata", "location": "File System", "identify": "Packed binaries with unknown or suspicious packer signatures"},
            {"type": "Memory Dumps", "location": "Runtime Memory", "identify": "Unpacked code loaded dynamically during execution"},
            {"type": "Loaded DLLs", "location": "Process Memory", "identify": "Injection or runtime unpacking behavior"}
        ],
        "destination_artifacts": [
            {"type": "File Metadata", "location": "ProgramData or Temp folders", "identify": "Executables with known packer entropy patterns"},
            {"type": "Windows Defender Logs", "location": "Security logs", "identify": "Flags or warnings for packer use"},
            {"type": "Memory Dumps", "location": "Memory Snapshots", "identify": "Deobfuscated sections during runtime"}
        ],
        "detection_methods": [
            "Use entropy analysis to identify compressed/encrypted sections",
            "Detect packer signatures using static analysis tools like PEiD",
            "Monitor process injection and memory unpacking behavior"
        ],
        "apt": [
            "APT10", "APT38", "BlackOasis", "Cobalt Kitty", "CostaRicto", "Dragonfly", "Donot", "Lazarus", "Rocke",
            "Clop", "Bisonal", "RAINDROP", "Latrodectus", "Kimsuky", "OceanLotus", "GreyEnergy", "Tomiris", "Soft Cell", "TeamTNT",
            "Snake", "Sofacy", "Spalax", "Adwind", "Gamaredon", "Dust Storm", "Molaret", "Emotet", "FIN7", "ZeroT", "Machete"
        ],
        "spl_query": [
            'index=malware_logs "packer detected" OR "entropy high" OR "runtime unpacking"\n| stats count by file_name, file_path, host',
            'index=endpoint file_name="*.exe" OR file_name="*.dll"\n| eval entropy=calculate_entropy(file_content)\n| where entropy > 7.5'
        ],
        "hunt_steps": [
            "Scan systems for packed executables using packer detection tools",
            "Check endpoint memory for deobfuscated code",
            "Analyze AV logs for repeated flags on compressed/encrypted executables"
        ],
        "expected_outcomes": [
            "Detection of adversaries using UPX or custom packers to evade static detection",
            "Identification of binaries dynamically unpacking code in memory",
            "Correlation of packed binaries with suspicious process behavior"
        ],
        "false_positive": "Legitimate software such as commercial games, DRM-protected tools, or proprietary software may use packing. Always correlate with behavior.",
        "clearing_steps": [
            "Delete detected packed binaries unless verified as legitimate",
            "Run AV scans with heuristics enabled to catch repacked malware",
            "Use a sandbox environment to unpack and analyze binaries safely"
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1140", "example": "Packed malware unpacks itself before execution"},
            {"tactic": "Execution", "technique": "T1059.003", "example": "Packed payload launches command shell post-unpacking"}
        ],
        "watchlist": [
            "Executables with high entropy values",
            "Files packed with UPX or MPRESS in unexpected paths",
            "Processes spawning from known packer extraction points (Temp, AppData)"
        ],
        "enhancements": [
            "Enable sandbox detonation of binaries before execution",
            "Tune EDR to alert on execution of binaries from Temp/AppData",
            "Combine entropy analysis with process behavior analytics"
        ],
        "summary": "Software packing is a method used by adversaries to obfuscate executable code, often compressing or encrypting it to bypass static detection mechanisms. While common in legitimate applications, it is also widely abused by malware to conceal intent.",
        "remediation": "Deploy advanced endpoint detection capable of runtime unpacking analysis. Proactively review high-entropy binaries or packer indicators in your environment.",
        "improvements": "Correlate detection of packed binaries with behavioral analysis and known threat actor TTPs to reduce false positives.",
        "mitre_version": "16.1"
    }
