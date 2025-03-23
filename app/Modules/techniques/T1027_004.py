def get_content():
    return {
        "id": "T1027.004",
        "url_id": "T1027/004",
        "title": "Obfuscated Files or Information: Compile After Delivery",
        "description": "Adversaries may deliver source code that is compiled on the target system to evade detection.",
        "tags": ["evasion", "compile", "defense evasion", "source code", "ilasm", "gcc", "csc"],
        "tactic": "Defense Evasion",
        "protocol": "",
        "os": "Linux, Windows, macOS",
        "tips": [
            "Alert on execution of compilers like ilasm.exe, csc.exe, gcc, or mingw when not part of software development activity.",
            "Monitor temp or user folders for newly created executables compiled shortly after receiving source code.",
            "Track payloads written in text-based formats such as .cs, .cpp, or embedded within scripting containers."
        ],
        "data_sources": "Command: Command Execution, File: File Creation, File: File Metadata, Process: Process Creation",
        "log_sources": [
            {"type": "Command", "source": "", "destination": ""},
            {"type": "File", "source": "", "destination": ""},
            {"type": "Process", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "File Metadata", "location": "User folders or downloads", "identify": "Uncompiled source files (e.g., .cs, .cpp)"},
            {"type": "Process List", "location": "Runtime", "identify": "Compiler processes such as ilasm.exe, gcc"},
            {"type": "Memory Dumps", "location": "RAM", "identify": "Compiler activity in memory creating binaries"}
        ],
        "destination_artifacts": [
            {"type": "File Creation", "location": "User profile or temp folders", "identify": "Executable compiled from suspicious source"},
            {"type": "Registry Hives", "location": "HKCU\\Software\\Microsoft\\VisualStudio", "identify": "Artifact of compiler execution"},
            {"type": "Recent Files", "location": "NTUSER.DAT", "identify": "Recently opened source code files"}
        ],
        "detection_methods": [
            "Monitor for process execution of compiler binaries outside of known dev environments",
            "Analyze file creation patterns tied to compile-time activity",
            "Correlation of email/downloaded attachments containing source code followed by compiler process execution"
        ],
        "apt": [
            "njRAT", "Rocke", "MuddyWater", "Gamaredon", "ToddyCat", "DarkWatchman", "CardinalRat", "FoggyWeb"
        ],
        "spl_query": [
            'index=endpoint_logs process_name="ilasm.exe" OR process_name="csc.exe" OR process_name="gcc"\n| stats count by host, user, parent_process, command_line',
            'index=file_creation file_path="*.exe" \n| join file_path [ search index=file_access file_path="*.cs" OR file_path="*.cpp" ]\n| stats count by file_path, user, host'
        ],
        "hunt_steps": [
            "Search for source code dropped in user temp/downloads directories",
            "Look for compiler tools launched from uncommon paths",
            "Identify binaries with compile timestamps matching recent file writes"
        ],
        "expected_outcomes": [
            "Detection of source code execution via local compilation",
            "Correlation of downloaded source with compiled binaries",
            "Discovery of unauthorized compiler presence or usage"
        ],
        "false_positive": "Legitimate software developers may use local compilers. Baseline dev activity to reduce noise.",
        "clearing_steps": [
            "Remove compiler payloads and compiled binaries",
            "Inspect startup folders or registry keys for persistence",
            "Quarantine user accounts that compiled and executed unverified source code"
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1059.005", "example": "Execution of code from newly compiled binary"},
            {"tactic": "Execution", "technique": "T1204.002", "example": "User opens uncompiled code and executes resulting binary"}
        ],
        "watchlist": [
            "Compiler usage on production systems",
            "Executable creation in %TEMP% or Downloads shortly after code delivery",
            "Rare invocation of Mono or MinGW compilers"
        ],
        "enhancements": [
            "Implement EDR rules for compiler process creation",
            "Restrict access to compiler binaries on non-dev systems",
            "Add alerting for file extensions like .cs or .cpp being opened in text editors followed by compile activity"
        ],
        "summary": "Compile After Delivery enables adversaries to evade static detection by delivering source code instead of executables. The code is compiled post-delivery, often using native compilers already present on the system.",
        "remediation": "Block or restrict compiler tools on non-development machines. Audit logs for new executable creation tied to user actions.",
        "improvements": "Deploy alerts on compiler binaries in sensitive environments. Tag compiler paths as high-risk in endpoint monitoring.",
        "mitre_version": "16.1"
    }
