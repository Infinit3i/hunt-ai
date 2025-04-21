def get_content():
    return {
        "id": "T1574.004",
        "url_id": "T1574/004",
        "title": "Hijack Execution Flow: Dylib Hijacking",
        "description": "Adversaries may abuse the dynamic linker (dyld) on macOS by placing malicious dynamic libraries (dylibs) in locations where they will be loaded by applications at runtime. Dylib hijacking occurs when a legitimate application is tricked into loading a malicious library instead of the intended one, due to how the system resolves paths. This can occur when the application uses path-dependent loading keywords like `@rpath`, `@loader_path`, or `@executable_path`, or when it weakly links to libraries using `LC_LOAD_WEAK_DYLIB`.\n\nIf a required dylib is missing or improperly specified, attackers can place a malicious one with the expected name in a searched path. Once loaded, the dylib inherits the privileges and context of the application, potentially allowing privilege escalation, persistent access, and evasion of defenses due to execution under a trusted process.\n\nCommonly abused by malware on macOS, this technique can bypass security controls and exploit applications that do not properly validate their dynamic library dependencies.",
        "tags": ["macOS", "Dylib Injection", "Privilege Escalation", "Persistence", "Execution Hijack"],
        "tactic": "Defense Evasion, Persistence, Privilege Escalation",
        "protocol": "",
        "os": "macOS",
        "tips": [
            "Use `otool -l` to inspect binaries for rpath or weak dylib dependencies.",
            "Enforce code signing and library validation with SIP (System Integrity Protection).",
            "Monitor for changes in dylib load paths or unexpected dylib versions loaded into sensitive apps."
        ],
        "data_sources": "File: File Creation, File: File Modification, Module: Module Load",
        "log_sources": [
            {"type": "File", "source": "/Library, ~/Library", "destination": ""},
            {"type": "Module", "source": "macOS Unified Logs or endpoint telemetry", "destination": ""},
            {"type": "File", "source": "fs_usage / audit logs", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Dylib", "location": "~/Library/Application Support/<App>/libXYZ.dylib", "identify": "Malicious dylib inserted in expected path"}
        ],
        "destination_artifacts": [
            {"type": "Module", "location": "Legitimate macOS application memory space", "identify": "Hijacked library loaded at runtime"}
        ],
        "detection_methods": [
            "Compare loaded dylibs against a baseline of legitimate libraries.",
            "Use Objective-See tools like Dylib Hijack Scanner to detect vulnerable apps.",
            "Track module load events that originate from unusual paths in user-writable directories."
        ],
        "apt": [],
        "spl_query": [
            "index=macos_logs sourcetype=process_events\n| search process_path=\"*.dylib\" AND (file_path=\"*/Library/*\" OR file_path=\"/Users/*\")\n| stats count by user, process_name, file_path, command_line"
        ],
        "hunt_steps": [
            "Identify all apps weakly linking to dylibs via `LC_LOAD_WEAK_DYLIB` or `@rpath`.",
            "Search for newly created or modified dylibs in user-accessible folders.",
            "Check if any system or trusted processes are loading dylibs from non-standard paths."
        ],
        "expected_outcomes": [
            "Detection of unauthorized dylib loads from user-modifiable directories.",
            "Confirmation that legitimate apps are loading malicious or unexpected dylibs.",
            "Improved monitoring of macOS dynamic linker abuse patterns."
        ],
        "false_positive": "Developer debugging activity or legitimate library updates may trigger changes in dylib paths. Validate by verifying signatures and sources.",
        "clearing_steps": [
            "Delete or quarantine the malicious dylib.",
            "Reinstall or update the hijacked application to restore proper dependencies.",
            "Ensure permissions and SIP settings are appropriately enforced."
        ],
        "mitre_mapping": [
            {"tactic": "Persistence", "technique": "T1574.004", "example": "Malware drops malicious dylib to override weakly linked dependency in a user app"}
        ],
        "watchlist": [
            "Unexpected dylib creation in user directories",
            "Process loads of dylibs with unverified signatures",
            "System apps loading libraries from non-root paths"
        ],
        "enhancements": [
            "Leverage macOS MDM policies to limit execution of unsigned code.",
            "Enforce full path specification and remove weak linking in compiled applications.",
            "Build baselines of trusted dylibs per endpoint and flag deviations."
        ],
        "summary": "Dylib hijacking on macOS allows attackers to inject malicious code into legitimate applications by abusing weak path resolution mechanisms. This technique is stealthy, persistent, and effective at privilege escalation or defense evasion.",
        "remediation": "Patch vulnerable applications to specify absolute paths to dependencies. Enforce SIP and code-signing. Detect and remove rogue dylibs.",
        "improvements": "Train devs to avoid relative path loading and weak dylib links. Improve baseline monitoring for dylib loads per app.",
        "mitre_version": "16.1"
    }
