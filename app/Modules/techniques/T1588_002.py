def get_content():
    return {
        "id": "T1588.002",
        "url_id": "T1588/002",
        "title": "Obtain Capabilities: Tool",
        "description": "Adversaries may buy, steal, or download software tools that can be used during targeting. These tools may be open-source, commercial, or proprietary utilities not inherently malicious but repurposed for adversary operations. Tools like PsExec, Cobalt Strike, and similar red team frameworks are often acquired through legal channels or by cracking licensing restrictions. In some instances, adversaries may steal licensed copies or credentials for licensed tools from other threat actors or organizations.",
        "tags": ["resource-development", "tooling", "third-party-tools", "psExec", "cobalt-strike", "commercial-ware"],
        "tactic": "Resource Development",
        "protocol": "",
        "os": "Any",
        "tips": [
            "Track installation or appearance of dual-use tools in internal environments.",
            "Use threat intel to correlate tools with known APT or ransomware groups.",
            "Apply behavioral detection for usage patterns indicative of abuse (e.g., PsExec for lateral movement)."
        ],
        "data_sources": "Malware Repository: Malware Metadata, Endpoint: File Metadata, Process Creation, Network Traffic",
        "log_sources": [
            {"type": "Malware Repository", "source": "", "destination": ""},
            {"type": "Endpoint", "source": "File Metadata", "destination": ""},
            {"type": "Endpoint", "source": "Process Creation", "destination": ""},
            {"type": "Network", "source": "Traffic Flow", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "PE File", "location": "Adversary staging system", "identify": "Tool executables used for lateral movement"},
            {"type": "Network Metadata", "location": "Initial contact system logs", "identify": "Communication to known tooling infrastructure"}
        ],
        "destination_artifacts": [
            {"type": "File", "location": "C:\\ProgramData\\*", "identify": "Staged red team or exploitation tools"},
            {"type": "Process", "location": "", "identify": "Child processes launched by PsExec or similar tool"}
        ],
        "detection_methods": [
            "Detect known tool hashes and file paths",
            "Hunt for process names associated with red team frameworks (e.g., beacon.exe, rundll32 launched with unusual arguments)",
            "Alert on command-line usage or services resembling lateral movement or post-exploitation tools"
        ],
        "apt": ["APT29", "APT41", "FIN12", "Cobalt Group", "LAPSUS", "UNC3890", "Chimera", "Silence", "Volt Typhoon"],
        "spl_query": [
            "index=malware_repository signature=\"Tool\" source=\"*cobaltstrike*\" OR file_name=\"*PsExec.exe\"\n| stats count by file_name, hash, signature_status",
            "index=endpoint sourcetype=winlog source_image=*PsExec* OR command_line=\"*beacon*\"\n| stats count by host, parent_process, command_line"
        ],
        "hunt_steps": [
            "Review endpoint logs for installation or execution of well-known dual-use tools",
            "Correlate hashes and file paths with threat intel on red team frameworks",
            "Examine network flows for command-and-control communication tied to cracked tools"
        ],
        "expected_outcomes": [
            "Identification of unauthorized tool acquisition",
            "Early detection of adversary staging activities",
            "Mapping of adversary-preparation steps prior to active compromise"
        ],
        "false_positive": "Penetration testing teams and internal red teams may use the same tools. Always validate context, timing, and ownership.",
        "clearing_steps": [
            "Isolate and delete unauthorized tools",
            "Audit and disable compromised licenses",
            "Reimage or rollback systems where tool execution occurred"
        ],
        "clearing_playbook": ["https://attack.mitre.org/resources/prevention-toolkit/tool-acquisition-mitigation"],
        "mitre_mapping": [
            {"tactic": "Execution", "technique": "T1059", "example": "Tool used to run commands post-compromise"},
            {"tactic": "Defense Evasion", "technique": "T1218", "example": "Signed tool used to evade AV/EDR"},
            {"tactic": "Lateral Movement", "technique": "T1021", "example": "PsExec or SMB tools used for movement"}
        ],
        "watchlist": [
            "Tools like Cobalt Strike, PsExec, SoftPerfect, Metasploit",
            "Payloads delivered from GitHub, anonymous file shares, or cracked software portals",
            "Internal use of known red team software without authorization"
        ],
        "enhancements": [
            "Enable enhanced logging on binaries with known abuse potential",
            "Create signatures for cracked or watermark-free variants of red team tools",
            "Tag first-seen dual-use tools in EDR/XDR platforms"
        ],
        "summary": "The acquisition of software tools—especially red team and administrative utilities—allows adversaries to prepare for and execute post-compromise actions more effectively. While not inherently malicious, these tools can become highly dangerous when abused.",
        "remediation": "Revoke or blacklist unauthorized tooling, perform forensic analysis, and implement better license and access controls to prevent future misuse.",
        "improvements": "Use threat feeds to monitor for new tooling trends, and regularly update internal whitelists and blacklists to distinguish red team and threat actor tools.",
        "mitre_version": "16.1"
    }
