def get_content():
    return {
        "id": "T1027.005",
        "url_id": "T1027/005",
        "title": "Obfuscated Files or Information: Indicator Removal from Tools",
        "description": "Adversaries may remove identifying indicators from tools to bypass detection.",
        "tags": ["evasion", "tool modification", "signature evasion", "indicator removal"],
        "tactic": "Defense Evasion",
        "protocol": "",
        "os": "Linux, Windows, macOS",
        "tips": [
            "Look for repeated malware variants with small modifications that evade signature-based detection.",
            "Track behavioral patterns instead of relying solely on signatures.",
            "Correlate initial alerts with any follow-up changes or redeployment of similar tools."
        ],
        "data_sources": "Application Log: Application Log Content",
        "log_sources": [
            {"type": "Application Log", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "File Access Times (MACB Timestamps)", "location": "Tool directory", "identify": "Recently modified tools with slight changes"},
            {"type": "Event Logs", "location": "Security logs", "identify": "Initial detection followed by removal or modification"},
            {"type": "Memory Dumps", "location": "RAM", "identify": "Modified or packed in-memory variants of known tools"}
        ],
        "destination_artifacts": [
            {"type": "Recent Files", "location": "NTUSER.DAT", "identify": "Recently accessed modified tools"},
            {"type": "Jump Lists", "location": "User profile", "identify": "Modified tool binaries appearing again after initial alert"},
            {"type": "Registry Hives", "location": "HKCU\\Software", "identify": "Updated tool or config references"}
        ],
        "detection_methods": [
            "Track behavioral detections, especially persistence mechanisms or network patterns.",
            "Monitor file hash changes in tools used by adversaries previously detected.",
            "Analyze compile timestamps and compare with previous malicious tool variants."
        ],
        "apt": [
            "Patchwork", "TEMP.Veles", "OilRig", "Soft Cell", "GravityRAT", "Qakbot", "Turla", "Gazer", "InvisiMole"
        ],
        "spl_query": [
            'index=av_logs action="quarantined" signature="*"\n| stats count by file_name, file_hash, user, host',
            'index=file_modifications file_path="*\\\\Tools\\*" OR file_path="*\\\\Scripts\\*"\n| stats values(file_hash) as hashes by file_name, user, host'
        ],
        "hunt_steps": [
            "Review anti-virus logs for previously detected signatures followed by modified variants.",
            "Check for small deltas in file hashes of known tools after detection alerts.",
            "Hunt for tool re-use by examining TTPs rather than exact file matches."
        ],
        "expected_outcomes": [
            "Detection of previously detected tool being modified and reused",
            "Linkage between initial alert and follow-up undetected activity",
            "Reduction of over-reliance on static signature detection"
        ],
        "false_positive": "Legitimate software updates or recompiled tools may trigger similar alerts. Validate based on context and user behavior.",
        "clearing_steps": [
            "Delete both original and modified versions of tools",
            "Update AV signatures and heuristic detection rules",
            "Investigate persistence and lateral movement attempts stemming from modified tools"
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1027.002", "example": "Repacking of same tool to change binary signature"},
            {"tactic": "Execution", "technique": "T1059", "example": "Modified tool launching payloads via PowerShell"}
        ],
        "watchlist": [
            "Modified file hashes appearing shortly after a tool was quarantined",
            "Re-use of same directory paths for tool deployment",
            "Changes in PowerShell script contents with similar command structure"
        ],
        "enhancements": [
            "Implement YARA rules focused on code structure rather than signatures",
            "Enable file integrity monitoring in high-risk directories",
            "Integrate AV detections with automated sandboxing for behavior correlation"
        ],
        "summary": "This technique involves modifying tools to remove detection indicators such as signatures, enabling adversaries to reuse tools that were previously caught.",
        "remediation": "Enforce behavior-based detection and apply threat intelligence correlation to catch modified tool variants. Conduct post-quarantine analysis to prevent redeployment.",
        "improvements": "Improve telemetry on small binary changes and enhance tooling to detect tool modification behavior. Enable automated re-analysis of redeployed artifacts.",
        "mitre_version": "16.1"
    }
