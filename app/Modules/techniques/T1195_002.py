def get_content():
    return {
        "id": "T1195.002",
        "url_id": "T1195/002",
        "title": "Supply Chain Compromise: Compromise Software Supply Chain",
        "description": "Adversaries may manipulate application software prior to receipt by a final consumer for the purpose of data or system compromise. Supply chain compromise of software can take place in a number of ways, including manipulation of the application source code, manipulation of the update/distribution mechanism for that software, or replacing compiled releases with a modified version. Targeting may be specific to a desired victim set or may be distributed to a broad set of consumers but only move on to additional tactics on specific victims.",
        "tags": ["supply chain", "initial access", "software tampering", "distribution compromise", "build system"],
        "tactic": "Initial Access",
        "protocol": "",
        "os": "Linux, Windows, macOS",
        "tips": [
            "Use code signing and validate binaries during installation.",
            "Secure update mechanisms and monitor version integrity.",
            "Restrict access to source code and build systems."
        ],
        "data_sources": "File",
        "log_sources": [
            {"type": "File", "source": "", "destination": ""}
        ],
        "source_artifacts": [],
        "destination_artifacts": [],
        "detection_methods": [
            "Hash comparison of installed binaries with known good versions.",
            "Behavioral analysis of applications after update or install.",
            "Audit logs from update servers or build pipelines."
        ],
        "apt": ["APT41", "Evasive Panda", "FIN7", "Iron Tiger", "Moonstone Sleet", "SolarWinds attackers", "REvil", "GOLD SOUTHFIELD", "GANDCRAB", "GRU Unit 74455", "Berserk Bear"],
        "spl_query": [
            "index=software_updates sourcetype=install_logs \n| search file_signature_invalid=true \n| stats count by file_name, version, hash"
        ],
        "hunt_steps": [
            "Check software update logs for unexpected version changes.",
            "Scan for unsigned executables in critical paths.",
            "Cross-check installed software hashes with vendor hash repositories."
        ],
        "expected_outcomes": [
            "Identification of software modified during distribution.",
            "Awareness of compromise via altered update mechanism."
        ],
        "false_positive": "Custom software builds or unsigned legacy software may trigger alerts.",
        "clearing_steps": [
            "Reinstall trusted software versions from verified sources.",
            "Invalidate compromised signing certificates if applicable.",
            "Review entire software supply path."
        ],
        "clearing_playbook": [
            "https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-supply-chain"
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1036", "example": "Modified software appears legitimate via mimicry or naming conventions."}
        ],
        "watchlist": [
            "Unexpected update activity outside regular patch cycles",
            "Execution of recently updated unsigned binaries"
        ],
        "enhancements": [
            "Use secure boot and verified platform firmware.",
            "Implement reproducible builds and source-to-binary traceability."
        ],
        "summary": "Supply chain software compromise injects malicious changes during distribution, build, or update processes to gain system access.",
        "remediation": "Enforce strong controls on distribution and update infrastructure, verify binary integrity, and monitor update activities.",
        "improvements": "Adopt SBOM practices, protect build infrastructure, and ensure end-to-end software verification.",
        "mitre_version": "16.1"
    }
