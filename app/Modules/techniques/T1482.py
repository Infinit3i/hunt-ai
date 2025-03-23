def get_content():
    return {
        "id": "T1482",
        "url_id": "T1482",
        "title": "Domain Trust Discovery",
        "description": "Adversaries may attempt to gather information on domain trust relationships that may be used to identify lateral movement opportunities in Windows multi-domain/forest environments.",
        "tags": ["t1482", "domain trust discovery", "discovery", "windows"],
        "tactic": "Discovery",
        "protocol": "Windows",
        "os": "Windows",
        "tips": [
            "Monitor for nltest command-line execution with /domain_trusts parameter.",
            "Alert on usage of uncommon .NET methods like GetAllTrustRelationships().",
            "Review process API calls to DSEnumerateDomainTrusts for signs of automated trust enumeration."
        ],
        "data_sources": "Command: Command Execution, Network Traffic: Network Traffic Content, Process: OS API Execution, Process: Process Creation, Script: Script Execution",
        "log_sources": [
            {"type": "Process", "source": "nltest", "destination": "SIEM"},
            {"type": "API", "source": "DSEnumerateDomainTrusts", "destination": "EDR"}
        ],
        "source_artifacts": [
            {"type": "Process", "location": "nltest /domain_trusts", "identify": "Enumerate Domain Trusts via CLI"},
            {"type": "API Call", "location": "DSEnumerateDomainTrusts", "identify": "Win32 API trust discovery"}
        ],
        "destination_artifacts": [],
        "detection_methods": [
            "Monitor nltest execution with trust-related switches.",
            "Track .NET trust enumeration functions.",
            "Detect scripts or API calls that enumerate trust relationships."
        ],
        "apt": ["FIN6", "FIN8", "APT41", "Ryuk", "Bumblebee", "SocGholish"],
        "spl_query": [
            "index=process_creation command_line=\"*nltest* /domain_trusts\"",
            "index=script_logs script_content=\"*GetAllTrustRelationships*\""
        ],
        "hunt_steps": [
            "Identify systems where nltest has been executed.",
            "Correlate use of nltest or DSEnumerateDomainTrusts with login events."
        ],
        "expected_outcomes": [
            "Detect enumeration of trust relationships for lateral movement planning."
        ],
        "false_positive": "Legitimate administrators may enumerate domain trusts during diagnostics or setup.",
        "clearing_steps": [
            "Restrict access to nltest and auditing domain enumeration API usage."
        ],
        "mitre_mapping": [
            {"tactic": "Discovery", "technique": "T1482", "example": "Using nltest or DSEnumerateDomainTrusts to enumerate trusts"}
        ],
        "watchlist": [
            "Monitor domain controller logs for enumeration of trusts.",
            "Watch for new scripts or binaries calling GetAllTrustRelationships."
        ],
        "enhancements": [
            "Enable command-line logging for nltest.",
            "Use endpoint telemetry to catch trust-related API usage."
        ],
        "summary": "Adversaries may enumerate domain trust relationships to find paths for lateral movement across domains.",
        "remediation": "Limit use of domain enumeration tools and monitor trust-related API calls.",
        "improvements": "Improve monitoring around domain trust enumeration techniques, especially via scripting or command-line tools."
    }
