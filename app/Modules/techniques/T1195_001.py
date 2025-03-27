def get_content():
    return {
        "id": "T1195.001",
        "url_id": "T1195/001",
        "title": "Supply Chain Compromise: Compromise Software Dependencies and Development Tools",
        "description": "Adversaries may manipulate software dependencies and development tools prior to receipt by a final consumer for the purpose of data or system compromise. Applications often depend on external software to function properly. Popular open source projects that are used as dependencies in many applications may be targeted as a means to add malicious code to users of the dependency. Targeting may be specific to a desired victim set or may be distributed to a broad set of consumers but only move on to additional tactics on specific victims.",
        "tags": ["supply chain", "initial access", "open source", "dependency hijack", "ci/cd compromise"],
        "tactic": "Initial Access",
        "protocol": "",
        "os": "Linux, Windows, macOS",
        "tips": [
            "Verify external dependencies and tools with cryptographic signatures or hashes.",
            "Review sources for critical packages used in build pipelines.",
            "Use dependency checkers for CVEs and compromise indicators."
        ],
        "data_sources": "File",
        "log_sources": [
            {"type": "File", "source": "", "destination": ""}
        ],
        "source_artifacts": [],
        "destination_artifacts": [],
        "detection_methods": [
            "Monitor integrity of dependencies included during builds.",
            "Check downloaded packages against known-good checksums.",
            "Detect execution of unsigned or unexpected developer tools."
        ],
        "apt": [],
        "spl_query": [
            "index=ci_cd_logs sourcetype=build_pipeline \n| search dependency_downloaded=* \n| stats count by dependency_name, hash"
        ],
        "hunt_steps": [
            "Audit software dependencies used in internal and customer-facing apps.",
            "Check build tools and scripts for unauthorized code.",
            "Review supply chain for compromised registries or mirrors."
        ],
        "expected_outcomes": [
            "Detection of manipulated open-source dependencies.",
            "Greater assurance over integrity of CI/CD pipeline."
        ],
        "false_positive": "Custom compiled binaries or non-standard repos may trigger alerts. Verify trust before flagging as compromise.",
        "clearing_steps": [
            "Replace compromised dependencies with trusted versions.",
            "Purge build systems and reset all tokens and secrets used during compromise.",
            "Rebuild affected packages from clean sources."
        ],
        "clearing_playbook": [
            "https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-supply-chain"
        ],
        "mitre_mapping": [
            {"tactic": "Execution", "technique": "T1059", "example": "Injected code in a compromised dependency triggers on software launch."}
        ],
        "watchlist": [
            "Dependencies from unverified GitHub/NPM/PyPI accounts",
            "New build tool usage without code review"
        ],
        "enhancements": [
            "Integrate automated SBOM and supply chain validation tools.",
            "Use allowlisting for packages and developer tools."
        ],
        "summary": "Compromising development tools and software dependencies allows adversaries to introduce malicious functionality early in the software lifecycle.",
        "remediation": "Verify dependencies, scan all third-party code, and implement controls in the CI/CD process.",
        "improvements": "Use reproducible builds, peer-reviewed code commits, and runtime behavioral analysis of dependencies.",
        "mitre_version": "16.1"
    }
