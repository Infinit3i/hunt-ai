def get_content():
    return {
        "id": "T1553.002",
        "url_id": "T1553/002",
        "title": "Subvert Trust Controls: Code Signing",
        "description": "Adversaries may create, acquire, or steal code signing materials to sign their malware or tools. Code signing provides a level of authenticity on a binary from the developer and a guarantee that the binary has not been tampered with.",
        "tags": ["Windows", "macOS", "Code Signing", "Defense Evasion"],
        "tactic": "Defense Evasion",
        "protocol": "",
        "os": "Windows, macOS",
        "tips": [
            "Collect and analyze signing certificate metadata on software executions.",
            "Flag certificates with unusual attributes or unknown issuers.",
            "Correlate signed binaries with expected certificate usage."
        ],
        "data_sources": "File: File Metadata",
        "log_sources": [
            {"type": "File", "source": "", "destination": ""}
        ],
        "source_artifacts": [],
        "destination_artifacts": [],
        "detection_methods": [
            "Certificate metadata analysis",
            "Binary integrity checks",
            "Endpoint behavior correlation with certificate use"
        ],
        "apt": [
            "HermeticWiper",
            "Iron Tiger",
            "APT10",
            "APT41",
            "Lazarus",
            "Scattered Spider",
            "Winnti",
            "Ryuk",
            "Macma",
            "Lockergoga",
            "Metamorfo",
            "Black Basta",
            "Kimsuky",
            "BLINDINGCAN",
            "AppleJeus",
            "FIN7",
            "Darkhotel",
            "Wilted Tulip",
            "TA505",
            "Silence",
            "Cobalt Strike",
            "Nerex",
            "PipeMon",
            "RTM",
            "EvasivePanda",
            "LuminousMoth",
            "GreyEnergy",
            "Turla",
            "BackConfig",
            "MosesStaff",
            "StrongPity",
            "DriveSlayer",
            "Bandook",
            "CARBANAK",
            "menuPass",
            "Operation Molerats",
            "Anchor",
            "ROADSWEEP",
            "Tick",
            "GALLIUM",
            "Clop",
            "OilRig"
        ],
        "spl_query": [
            "index=endpoint_logs sourcetype=code_integrity eventType=SignatureVerification\n| search certificate_status=valid"
        ],
        "hunt_steps": [
            "Scan environment for newly introduced signed binaries.",
            "Compare signer identity with known vendors.",
            "Validate timestamp and issuer against trusted authorities."
        ],
        "expected_outcomes": [
            "Detection of malware signed with valid but suspicious certificates",
            "Identification of abuse of code signing policies"
        ],
        "false_positive": "Some legitimate tools may use self-signed or newly issued certificates. Validation against a trusted issuer list is recommended.",
        "clearing_steps": [
            "Revoke compromised certificates via the issuing authority.",
            "Remove or quarantine the signed malware binary.",
            "Review system trust stores for untrusted issuers."
        ],
        "clearing_playbook": [
            "https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-phishing"
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1036.001", "example": "Using valid signatures to mimic legitimate tools."}
        ],
        "watchlist": [
            "Newly introduced signed binaries",
            "Signed binaries from unexpected issuers",
            "Repeated signing by the same uncommon certificate"
        ],
        "enhancements": [
            "Deploy certificate reputation scoring",
            "Integrate with CT logs and certificate transparency feeds"
        ],
        "summary": "Code signing can be subverted by adversaries using stolen or fraudulent certificates to legitimize malware. This bypasses common defenses that rely on verifying the authenticity of software publishers.",
        "remediation": "Monitor signing activity, enforce trusted signer policies, and validate certificate chains regularly.",
        "improvements": "Add telemetry around signature verification failures and new certificate observations.",
        "mitre_version": "16.1"
    }
