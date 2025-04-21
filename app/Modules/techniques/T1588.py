def get_content():
    return {
        "id": "T1588",
        "url_id": "T1588",
        "title": "Obtain Capabilities",
        "description": "Adversaries may buy, steal, or download capabilities to use during their operations instead of developing them in-house. These capabilities may include malware, exploits, software tools, digital or code-signing certificates, or vulnerability intelligence. The sourcing of such capabilities may come from open-source repositories, black/gray markets, or through direct compromise of third-party entities. These acquired capabilities may support various stages across the attack lifecycle including initial access, persistence, command and control, and data exfiltration.",
        "tags": ["resource-development", "third-party", "capabilities", "malware", "exploits", "certificates", "MaaS", "C2"],
        "tactic": "Resource Development",
        "protocol": "",
        "os": "Any",
        "tips": [
            "Monitor threat actor campaigns that re-use third-party or previously leaked malware to trace back potential procurement sources.",
            "Analyze metadata in digital certificates, software licenses, and binary files to uncover procurement or reuse patterns.",
            "Pivot on certificate thumbprints and reused C2 infrastructure to map distributed use of obtained capabilities."
        ],
        "data_sources": "Certificate: Certificate Registration, Internet Scan: Response Content, Malware Repository: Malware Content, Malware Repository: Malware Metadata",
        "log_sources": [
            {"type": "Malware Repository", "source": "Malware Content", "destination": ""},
            {"type": "Malware Repository", "source": "Malware Metadata", "destination": ""},
            {"type": "Certificate", "source": "Certificate Registration", "destination": ""},
            {"type": "Internet Scan", "source": "Response Content", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Malware Sample", "location": "Open Source Repo / Underground Forum", "identify": "MaaS loader or backdoor"},
            {"type": "Code Signing Certificate", "location": "Underground market or stolen CA store", "identify": "Signed payload validation"}
        ],
        "destination_artifacts": [
            {"type": "Binary Payload", "location": "Victim system", "identify": "Delivered via phishing or exploit"},
            {"type": "TLS Certificate", "location": "Adversary-controlled server", "identify": "Used to encrypt C2"}
        ],
        "detection_methods": [
            "Passive scanning of known dark web forums and vendor platforms",
            "Certificate transparency log monitoring and fingerprint pivoting",
            "Malware hash correlation across threat actor campaigns"
        ],
        "apt": ["APT1", "APT29", "APT41", "FIN7", "UNC3890", "Metador", "TA505", "Lazarus Group", "OilRig", "Cobalt Group", "Andariel"],
        "spl_query": [
            "index=certificates issuer_common_name!=\"Let's Encrypt\" subject_country!=\"US\"\n| stats count by thumbprint, issuer_common_name",
            "index=malware_repository file_type=\"exe\" tags=\"third-party\"\n| stats count by malware_family, sha256, source"
        ],
        "hunt_steps": [
            "Search for newly obtained code signing or TLS certificates not associated with trusted vendors.",
            "Monitor for reuse of well-known toolkits or previously observed malware loaders.",
            "Hunt for signs of stolen toolsets from security vendors or red teams (e.g., Cobalt Strike, Metasploit)."
        ],
        "expected_outcomes": [
            "Detection of reused malware, exploits, and tools that match adversary signatures",
            "Certificate reuse revealing additional adversary infrastructure",
            "Insight into adversary capabilities procurement trends"
        ],
        "false_positive": "Legitimate red teaming activity or penetration testing operations may use tools or certificates that resemble adversary behavior. Validate actors and tooling origin.",
        "clearing_steps": [
            "Revoke compromised certificates",
            "Blacklist acquired tools and malware indicators in endpoint and network defenses",
            "Block C2 infrastructure linked to purchased or stolen capabilities"
        ],
        "clearing_playbook": ["https://attack.mitre.org/resources/prevention-toolkit/remediation-guidance"],
        "mitre_mapping": [
            {"tactic": "Command and Control", "technique": "T1071", "example": "Use of purchased malware to communicate with infrastructure"},
            {"tactic": "Defense Evasion", "technique": "T1553", "example": "Use of stolen code signing certificates for payload validation"},
            {"tactic": "Execution", "technique": "T1059", "example": "Malware obtained from third-party used for execution chain"}
        ],
        "watchlist": [
            "MaaS payloads reused across actors",
            "Leaked red team tools posted to dark web forums",
            "Dark web markets distributing vulnerability or exploit intelligence"
        ],
        "enhancements": [
            "Develop ML classifiers to correlate certificate thumbprints with previously observed malicious use",
            "Integrate threat intel feeds from marketplaces or forums for early detection of shared capabilities",
            "Build YARA rules for identification of reused toolkits across environments"
        ],
        "summary": "Adversaries streamline their operations by acquiring malware, tools, certificates, or exploits from third-party sources. This lowers cost, increases stealth, and often introduces shared tools across threat actors, complicating attribution while enhancing capability access.",
        "remediation": "Harden acquisition chains, monitor open-source usage, revoke compromised credentials or licenses, and coordinate with certificate authorities or software vendors to mitigate exposure.",
        "improvements": "Introduce proactive monitoring of threat actor procurement behavior via dark web surveillance, honeypots, and sandbox detonations to capture emerging tools and payloads.",
        "mitre_version": "16.1"
    }
