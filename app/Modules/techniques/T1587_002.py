def get_content():
    return {
        "id": "T1587.002",  # Tactic Technique ID
        "url_id": "1587/002",  # URL segment for technique reference
        "title": "Develop Capabilities: Code Signing Certificates",  # Name of the attack technique
        "description": "Adversaries may create self-signed code signing certificates to lend legitimacy to malicious executables or scripts. Code signing provides a level of authenticity, and users/security tools may trust signed code even if the certificate is self-signed.",  # Simple description
        "tags": [
            "Code Signing Certificates",
            "Self-Signed Certificates",
            "Resource Development",
            "ESET EvasivePanda 2024",
            "ESET Lazarus Jun 2020",
            "Bitdefender StrongPity June 2020",
            "Unit 42 BackConfig May 2020",
            "Certificate Authenticity",
            "Code Signing",
            "Malware"
        ],  # Up to 10 tags
        "tactic": "Resource Development",  # Associated MITRE ATT&CK tactic
        "protocol": "Various",  # Protocol used in the attack technique
        "os": "N/A",  # Not OS-specific (PRE-ATT&CK)
        "tips": [
            "Analyze self-signed certificates for suspicious attributes (e.g., thumbprint, validity period)",
            "Use malware repositories to identify additional samples signed by the same certificate",
            "Monitor subsequent usage of these certificates for code signing or root certificate installation"
        ],
        "data_sources": "Malware Repository: Malware Metadata",
        "log_sources": [],  # No direct log sources in the victim environment for certificate creation
        "source_artifacts": [
            {
                "type": "Self-Signed Certificates",
                "location": "Adversary or contractor environment",
                "identify": "Maliciously created certificates for code signing"
            }
        ],
        "destination_artifacts": [
            {
                "type": "Signed Executables/Scripts",
                "location": "Adversary infrastructure or distributed to victims",
                "identify": "Malware signed with self-signed certificates"
            }
        ],
        "detection_methods": [
            "Track certificate metadata (e.g., thumbprint, issuer) in malware repositories",
            "Correlate newly identified code signing certificates with known malicious signatures",
            "Focus on follow-on behaviors such as code signing or root certificate installation"
        ],
        "apt": [
            "Lazarus",
            "StrongPity",
            "EvasivePanda"
        ],
        "spl_query": [],
        "hunt_steps": [
            "Pivot on certificate details (issuer name, thumbprint) across malware samples",
            "Identify patterns in certificate creation or usage by known threat groups",
            "Review newly discovered self-signed certificates in the context of suspicious file signatures"
        ],
        "expected_outcomes": [
            "Increased visibility into adversary development of self-signed certificates",
            "Detection of malicious code signing practices in malware samples",
            "Correlation of certificate usage with specific threat actor toolsets"
        ],
        "false_positive": "Legitimate developers and security researchers may also use self-signed certificates for testing. Validate context and usage scenarios.",
        "clearing_steps": [
            "N/A (Occurs outside victim visibility; clearing steps not typically applicable in victim environment)"
        ],
        "mitre_mapping": [
            {
                "tactic": "Resource Development",
                "technique": "Develop Capabilities: Code Signing Certificates (T1587.002)",
                "example": "Creating self-signed certificates to sign malicious binaries or scripts"
            }
        ],
        "watchlist": [
            "Unusual or repeated usage of self-signed certificates across different malware families",
            "Certificates with mismatched or nonsensical issuer/subject details",
            "Certificate validity periods or cryptographic parameters that deviate from norms"
        ],
        "enhancements": [
            "Leverage certificate transparency services to detect suspicious certificate issuances",
            "Implement threat intelligence correlation to track repeated certificate usage by known adversaries",
            "Use advanced malware analysis pipelines to flag unknown or untrusted certificates in code signatures"
        ],
        "summary": "Adversaries may develop and use self-signed code signing certificates to make their malicious executables appear legitimate, undermining trust-based security measures and enabling stealthy malware distribution.",
        "remediation": "Employ certificate reputation checks, use strong code integrity policies, and monitor for suspiciously signed binaries to mitigate the impact of self-signed certificates.",
        "improvements": "Enhance malware analysis with robust certificate metadata correlation, share intelligence on malicious certificate usage, and adopt code signing best practices to help identify suspicious certificates."
    }
