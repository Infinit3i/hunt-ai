def get_content():
    return {
        "id": "T1584.001",  # Tactic Technique ID
        "url_id": "1584/001",  # URL segment for technique reference
        "title": "Compromise Infrastructure: Domains",  # Name of the attack technique
        "description": (
            "Adversaries may hijack domains and/or subdomains to facilitate malicious activities. "
            "Domain registration hijacking involves changing the registration of a domain name without the "
            "owner's permission. Adversaries may gain access to the domain owner's email account to reset "
            "registration passwords, leverage social engineering against a domain registrar help desk, "
            "exploit renewal process gaps, or compromise cloud services (e.g., AWS Route53). Subdomain "
            "hijacking can also occur when DNS entries point to deprovisioned or non-existent resources. "
            "Additionally, adversaries may engage in domain shadowing by creating malicious subdomains under "
            "their control, potentially going unnoticed for extended periods."
        ),
        "tags": [
            "domain hijacking",
            "subdomain hijacking",
            "domain shadowing",
            "resource development"
        ],
        "tactic": "Resource Development",  # Associated MITRE ATT&CK tactic
        "protocol": "DNS",  # Protocol (primarily related to domain resolution)
        "os": "N/A",  # Not OS-specific
        "tips": [
            "Monitor for anomalous changes to domain registrant information or domain resolution.",
            "Tailor efforts to domains of high value/interest, as benign changes can be common.",
            "Focus detection efforts on related adversary lifecycle stages, such as Command and Control."
        ],
        "data_sources": "Domain Name",  # Data sources relevant to detection
        "log_sources": [
            {"type": "Domain Name", "source": "Active DNS", "destination": ""},
            {"type": "Domain Name", "source": "Domain Registration", "destination": ""},
            {"type": "Domain Name", "source": "Passive DNS", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "", "location": "", "identify": ""}
        ],
        "destination_artifacts": [
            {"type": "", "location": "", "identify": ""}
        ],
        "detection_methods": [
            "Monitor domain registration changes for unauthorized updates.",
            "Check for newly created or suspicious subdomains pointing to malicious IPs.",
            "Compare domain records over time to identify unexpected changes or anomalies."
        ],
        "apt": [
            "APT1",
            "Lazarus",
            "Charming Kitten",
            "APT43",
            "NOBELIUM",
            "Transparent Tribe",
            "SideCopy",
            "UNC3890",
            "Gold Prelude"
        ],
        "spl_query": [
            "index=dns \n| stats count by query, answer"
        ],
        "hunt_steps": [
            "Enumerate active domains and subdomains; compare with historical records to detect unauthorized changes.",
            "Correlate domain ownership data with email activity to identify potential account compromise.",
            "Look for domains or subdomains that suddenly redirect to unfamiliar IP addresses or hosting providers."
        ],
        "expected_outcomes": [
            "Identification of compromised domain registrations or subdomain takeovers.",
            "Detection of malicious infrastructure leveraged for phishing, C2, or other attacks."
        ],
        "false_positive": (
            "Legitimate domain or subdomain changes may appear suspicious. Validate business context and "
            "intent before concluding malicious activity."
        ),
        "clearing_steps": [
            "Regain control of domain registrar account(s) and reset credentials.",
            "Revert unauthorized DNS or domain registration changes.",
            "Implement domain locks and enable multi-factor authentication (MFA) for registrar accounts.",
            "Monitor for further unauthorized modifications."
        ],
        "mitre_mapping": [
            {
                "tactic": "Resource Development",
                "technique": "Compromise Infrastructure: DNS Server (T1584.002)",
                "example": "Adversaries may pivot to DNS server compromise after hijacking a domain."
            }
        ],
        "watchlist": [
            "Unusual or frequent domain registration updates.",
            "Unexpected subdomains appearing under legitimate domains.",
            "Subdomains pointing to deprecated or non-existent hosting services."
        ],
        "enhancements": [
            "Automate domain and subdomain monitoring; integrate results with threat intelligence feeds.",
            "Use domain privacy and registrar locks to reduce the likelihood of unauthorized changes."
        ],
        "summary": (
            "Adversaries can hijack domain registrations and subdomains to leverage the trust associated "
            "with legitimate domains. By manipulating DNS or registrar settings, they can redirect traffic, "
            "conduct phishing, facilitate command and control, and perform other malicious activities under "
            "the guise of a trusted entity."
        ),
        "remediation": (
            "Secure domain registrar accounts (implement MFA, strong passwords, and registrar locks), "
            "regularly audit domain records, and monitor for newly created or suspicious subdomains. "
            "Ensure proper offboarding of deprovisioned resources to prevent subdomain hijacking."
        ),
        "improvements": (
            "Increase visibility into domain registration and DNS changes via SIEM alerts. "
            "Leverage certificate transparency logs to detect unauthorized certificate requests for hijacked domains."
        )
    }
