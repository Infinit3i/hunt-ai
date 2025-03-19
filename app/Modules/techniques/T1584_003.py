def get_content():
    return {
        "id": "T1584.003",  # Tactic Technique ID
        "url_id": "1584/003",  # URL segment for technique reference
        "title": "Compromise Infrastructure: Virtual Private Server",  # Name of the attack technique
        "description": (
            "Adversaries may compromise third-party Virtual Private Servers (VPSs) to facilitate malicious "
            "operations. By compromising a VPS owned by another entity, adversaries can leverage existing "
            "infrastructure and make it more difficult to attribute activity to themselves. These compromised "
            "VPSs can be used to host Command and Control (C2) or other malicious services, benefiting from "
            "the trust and ubiquity of reputable cloud service providers as well as the VPS owner’s reputation."
        ),
        "tags": [
            "vps compromise",
            "cloud infrastructure",
            "resource development",
            "command and control"
        ],
        "tactic": "Resource Development",  # Associated MITRE ATT&CK tactic
        "protocol": "Various",  # Protocol used in the attack technique
        "os": "N/A",  # Targeted operating systems
        "tips": [
            "Monitor for anomalous or unauthorized activities within VPS environments.",
            "Use threat intelligence to identify known malicious VPS IP addresses or hosting providers.",
            "Employ SSL/TLS fingerprinting or other scanning techniques to detect suspicious C2 patterns."
        ],
        "data_sources": "Internet Scan",  # Data sources relevant to detection
        "log_sources": [
            {"type": "Internet Scan", "source": "Response Content", "destination": ""},
            {"type": "Internet Scan", "source": "Response Metadata", "destination": ""}
        ],
        "source_artifacts": [
            {
                "type": "Server configuration",
                "location": "Compromised VPS filesystem",
                "identify": "Check for malicious scripts, binaries, or suspicious processes"
            }
        ],
        "destination_artifacts": [
            {
                "type": "Network Traffic",
                "location": "Outbound connections",
                "identify": "Identify suspicious C2 communications or unusual traffic patterns"
            }
        ],
        "detection_methods": [
            "Monitor for unexpected VPS usage or newly created virtual instances that deviate from normal activity.",
            "Analyze network traffic for suspicious SSL/TLS certificates or negotiation patterns.",
            "Correlate known malicious IP addresses/domains with VPS provider IP ranges."
        ],
        "apt": [],
        "spl_query": [
            "index=network \n| stats count by src_ip, dest_ip, ssl_subject, ssl_issuer"
        ],
        "hunt_steps": [
            "Identify and review VPS instances within your environment for abnormal software or processes.",
            "Compare current VPS configurations and certificates against known good baselines.",
            "Correlate VPS traffic with threat intelligence or known malicious infrastructure."
        ],
        "expected_outcomes": [
            "Detection of compromised VPS instances hosting malicious services.",
            "Identification of suspicious SSL/TLS certificates or unusual processes on VPS environments."
        ],
        "false_positive": (
            "Legitimate VPS changes or reconfigurations (e.g., new software installations) may appear "
            "malicious. Validate through change records and administrative logs."
        ),
        "clearing_steps": [
            "Terminate or isolate compromised VPS instances.",
            "Remove malicious software or scripts from the affected VPS environment.",
            "Reset credentials and apply patches/updates to prevent reinfection."
        ],
        "mitre_mapping": [
            {
                "tactic": "Resource Development",
                "technique": "Compromise Infrastructure: Server (T1584.004)",
                "example": "Adversaries may also compromise traditional servers to expand or hide their infrastructure."
            }
        ],
        "watchlist": [
            "Newly provisioned VPS instances with no legitimate business justification.",
            "Unusual inbound/outbound traffic patterns originating from VPS IP ranges.",
            "SSL certificates or negotiation features associated with known adversary C2 frameworks."
        ],
        "enhancements": [
            "Integrate VPS logs with a SIEM to correlate and detect anomalies.",
            "Leverage external scanning services to identify malicious services hosted on compromised VPS instances.",
            "Implement strict access controls and regular audits of cloud credentials."
        ],
        "summary": (
            "Compromising third-party VPSs enables adversaries to mask their operations behind trusted "
            "infrastructure. By leveraging the reputation of the legitimate VPS owner and cloud service providers, "
            "they can reduce the likelihood of detection and complicate attribution."
        ),
        "remediation": (
            "Ensure strong authentication, least-privilege access, and robust monitoring for VPS environments. "
            "Regularly audit usage, patch systems, and verify the integrity of virtual machine images."
        ),
        "improvements": (
            "Adopt continuous vulnerability scanning for VPS infrastructure, employ TLS certificate transparency "
            "monitoring, and integrate threat intelligence for cloud-based indicators of compromise."
        )
    }
