# dj wip
def get_content():
    return {
        "id": "APT3",  # APT name
        "url_id": "apt3",  # URL segment APT name all lowercase with _ for spaces
        "title": "APT3 (Gothic Panda)",  # Name of the APT group
        "tags": ["state-sponsored", "Chinese", "cyber espionage"],  # Tags associated with the group
        "description": "APT3, also known as Gothic Panda, is a Chinese state-sponsored cyber espionage group attributed to China’s Ministry of State Security (MSS). The group is known for its advanced exploits and zero-day vulnerabilities, primarily targeting aerospace, defense, and technology sectors.",  # Overview/description of the APT group
        "associated_groups": ["Buckeye"],  # Other groups associated with this APT
        "campaigns": [  # Campaigns attributed to this APT
            {
                "id": "C0091",  # Campaign ID
                "name": "Operation Clandestine Fox",  # Campaign name
                "first_seen": "2014",  # First seen date
                "last_seen": "2016",  # Last seen date
                "references": [
                    "https://attack.mitre.org/groups/G0022/",
                    "https://www.fireeye.com/blog/threat-research/2014/04/cve-2014-1776-used-in-targeted-attacks.html"
                ]  # List of references
            }
        ],
        "techniques": ["T1060", "T1203", "T1086", "T1133", "T1210"],  # List of techniques employed by this APT group
        "contributors": ["MITRE", "FireEye", "NSA"],  # Contributors of the intel
        "version": "1.0",  # Version of this APT entry
        "created": "20 March 2025",  # Date when this entry was created
        "last_modified": "20 March 2025",  # Date when this entry was last modified
        "references": [  # References and source documents
            {"source": "MITRE ATT&CK", "url": "https://attack.mitre.org/groups/G0022/"},
            {"source": "FireEye", "url": "https://www.fireeye.com/blog/threat-research/2014/04/cve-2014-1776-used-in-targeted-attacks.html"}
        ],
        "resources": ["https://attack.mitre.org/groups/G0022/", "https://www.fireeye.com/blog/threat-research/2014/04/cve-2014-1776-used-in-targeted-attacks.html"],  # Additional resources
        "remediation": "Apply patches for known vulnerabilities, restrict RDP access, and deploy network segmentation.",  # Recommended actions to mitigate risks
        "improvements": "Enhance endpoint monitoring, deploy threat intelligence feeds, and conduct regular penetration testing.",  # Suggestions for detection and response
        "hunt_steps": ["Analyze exploit delivery mechanisms in network logs", "Monitor for unauthorized use of remote access tools"],  # Proactive threat hunting steps
        "expected_outcomes": ["Detection of zero-day exploit attempts", "Identification of lateral movement within the network"],  # Expected outcomes
        "false_positive": "Legitimate penetration testing activity may resemble APT3’s techniques. Correlate logs to rule out authorized testing.",  # Known false positives
        "clearing_steps": ["Block associated C2 IPs and domains, revoke compromised credentials, and update intrusion detection signatures."],  # Steps for remediation
        "ioc": {  # Indicators of Compromise (IOCs)
            "sha256": [""],  # Example SHA256 hash values
            "md5": [""],  # Example MD5 hash values
            "ip": ["", ""],  # Example IP addresses
            "domain": ["", ""],  # Example domains
            "resources": ["", ""]  # Additional resources or references for IOCs
        }
    }
