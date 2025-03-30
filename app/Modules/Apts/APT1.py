#dj wip
def get_content():
    return {
        "id": "APT-C-36",  # APT name
        "url_id": "apt_c_36",  # URL segment APT name all lowercase with _ for spaces
        "title": "APT-C-36 (Blind Eagle)",  # Name of the APT group
        "tags": ["cybercriminal", "South American", "cyber espionage", "financial fraud"],  # Tags associated with the group
        "description": "APT-C-36, also known as Blind Eagle, is a cybercriminal group primarily operating in South America, targeting financial institutions, government agencies, and private sector organizations. The group is known for spear-phishing attacks and the use of remote access trojans (RATs) to conduct espionage and financial fraud.",  # Overview/description of the APT group
        "associated_groups": ["Mispadu", "Guildma"],  # Other groups associated with this APT
        "campaigns": [  # Campaigns attributed to this APT
            {
                "id": "C0255",  # Campaign ID
                "name": "Banking and Government Targeted Attacks",  # Campaign name
                "first_seen": "2018",  # First seen date
                "last_seen": "2025",  # Last seen date
                "references": [
                    "https://attack.mitre.org/groups/G0099/",
                    "https://www.trendmicro.com/en_us/research/21/h/blind-eagle-targets-colombia-in-latest-cybercrime-attacks.html"
                ]  # List of references
            }
        ],
        "techniques": ["T1566", "T1204", "T1105", "T1071", "T1059"],  # List of techniques employed by this APT group
        "contributors": ["MITRE", "Trend Micro", "CISA"],  # Contributors of the intel
        "version": "1.0",  # Version of this APT entry
        "created": "30 March 2024",  # Date when this entry was created
        "last_modified": "20 March 2025",  # Date when this entry was last modified
        "references": [  # References and source documents
            {"source": "MITRE ATT&CK", "url": "https://attack.mitre.org/groups/G0099/"},
            {"source": "Trend Micro", "url": "https://www.trendmicro.com/en_us/research/21/h/blind-eagle-targets-colombia-in-latest-cybercrime-attacks.html"}
        ],
        "resources": ["https://attack.mitre.org/groups/G0099/", "https://www.trendmicro.com/en_us/research/21/h/blind-eagle-targets-colombia-in-latest-cybercrime-attacks.html"],  # Additional resources
        "remediation": "Deploy anti-phishing solutions, strengthen banking security protocols, and implement endpoint protection measures.",  # Recommended actions to mitigate risks
        "improvements": "Enhance financial transaction monitoring, enforce multi-factor authentication (MFA), and conduct regular employee cybersecurity awareness training.",  # Suggestions for detection and response
        "hunt_steps": ["Monitor email logs for spear-phishing attempts", "Analyze network traffic for command-and-control (C2) connections to known malicious servers"],  # Proactive threat hunting steps
        "expected_outcomes": ["Detection of phishing campaigns targeting financial institutions", "Identification of remote access trojan (RAT) infections"],  # Expected outcomes
        "false_positive": "Legitimate remote banking access and email marketing campaigns may generate alerts. Verify sender legitimacy and intent.",  # Known false positives
        "clearing_steps": ["Isolate infected machines, remove malicious payloads, and block known malicious IP addresses and domains.", "Conduct forensic analysis of compromised systems to determine the extent of data exfiltration."],  # Steps for remediation
        "ioc": {  # Indicators of Compromise (IOCs)
            "sha256": [""],  # Example SHA256 hash values
            "md5": [""],  # Example MD5 hash values
            "ip": ["", ""],  # Example IP addresses
            "domain": ["", ""],  # Example domains
            "resources": ["", ""]  # Additional resources or references for IOCs
        }
    }
