def get_content():
    return {
        "id": "G0136",
        "url_id": "IndigoZebra",
        "title": "IndigoZebra",
        "tags": ["espionage", "China", "Central Asia", "Dropbox", "APT", "2014+"],
        "description": (
            "IndigoZebra is a suspected Chinese cyber espionage group active since at least 2014. The group has focused "
            "on targeting Central Asian governments, leveraging phishing techniques, compromised infrastructure, and "
            "open-source tooling to deliver malware and maintain access to victim networks. Their operations have included "
            "the use of legitimate cloud platforms like Dropbox for command and control."
        ),
        "associated_groups": [],
        "campaigns": [],
        "techniques": [
            "T1583.001", "T1583.006", "T1586.002", "T1105", "T1588.002", "T1566.001", "T1204.002"
        ],
        "contributors": [
            "Pooja Natarajan, NEC Corporation India",
            "Yoshihiro Kori, NEC Corporation",
            "Manikantan Srinivasan, NEC Corporation India"
        ],
        "version": "1.0",
        "created": "24 September 2021",
        "last_modified": "16 April 2025",
        "navigator": "",
        "references": [
            {"source": "The Hacker News", "url": "https://thehackernews.com/2021/07/indigozebra-apt-hacking-campaign.html"},
            {"source": "Check Point Research", "url": "https://research.checkpoint.com/2021/indigozebra-apt-continues-to-attack-central-asia-with-evolving-tools/"},
            {"source": "Kaspersky GReAT", "url": "https://securelist.com/apt-trends-report-q2-2017/79005/"}
        ],
        "resources": [],
        "remediation": (
            "Educate users to avoid interacting with suspicious password-protected attachments. Monitor cloud storage services "
            "like Dropbox for unusual activity, and block untrusted domains that mimic official government infrastructure. "
            "Implement multi-factor authentication (MFA) on email accounts and restrict execution of unknown executable files."
        ),
        "improvements": (
            "Enhance email filtering to detect spearphishing with password-protected RAR attachments. Deploy behavior analytics "
            "to detect abnormal use of cloud storage APIs. Monitor for open-source tool activity such as Meterpreter and NBTscan "
            "in sensitive segments."
        ),
        "hunt_steps": [
            "Search for unusual Dropbox usage patterns across endpoints and outbound connections.",
            "Look for indicators of password-protected archive extraction followed by executable launches.",
            "Query for known NBTscan and Meterpreter behavior and signatures.",
            "Investigate abnormal usage of legitimate email accounts across regions or time zones."
        ],
        "expected_outcomes": [
            "Detection of spearphishing emails and credential misuse.",
            "Identification of data exfiltration to Dropbox or other web services.",
            "Discovery of open-source tool deployments for network reconnaissance."
        ],
        "false_positive": (
            "Legitimate usage of Dropbox and password-protected RAR files may occur in business operations. Validate with context "
            "like sender reputation, timing, and post-execution activity."
        ),
        "clearing_steps": [
            "Revoke access to compromised email accounts and reset associated credentials.",
            "Block malicious infrastructure domains and Dropbox accounts identified in C2 communications.",
            "Remove any malware artifacts and persistence mechanisms from infected systems."
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": []
        }
    }
