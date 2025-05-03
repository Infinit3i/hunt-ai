def get_content():
    return {
        "id": "G0061",
        "url_id": "FIN8",
        "title": "FIN8",
        "tags": ["financial", "pos", "ransomware", "hospitality", "lateral movement"],
        "description": "FIN8 is a financially motivated threat group active since at least January 2016. It is known for targeting organizations in the hospitality, retail, entertainment, and financial sectors. Originally focused on point-of-sale (POS) devices, FIN8 later evolved to distribute various ransomware variants including Ragnar Locker and White Rabbit, as well as deploying sophisticated backdoors such as BADHATCH and Sardonic.",
        "associated_groups": ["Syssphinx"],
        "campaigns": [],
        "techniques": [
            "T1134.001", "T1071.001", "T1560.001", "T1059.001", "T1059.003", "T1486", "T1074.002",
            "T1482", "T1573.002", "T1546.003", "T1048.003", "T1068", "T1070.001", "T1070.004",
            "T1105", "T1112", "T1027.010", "T1588.002", "T1588.003", "T1003.001", "T1566.001",
            "T1566.002", "T1055.004", "T1021.001", "T1021.002", "T1018", "T1053.005", "T1518.001",
            "T1082", "T1016.001", "T1033", "T1204.001", "T1204.002", "T1078", "T1102", "T1047"
        ],
        "contributors": ["Daniyal Naeem, BT Security", "Serhii Melnyk, Trustwave SpiderLabs"],
        "version": "2.0",
        "created": "18 April 2018",
        "last_modified": "16 April 2025",
        "navigator": "",
        "references": [
            {"source": "Symantec", "url": "https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/fin8-sardonic-noberus-ransomware"},
            {"source": "Trustwave", "url": "https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/deep-dive-into-a-fin8-attack-a-forensic-investigation/"},
            {"source": "Bitdefender", "url": "https://www.bitdefender.com/blog/labs/fin8-threat-actor-goes-agile-with-new-sardonic-backdoor/"},
            {"source": "FireEye", "url": "https://www.fireeye.com/blog/threat-research/2016/05/threat-actor-leverages-windows-zero-day.html"}
        ],
        "resources": [],
        "remediation": "Disable macros in Office documents, restrict PowerShell and WMI usage through GPO, segment POS and internal networks, monitor outbound FTP and tunneling behavior, and enforce credential hygiene.",
        "improvements": "Improve monitoring for scheduled tasks, registry modifications, and suspicious PowerShell activity. Enrich detections around Impacket, WMI-based persistence, and known tunneling tools like Plink.",
        "hunt_steps": [
            "Look for nltest, dsquery, and Impacket usage across hosts.",
            "Trace creation and deletion of prefetch/tmp files or suspicious scheduled tasks.",
            "Identify use of WMIC or unusual PowerShell command-line arguments linked to C2 activity."
        ],
        "expected_outcomes": [
            "Discovery of lateral movement using Impacket and SMB shares.",
            "Detection of data staging and exfiltration via FTP or RAR.",
            "Uncovering registry and WMI-based persistence methods."
        ],
        "false_positive": "PowerShell and WMI usage may be legitimate in administrative tasks. Review context and execution patterns before escalating.",
        "clearing_steps": [
            "Disable and delete scheduled tasks and WMI event subscriptions.",
            "Purge downloaded payloads and reverse Impacket/SMB tools.",
            "Clear suspicious registry entries and audit remote access activity.",
            "Reimage compromised endpoints if credential theft is confirmed."
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": []
        }
    }
