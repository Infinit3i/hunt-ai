def get_content():
    return {
        "id": "G0129",
        "url_id": "MustangPanda",
        "title": "Mustang Panda",
        "tags": ["china", "espionage", "PlugX", "DLL sideloading", "RedDelta", "TA416", "BRONZE PRESIDENT"],
        "description": (
            "Mustang Panda is a China-based cyber espionage group that has been active since at least 2014, officially tracked from 2017. "
            "Their targets include government agencies, NGOs, religious institutions, and think tanks across the U.S., Europe, and Asia. "
            "Known for their use of customized PlugX malware and extensive phishing operations, Mustang Panda has demonstrated persistent, targeted operations "
            "often leveraging strategic web infrastructure and signed binaries for DLL sideloading."
        ),
        "associated_groups": ["TA416", "RedDelta", "BRONZE PRESIDENT"],
        "campaigns": ["C0047"],
        "techniques": [
            "T1583.001", "T1071.001", "T1560.001", "T1560.003", "T1119", "T1547.001",
            "T1059.001", "T1059.003", "T1059.005", "T1074.001", "T1573.001", "T1585.002",
            "T1546.003", "T1480", "T1052.001", "T1203", "T1083", "T1564.001", "T1574.001",
            "T1070.004", "T1105", "T1036.004", "T1036.005", "T1036.007", "T1095", "T1027",
            "T1027.013", "T1027.016", "T1588.004", "T1003.003", "T1566.001", "T1566.002",
            "T1598.003", "T1057", "T1090", "T1219.002", "T1091", "T1053.005", "T1518",
            "T1608", "T1608.001", "T1553.002", "T1218.004", "T1218.005", "T1218.007",
            "T1218.014", "T1082", "T1016", "T1049", "T1204.001", "T1204.002", "T1102",
            "T1047"
        ],
        "contributors": ["Kyaw Pyiyt Htet, @KyawPyiytHtet"],
        "version": "2.1",
        "created": "12 April 2021",
        "last_modified": "16 April 2025",
        "navigator": "",
        "references": [
            {"source": "CrowdStrike", "url": "https://www.crowdstrike.com/blog/mustang-panda-adversary-profile/"},
            {"source": "Anomali", "url": "https://www.anomali.com/blog/china-based-apt-mustang-panda-targets-minority-groups"},
            {"source": "CTU", "url": "https://www.secureworks.com/research/bronze-president-targets-ngos"},
            {"source": "Proofpoint", "url": "https://www.proofpoint.com/us/blog/threat-insight/ta416-goes-ground-returns-golang-plugx"},
            {"source": "Recorded Future", "url": "https://www.recordedfuture.com/reddelta-targets-vatican"},
            {"source": "Recorded Future", "url": "https://www.recordedfuture.com/ta416-operational-tempo-ukraine"}
        ],
        "resources": [],
        "remediation": (
            "Enforce signed binary policies, monitor use of uncommon installers like MMC, Msiexec, and InstallUtil. "
            "Deploy behavioral detections for DLL sideloading and archive-based payload delivery."
        ),
        "improvements": (
            "Implement DNS and HTTP anomaly-based detection, geo-based download policy enforcement, "
            "and strict email attachment filtering with sandbox detonation."
        ),
        "hunt_steps": [
            "Look for hidden directories (e.g., RECYCLE.BIN) containing executables or archives on USB devices.",
            "Trace InstallUtil and MMC usage tied to LNK or MSC file execution.",
            "Flag DLLs loaded by OneNote Update or other suspiciously named services."
        ],
        "expected_outcomes": [
            "Detection of PlugX or ORat payloads via DLL sideloading.",
            "Discovery of phishing activity with Cloudflare-based C2 or SMTP2Go links.",
            "Recovery of staged credential dumps or encrypted documents."
        ],
        "false_positive": (
            "InstallUtil.exe and Msiexec.exe are common administrative tools. Validate usage context and command-line arguments before triggering alerts."
        ),
        "clearing_steps": [
            "Delete malicious scheduled tasks and registry run keys.",
            "Terminate PlugX-related payloads and associated parent processes.",
            "Rotate domain controller credentials if NTDS.dit compromise suspected."
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": []
        }
    }
