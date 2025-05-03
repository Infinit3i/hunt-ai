def get_content():
    return {
        "id": "G0017",
        "url_id": "DragonOK",
        "title": "DragonOK",
        "tags": ["phishing", "custom malware", "Japan", "Chinese-speaking APT"],
        "description": (
            "DragonOK is a threat group that has primarily targeted Japanese organizations using phishing emails. "
            "The group is believed to have direct or indirect connections with Moafee due to overlapping TTPs and custom toolsets. "
            "DragonOK has deployed various malware families including Sysget/HelloBridge, PlugX, PoisonIvy, FormerFirstRat, NFlog, and NewCT."
        ),
        "associated_groups": ["Moafee"],
        "campaigns": [],
        "techniques": [
            "T1071", "T1071.001", "T1071.004", "T1547.001", "T1059.003", "T1543.003", "T1140", "T1573.001",
            "T1083", "T1564.001", "T1574.001", "T1562.004", "T1105", "T1056.001", "T1036.004", "T1036.003",
            "T1112", "T1106", "T1135", "T1043", "T1571", "T1571", "T1027", "T1057", "T1012", "T1113",
            "T1057", "T1055.001", "T1014", "T1010", "T1547.001", "T1547.009", "T1059.003", "T1543.003",
            "T1005", "T1074.001", "T1573.001", "T1021.001", "T1056.001", "T1112", "T1027", "T1055.001",
            "T1014"
        ],
        "contributors": [],
        "version": "1.0",
        "created": "31 May 2017",
        "last_modified": "17 November 2024",
        "navigator": "",
        "references": [
            {"source": "OPERATION QUANTUM ENTANGLEMENT", "url": "https://example.com/quantum_entanglement"},
            {"source": "Unit 42 - DragonOK Backdoor", "url": "https://example.com/dragonok_backdoor"}
        ],
        "resources": [],
        "remediation": (
            "Implement network segmentation, block execution of known DragonOK malware (PlugX, PoisonIvy, etc.), "
            "monitor for suspicious command-line activity, and apply endpoint detection rules for known TTPs."
        ),
        "improvements": (
            "Enhance monitoring of Windows Registry modifications and Windows Service creations. "
            "Apply stricter email filtering policies and sandbox phishing payloads."
        ),
        "hunt_steps": [
            "Search for known PlugX/PoisonIvy signatures in EDR telemetry.",
            "Hunt for suspicious DLL sideloading behavior indicative of PlugX.",
            "Review logs for anomalous use of MSBuild or cmd.exe tied to registry modifications."
        ],
        "expected_outcomes": [
            "Identification of potential compromise via custom backdoors.",
            "Detection of persistence via modified registry run keys.",
            "Exposure of keylogging or screen capture modules active in memory."
        ],
        "false_positive": (
            "Some use of MSBuild and registry keys may be legitimate—validate with user and system context."
        ),
        "clearing_steps": [
            "Remove malicious services and startup entries.",
            "Delete or quarantine PlugX, PoisonIvy, and related malware artifacts.",
            "Reset credentials and rebuild compromised systems from clean images."
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": []
        }
    }
