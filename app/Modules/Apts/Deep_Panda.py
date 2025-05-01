def get_content():
    return {
        "id": "G0009",
        "url_id": "Deep_Panda",
        "title": "Deep Panda",
        "tags": ["chinese", "state-sponsored", "espionage", "anthem", "shell-crew", "web-shell", "powerful-malware"],
        "description": "Deep Panda is a suspected Chinese cyber espionage group known for targeting a wide range of industries, including government, defense, healthcare, finance, and telecommunications. Notably linked to the 2015 Anthem breach, the group operates under multiple aliases such as Shell Crew, WebMasters, KungFu Kittens, and Black Vine, and is known to use sophisticated malware like Derusbi and Sakula.",
        "associated_groups": ["Shell Crew", "WebMasters", "KungFu Kittens", "PinkPanther", "Black Vine"],
        "campaigns": [],
        "techniques": [
            "T1059.001", "T1546.008", "T1564.003", "T1027.005", "T1057",
            "T1021.002", "T1018", "T1505.003", "T1218.010", "T1047"
        ],
        "contributors": ["Andrew Smith", "@jakx_"],
        "version": "1.2",
        "created": "31 May 2017",
        "last_modified": "16 April 2025",
        "navigator": "",
        "references": [
            {"source": "Alperovitch, D.", "url": "https://www.crowdstrike.com/blog/deep-in-thought-chinese-targeting-of-national-security-think-tanks/"},
            {"source": "ThreatConnect", "url": "https://www.threatconnect.com/blog/anthem-hack-all-roads-lead-to-china/"},
            {"source": "RSA Incident Response", "url": "https://www.rsa.com/content/dam/en/white-paper/incident-response-emerging-threat-profile-shell-crew.pdf"},
            {"source": "FireEye (Black Vine)", "url": "https://www.fireeye.com/blog/threat-research/2015/08/the_black_vine_cybe.html"},
            {"source": "ICIT", "url": "https://icitech.org/wp-content/uploads/2016/07/China-Espionage-Dynasty.pdf"},
            {"source": "RYANJ", "url": "https://www.fireeye.com/blog/threat-research/2014/02/deep-panda-web-shells.html"},
            {"source": "Cylance SPEAR Team", "url": "https://threatvector.cylance.com/en_us/home/shell-crew-variants-continue-to-fly-under-big-avs-radar.html"}
        ],
        "resources": ["Sakula and Derusbi malware reports", "Anthem breach forensic timeline"],
        "remediation": "Segment internal systems to limit lateral movement. Disable accessibility features for non-admin users. Monitor for regsvr32 misuse and use of PowerShell with hidden windows.",
        "improvements": "Deploy behavior-based detection for malware that evades by modifying its indicators (hashes, names). Harden remote access paths and SMB shares with strong authentication.",
        "hunt_steps": [
            "Detect use of regsvr32.exe in unusual execution chains.",
            "Search for PowerShell usage with `-w hidden` or `-WindowStyle Hidden`.",
            "Look for unauthorized additions to Windows accessibility binaries.",
            "Review logs for `net use` commands indicating unauthorized SMB share access.",
            "Correlate process listings from Tasklist or WMI for enumeration and lateral movement."
        ],
        "expected_outcomes": [
            "Identification of stealthy malware loading via regsvr32 or web shells.",
            "Detection of credential reuse across SMB shares.",
            "Exposure of obfuscated PowerShell and evasion behaviors.",
            "Mapping of initial access to high-value lateral movements using WMI and shares."
        ],
        "false_positive": "Administrative tools like `net.exe` or `tasklist.exe` may be used legitimately. Verify execution context, parent processes, and lateral behavior.",
        "clearing_steps": [
            "Remove persistence mechanisms such as modified accessibility tools.",
            "Terminate web shells and monitor access logs of internet-facing services.",
            "Revoke any compromised credentials and rotate sensitive account passwords.",
            "Audit internal remote connections and isolate affected subnets for cleanup."
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": []
        }
    }
