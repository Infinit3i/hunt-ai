# Use this template and fill in the content to add a new technique to its own file

def get_content():
    return {
        "id": "",  # Tactic Technique ID (e.g., T1556.001)
        "url_id": "",  # URL segment for technique reference (e.g., T1556/001)
        "title": "",  # Name of the attack technique
        "description": "",  # only use one pair of "" with a simple Description of the attack technique
        "tags": [],  # Tags associated with the technique
        "tactic": "",  # Associated MITRE ATT&CK tactic
        "protocol": "",  # Protocol used in the attack technique
        "os": "",  # Targeted operating systems
        "tips": [],  # Additional investigation and mitigation tips
        "data_sources": "",  # Windows Security, Windows Powershell, Windows Application, Windows System, Sysmon, Zeek, Suricata, Active Directory, Application Log, Application Vetting, Asset, Certificate, Cloud Service, Cloud Storage, Command, Container, Domain Name, Drive, Driver, File, Firewall, Firmware, Group, Image, Instance, Internet Scan, Kernel, Logon Session, Malware Repository, Module, Named Pipe, Network Share, Network Traffic, Operational Databases, Persona, Pod, Process, Scheduled Job, Script, Sensor Health, Service, Snapshot, User Account, User Interface, Volume, Web Credential, Windows Registry, WMI
        "log_sources": [  # Logs necessary for detection the type should be the same as data sources
            {"type": "", "source": "", "destination": ""} # Windows Security, Windows Powershell, Windows Application, Windows System, Sysmon, Zeek, Suricata, Active Directory, Application Log, Application Vetting, Asset, Certificate, Cloud Service, Cloud Storage, Command, Container, Domain Name, Drive, Driver, File, Firewall, Firmware, Group, Image, Instance, Internet Scan, Kernel, Logon Session, Malware Repository, Module, Named Pipe, Network Share, Network Traffic, Operational Databases, Persona, Pod, Process, Scheduled Job, Script, Sensor Health, Service, Snapshot, User Account, User Interface, Volume, Web Credential, Windows Registry, WMI, 
        ],
        "source_artifacts": [  # Artifacts generated on the source machine - like Amcache, AppCompatCache (ShimCache), ARP Cache, Bash History, BitLocker Recovery Keys, Browser History, Clipboard Data, DNS Cache, Environment Variables, Event Logs, File Access Times (MACB Timestamps), Jump Lists, Link Files (.lnk), Loaded DLLs, Memory Dumps, MFT (Master File Table), Network Connections, Prefetch Files, Process List, Recent Files, Registry Hives (NTUSER.DAT, SYSTEM, SOFTWARE, etc.), RunMRU, Scheduled Tasks, Services, Shellbags, SRUM (System Resource Usage Monitor), Startup Folder Contents, Superfetch, Sysmon Logs, Taskbar Pins, UserAssist, USN Journal, WMI Persistence, Windows Defender Logs, Windows Error Reporting (WER), Windows Search History, Windows Timeline, WLAN Profiles, WordWheelQuery, URL History (TypedURLs, TypedPaths)
            {"type": "", "location": "", "identify": ""}
        ],
        "destination_artifacts": [  # Artifacts generated on the destination machine - like Amcache, AppCompatCache (ShimCache), ARP Cache, Bash History, BitLocker Recovery Keys, Browser History, Clipboard Data, DNS Cache, Environment Variables, Event Logs, File Access Times (MACB Timestamps), Jump Lists, Link Files (.lnk), Loaded DLLs, Memory Dumps, MFT (Master File Table), Network Connections, Prefetch Files, Process List, Recent Files, Registry Hives (NTUSER.DAT, SYSTEM, SOFTWARE, etc.), RunMRU, Scheduled Tasks, Services, Shellbags, SRUM (System Resource Usage Monitor), Startup Folder Contents, Superfetch, Sysmon Logs, Taskbar Pins, UserAssist, USN Journal, WMI Persistence, Windows Defender Logs, Windows Error Reporting (WER), Windows Search History, Windows Timeline, WLAN Profiles, WordWheelQuery, URL History (TypedURLs, TypedPaths)
            {"type": "", "location": "", "identify": ""}
        ],
        "detection_methods": [],  # Techniques for identifying the attack
        "apt": [], # APT groups known to use this technique typically start with G#### (e.g., G0016) - do not show the S#### - show the name of the APT not G####
        "spl_query": [],  # Splunk queries to detect the technique, multiple can be added. for | use \n| - this should be taken literal not putt in on your own
        "hunt_steps": [],  # Steps to proactively hunt for threats
        "expected_outcomes": [],  # Expected results from detection/hunting
        "false_positive": "",  # Known false positives and how to handle them
        "clearing_steps": [],  # Steps for remediation and clearing traces - do commands also on machines locally
        "mitre_mapping": [  # Next Mitre Technique that could be used after this technique
            {"tactic": "", "technique": "", "example": ""}
        ],
        "watchlist": [],  # Indicators to monitor for potential threats
        "enhancements": [],  # Suggested improvements to detection
        "summary": "",  # High-level summary of the technique
        "remediation": "",  # Recommended actions to mitigate risk
        "improvements": "",  # Suggested ways to improve detection and response
        "mitre_version": "16.1"  # MITRE ATT&CK version
    }

