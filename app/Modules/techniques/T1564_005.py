def get_content():
    return {
        "id": "T1564.005",
        "url_id": "T1564/005",
        "title": "Hide Artifacts: Hidden File System",
        "description": "Adversaries may use a hidden file system to conceal malicious activity from users and security tools. These hidden or virtual file systems can reside in reserved disk areas or within standard files as embedded partitions. They may be used to store payloads, logs, or other data structures while evading file-based detection and analysis. Hidden file systems bypass traditional file system enumeration methods and may only be accessed via custom malware routines.",
        "tags": ["virtual file system", "hidden storage", "bootkits", "partition evasion", "ComRAT", "Equation Group"],
        "tactic": "Defense Evasion",
        "protocol": "",
        "os": "Linux, Windows, macOS",
        "tips": [
            "Investigate suspicious partition images or mounted volumes not associated with user activity",
            "Analyze boot sequence for hidden file system loading behavior",
            "Correlate registry access with anomalous file access patterns"
        ],
        "data_sources": "File, Firmware, Windows Registry",
        "log_sources": [
            {"type": "File", "source": "", "destination": ""},
            {"type": "Firmware", "source": "", "destination": ""},
            {"type": "Windows Registry", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "File", "location": "System root or reserved disk sectors", "identify": "File structures that don't appear in the volume MFT"},
            {"type": "Firmware", "location": "UEFI or BIOS area", "identify": "Bootloader manipulation to load virtual FS"},
            {"type": "Registry Hives", "location": "HKLM\\SYSTEM\\CurrentControlSet\\Services", "identify": "References to unmounted volume images or unusual drivers"}
        ],
        "destination_artifacts": [
            {"type": "File", "location": "Mounted partitions or VFS blobs", "identify": "Encrypted or fragmented containers"},
            {"type": "Firmware", "location": "Bootkit drop locations", "identify": "Boot sector changes to support VFS"},
            {"type": "Windows Registry", "location": "Registry boot execution paths", "identify": "Autorun mechanisms loading hidden filesystems"}
        ],
        "detection_methods": [
            "Look for hidden partitions or files with raw disk signatures (e.g., using FTK Imager, EnCase)",
            "Detect unsigned drivers or services used to mount secondary file systems",
            "Audit changes to the boot configuration or firmware that may enable hidden file system loading"
        ],
        "apt": [
            "ComRAT", "Equation Group", "Snake Malware", "ProjectSauron", "Regin"
        ],
        "spl_query": [
            "index=sysmon EventCode=1 \n| search CommandLine=*mount* OR *image* \n| stats count by Image, CommandLine, ParentImage",
            "index=wineventlog EventCode=13 \n| search RegistryPath=*CurrentControlSet\\Services* AND RegistryValueData=*vfs* \n| stats count by RegistryPath, EventID",
            "index=osquery \n| search mount_point!=/mnt/* AND file_path LIKE '%.img' \n| stats count by username, file_path"
        ],
        "hunt_steps": [
            "Inspect the system for virtual file system binaries or partition images",
            "Check boot configuration and firmware for non-standard file access",
            "Analyze registry and file system I/O that bypass traditional storage paths"
        ],
        "expected_outcomes": [
            "Discovery of partition or disk space used by non-native filesystems",
            "Detection of malware writing to hidden or encrypted virtual filesystems",
            "Correlation of hidden FS loading with persistence mechanisms or privilege escalation"
        ],
        "false_positive": "Some virtualization and backup tools may use similar techniques to mount virtual disk images. Validate system context and tool usage before classification.",
        "clearing_steps": [
            "Unmount and securely wipe hidden file systems or partition images",
            "Rebuild bootloader and restore clean firmware images",
            "Remove autorun entries pointing to virtual filesystems from registry"
        ],
        "clearing_playbook": ["https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-phishing"],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1542.003", "example": "Bootkits loading virtual file systems from reserved disk sectors"},
            {"tactic": "Persistence", "technique": "T1053.005", "example": "Scheduled tasks pointing to hidden partitions or executable containers"}
        ],
        "watchlist": [
            "Presence of mount tools running without user interaction",
            "Unusual volume identifiers or image files being accessed repeatedly",
            "Registry changes involving service keys tied to mounting or booting"
        ],
        "enhancements": [
            "Add signatures to detect partition image formats and virtual file system headers",
            "Deploy forensic tools that can enumerate non-MFT disk regions",
            "Enable full registry auditing for sensitive startup and service paths"
        ],
        "summary": "Hidden file systems allow adversaries to operate in concealed storage locations that evade most traditional security tools. They provide stealthy persistence, data exfiltration channels, and malware staging platforms.",
        "remediation": "Use disk forensic tools to identify and extract hidden partitions, validate boot integrity, and remove unauthorized boot configurations or registry entries enabling hidden storage.",
        "improvements": "Integrate hidden file system detection into EDR platforms and implement baseline comparisons of disk structures and service registries.",
        "mitre_version": "16.1"
    }
