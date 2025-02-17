def get_content():
    return {
        "id": "T1135",
        "url_id": "T1135",
        "title": "Network Share Discovery",
        "tactic": "Discovery",
        "data_sources": "Security Event Logs, SMB Client Logs, Registry, File System Artifacts",
        "protocol": "SMB, CIFS",
        "os": "Windows, Linux, macOS",
        "objective": "Identify adversaries enumerating network shares to find sensitive data or lateral movement opportunities.",
        "scope": "Monitor network share access and mapping activities for anomalies.",
        "threat_model": "Attackers may use built-in system utilities such as net.exe to discover network shares, which can aid in data exfiltration or lateral movement.",
        "hypothesis": [
            "Are there unauthorized or abnormal network share enumeration attempts?",
            "Are multiple network shares being accessed in a short period?",
            "Is there access to administrative shares such as C$ and ADMIN$?"
        ],
        "tips": [
            "Monitor for excessive use of net.exe and net1.exe.",
            "Enable logging for file share access to detect suspicious activity.",
            "Investigate logs for unauthorized access to shared resources."
        ],
        "log_sources": [
            {"type": "Security Event Log", "source": "security.evtx", "destination": "SIEM"},
            {"type": "SMB Client Logs", "source": "Microsoft-Windows-SmbClient\\Security.evtx", "destination": "SIEM"}
        ],
        "source_artifacts": [
            {"type": "Registry", "location": "NTUSER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2", "identify": "Remotely mapped shares"},
            {"type": "Registry", "location": "USRCLASS.DAT", "identify": "Shellbags indicating accessed remote folders"},
            {"type": "Prefetch", "location": "C:\\Windows\\Prefetch\\", "identify": "net.exe and net1.exe prefetch files"}
        ],
        "destination_artifacts": [
            {"type": "File System", "location": "C:\\Windows\\System32\\LogFiles\\Sum", "identify": "User access logs on servers"}
        ],
        "detection_methods": [
            "Monitor Event ID 4624 (Logon Type 3) for unexpected share access.",
            "Detect Event ID 5140 and 5145 for shared folder access anomalies.",
            "Investigate usage of net.exe and net1.exe for network enumeration."
        ],
        "apt": [
            "G0032 - Lazarus Group: Uses network share enumeration for lateral movement."
        ],
        "spl_query": [
            "index=windows EventCode=4624 LogonType=3 \n| search AccountName!=\"SYSTEM\" \n| stats count by AccountName, ComputerName, IpAddress",
            "index=windows EventCode=5140 OR EventCode=5145 \n| search ShareName IN (\"C$\", \"ADMIN$\") \n| stats count by AccountName, ShareName, ComputerName"
        ],
        "hunt_steps": [
            "Identify suspicious network share enumeration activities.",
            "Correlate with event logs for unauthorized access attempts.",
            "Investigate newly accessed or modified files on shared resources."
        ],
        "expected_outcomes": [
            "Detection of unauthorized attempts to access network shares.",
            "Identification of possible lateral movement attempts using shared resources."
        ],
        "false_positive": "Legitimate IT administrators may access network shares for maintenance purposes.",
        "clearing_steps": [
            "Revoke unauthorized user access to sensitive shares.",
            "Audit and restrict administrative share access.",
            "Implement network segmentation to limit unnecessary share access."
        ],
        "mitre_mapping": [
            {"tactic": "Lateral Movement", "technique": "T1077 (Windows Admin Shares)", "example": "Adversaries may use mapped shares to transfer malicious files."},
            {"tactic": "Collection", "technique": "T1039 (Data from Network Shared Drive)", "example": "Attackers may exfiltrate files from shared drives."}
        ],
        "watchlist": [
            "Monitor repeated access attempts to network shares.",
            "Detect abnormal net.exe usage in event logs.",
            "Investigate excessive file modification within shared directories."
        ],
        "enhancements": [
            "Enable auditing for shared folder access (Event ID 5145).",
            "Implement least privilege principles for network shares.",
            "Use endpoint detection tools to flag suspicious network enumeration."
        ],
        "summary": "Monitor for adversaries leveraging built-in system tools to enumerate network shares for reconnaissance or lateral movement.",
        "remediation": "Restrict access to administrative shares, implement network segmentation, and monitor SMB-related events for anomalies.",
        "improvements": "Strengthen event log monitoring, enforce strict ACLs on shared resources, and enhance SIEM correlation rules."
    }


'''
        {
            "title": "Map Share Source Event Logs",
            "content": """
### Source Event Logs
- `security.evtx`
    - `4648` - Logon specifying alternate credentials
        - Current logged-on User Name
        - Alternate User Name
        - Destination Host Name/IP
        - Process Name 
- `Microsoft-Windows-SmbClient\\Security.evtx`
    - `31001` – Failed logon to destination
        - Destination Host Name
        - User Name for failed logon
        - Reason code for failed destination logon (e.g., bad password)
            """
        },
        {
            "title": "Map Share Destination Event Logs",
            "content": """
### Destination Event Logs
- **Security Event Log – `security.evtx`**
    - `4624`
        - Logon Type 3
        - Source IP/Logon User Name
    - `4672`
        - Logon User Name
        - Logon by user with administrative rights
        - Requirement for accessing default shares such as **C$** and **ADMIN$**
    - `4776` - NTLM if authenticating to Local System
        - Source Host Name/Logon User Name
    - `4768` - TGT Granted
        - Source Host Name/Logon User Name
        - Available only on domain controller
    - `4769` - Service Ticket Granted if authenticating to Domain Controller
        - Destination Host Name/Logon User Name
        - Source IP
        - Available only on domain controller
    - `5140`
        - Share Access
    - `5145`
        - Auditing of shared files – **NOISY**!
            """
        },
        {
            "title": "Map Share Source Registry",
            "content": """
### Source Registry
- **MountPoints2** - Remotely mapped shares
    - `NTUSER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2`
- **Shellbags** - USRCLASS.DAT
    - Remote folders accessed inside an interactive session via Explorer by attackers.
- **ShimCache** – SYSTEM
    - `net.exe`
    - `net1.exe`
- **BAM_DAM** – NTUSER.DAT – Last Time Executed
    - `net.exe`
    - `net1.exe`
- **AmCache.hve** - First Time Executed
    - `net.exe`
    - `net1.exe`
            """
        },
        {
            "title": "Map Share Destination Registry",
            "content": """
### Destination Registry
- N/A
            """
        },
        {
            "title": "Map Share Source File System",
            "content": """
### Source File System
- **Prefetch** - `C:\\Windows\\Prefetch\\`
    - `net.exe-{hash}.pf`
    - `net1.exe-{hash}.pf`
- **User Profile Artifacts**
    - Review shortcut files and jumplists for remote files accessed by attackers if they had interactive access (RDP).
            """
        },
        {
            "title": "Map Share Destination File System",
            "content": """
### Destination File System
- **File Creation**
    - Attacker's files (malware) copied to the destination system.
    - Look for Modified Time before Creation Time.
    - Creation Time is the time of file copy.
- **User Access Logging (Servers Only)**
    - `C:\\Windows\\System32\\LogFiles\\Sum`
        - User Name
        - Source IP Address
        - First and Last Access Time
            """
        }
    ]
'''