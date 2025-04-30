def get_content():
    return {
        "id": "T1021.001",
        "url_id": "T1021/001",
        "title": "Remote Services: Remote Desktop Protocol",
        "tactic": "lateral_movement",
        "protocol": "RDP (TCP/3389)",
        "os": "Windows",
        "description": "Adversaries may use RDP to move laterally within an environment. RDP is a common protocol used by system administrators to remotely manage Windows systems. Adversaries may abuse RDP to access systems within a network after obtaining valid credentials, allowing them to move laterally and maintain persistence on a victim network.",
        "tips": ["RDP authentication happens prior to session establishment (NLA)",
                 "RDP Event Flow: 1149 --> 4624 (type 10) OR 7 (reconnect) --> 21 --> 22",
                 "1149: Authentication succeeded",
                 "4624: Account successfully logged on",
                 "21: Session logon succeeded",
                 "22: Shell start notification received",
                 ],
        "data_sources": "Sysmon, Authentication Logs, Network Traffic Logs, Process Monitoring, Windows Event Logs",
        "log_sources": [
            {"type": "Windows Security", "source": "4648 - Logon specifying alternate credentials, 4624, 4625, 4776", "destination": "4624 Logon Type 10 (Source IP/Logon User Name), 4778, 4778/4779 (IP Address of Source/Source System Name, Logon User Name)"},
            {"type": "Microsoft-Windows-TerminalServices-RDPClient/Operational", "source": "1024, 1102", "destination": ""},
            {"type": "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational", "source": "", "destination": "98, 131 (Source IP)"},
            {"type": "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational", "source": "", "destination": "21, 22, 25, 41"},
            {"type": "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational", "source": "", "destination": "1149 (Blank user name may indicate use of Sticky Keys)"},
            {"type": "Registry", "source": "NTUSER\\Software\\Microsoft\\Terminal Server Client\\Servers", "destination": "ShimCache, AmCache.hve"},
            
            {"type": "ShimCache", "source": "mstsc.exe Remote Desktop Client", "destination": "rdpclip.exe, tstheme.exe"},
            {"type": "BAM_DAM", "source": "mstsc.exe", "destination": ""},
            {"type": "AmCache.hve", "source": "mstsc.exe - First time executed", "destination": "rdpclip.exe, tstheme.exe"},
            {"type": "UserAssist", "source": "mstsc.exe - last time executed & # of times executed", "destination": ""},
            {"type": "RecentApps - NTUSER.DAT", "source": "mstsc.exe - last time executed & # of times executed", "destination": ""},
                    
            {"type": "Network Traffic", "source": "Firewall Logs on the initiating machine showing outbound RDP (TCP/3389) attempts", "destination": "Firewall Logs on the destination machine receiving inbound RDP connections"},
            {"type": "Process Monitoring", "source": "Sysmon (Event ID 1 - Process Creation) on the source machine where the RDP client is executed", "destination": "Sysmon (Event ID 1, 3 - Network Connection) on the destination machine processing RDP sessions"},
            {"type": "EDR Logs", "source": "EDR solutions (e.g., CrowdStrike, Defender ATP, Carbon Black) logging RDP execution from the initiating machine", "destination": "EDR solutions detecting RDP session initiation on the target system"}
        ],
        "source_artifacts": [
            {"type": "Jumplists", "location": "C:\\Users\\<Username>\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\AutomaticDestinations\\", "identify": "{MSTSC-APPID}-automaticDestinations-ms"},
            {"type": "Prefetch", "location": "C:\\Windows\\Prefetch\\", "identify": "mstsc.exe-{hash}.pf"},
            {"type": "Bitmap_Cache", "location": "C:\\Users\\<Username>\\AppData\\Local\\Microsoft\\TerminalServer Client\\Cache", "identify": "bcache##.bmc, cache####.bin"},
            {"type": "Default.rdp file", "location": "C:\\Users\\<Username>\\Documents\\", "identify": ""},
        ],
        "destination_artifacts": [
            {"type": "Prefetch", "location": "C:\\Windows\\Prefetch\\", "identify": "rdpclip.exe-{hash}.pf, tstheme.exe-{hash}.pf"},   
        ],
        "detection_methods": [
            "Monitor for successful RDP logins (Event ID 4624, Logon Type 10) from unusual source IPs.",
            "Detect excessive failed RDP login attempts (Event ID 4625) which may indicate brute force attempts.",
            "Analyze firewall logs for unexpected RDP traffic from external IPs or uncommon subnets.",
            "Use behavioral analytics to detect rare RDP session initiation patterns.",
            "Correlate RDP activity with account usage to detect compromised credentials."
        ],
        "spl_query": [
            "index=windows EventCode=4624 LogonType=10 \n| stats count by user, src_ip, dest_ip",
            "index=windows EventCode=4625 LogonType=10 \n| stats count by user, src_ip \n| where count > 5",
            "index=network protocol=RDP \n| stats count by src_ip, dest_ip"
        ],
        "hunt_steps": [
            "Analyze RDP login events (4624) to identify unauthorized access.",
            "Investigate excessive failed RDP logins (4625) for potential brute-force attacks.",
            "Review firewall logs for RDP traffic originating from unexpected locations.",
            "Correlate RDP activity with recent account logins to detect compromised credentials.",
            "Monitor new RDP sessions on critical servers that do not usually allow RDP access."
        ],
        "expected_outcomes": [
            "Unauthorized RDP access detected: Investigate the source and disable unauthorized sessions.",
            "Brute-force attempts identified: Block the source IP and enforce account lockout policies.",
        ],
        "false_positive": "Improve baseline detection rules and update monitoring policies.",
        "clearing_steps": [
            "Terminate unauthorized RDP sessions.",
            "Reset passwords for compromised accounts.",
            "Block RDP access from unapproved external IPs.",
            "Harden RDP access controls (e.g., enable MFA, restrict to VPN users)."
        ],
        "mitre_mapping": [
            {"tactic": "Lateral Movement", "technique": "T1021.001", "example": "Adversary uses RDP to move laterally by logging into another system with stolen credentials."},
            {"tactic": "Credential Access", "technique": "T1110", "example": "Adversary attempts multiple RDP login attempts to gain access via brute-force."},
            {"tactic": "Defense Evasion", "technique": "T1070", "example": "Adversary clears Windows event logs to hide RDP activity."},
            {"tactic": "Persistence", "technique": "T1133", "example": "Adversary maintains persistent access via RDP."}
        ],
        "watchlist": [
            "Monitor for RDP sessions initiated from unknown or foreign IP addresses.",
            "Alert on multiple failed RDP logins in a short timeframe.",
            "Flag first-time RDP usage on systems that do not typically use it."
        ],
        "enhancements": [
            "Enable RDP session recording for forensic analysis.",
            "Restrict RDP access to specific administrative users and approved IP ranges.",
            "Use behavioral analytics to detect anomalies in RDP session usage."
        ],
        "summary": "Detect and prevent unauthorized RDP access to mitigate lateral movement risks.",
        "remediation": "Investigate unauthorized RDP usage, enforce access controls, and strengthen authentication measures.",
        "improvements": "Enhance RDP detection capabilities with anomaly-based monitoring and behavioral analytics."
    }
