import random
import re


TIPS = [
    "🚀 Be sure to check sysmon RuleName field for T-Codes"
    "🛠️ Investigate newly installed software that wasn't authorized by IT.",
    "🕵️‍♂️ Look for rogue processes running with elevated privileges.",
    "🌍 Monitor for unusual geolocation patterns in login attempts.",
    "📈 Analyze network traffic for unexpected spikes during off-hours.",
    "🔗 Check for changes in DNS configurations pointing to malicious servers.",
    "👾 Look for executables disguised as common file types like `.doc.exe`.",
    "📂 Investigate files with unusual double extensions like `report.pdf.exe`.",
    "🚦 Monitor ICMP traffic for unexpected usage, often used in C2.",
    "🔧 Scan for unauthorized modifications to firewall configurations.",
    "🕒 Investigate scheduled tasks that trigger outside working hours.",
    "🌐 Watch for connections to known threat actor infrastructure.",
    "📜 Look for tampered audit logs, especially around the incident timeline.",
    "🔗 Monitor changes to symbolic links or hard links on critical files.",
    "📤 Investigate large outbound data transfers to unknown domains.",
    "🛡️ Look for registry changes in startup or run keys.",
    "📡 Monitor DNS TXT record queries, which might be used for data exfiltration.",
    "📁 Check temp directories for unexpected executable files.",
    "💾 Look for removable media usage on high-security systems.",
    "🖥️ Monitor remote desktop sessions for unusual activity.",
    "📶 Watch for unusual patterns in Wi-Fi connections from endpoints.",
    "🚀 Look for process injection techniques in legitimate binaries.",
    "🔍 Investigate binaries running directly from `Downloads` folders.",
    "🛠️ Review new service creations for suspicious patterns.",
    "📜 Analyze event logs for sequences indicating privilege escalation.",
    "🔒 Track unusual access to encryption keys or keystores.",
    "📊 Monitor changes in user account privileges or roles.",
    "🌐 Review outbound HTTP POST requests for signs of exfiltration.",
    "🛡️ Scan for new PowerShell scripts in sensitive directories.",
    "📂 Look for altered timestamps on key system binaries.",
    "📡 Monitor inbound SSH connections from unknown IP addresses.",
    "📥 Investigate bulk email activity from user accounts.",
    "🔗 Look for network shares with changed permissions.",
    "🚦 Track internal traffic for lateral movement across VLANs.",
    "📋 Analyze clipboard activity for copied sensitive data.",
    "🖋️ Examine document metadata for unexpected embedded payloads.",
    "📈 Monitor CPU and RAM usage for resource-intensive attacks.",
    "🕵️‍♂️ Check for unrecognized browser extensions on user systems.",
    "🔗 Monitor SMB connections between unusual pairs of endpoints.",
    "📂 Investigate folders with an unusually large number of hidden files.",
    "🔧 Look for changes in application whitelisting policies.",
    "📶 Watch for rogue access points spoofing legitimate Wi-Fi networks.",
    "🖥️ Analyze usage of utilities like `certutil` or `powershell` for abuse.",
    "📜 Search for anomalies in VPN connection patterns.",
    "🚦 Monitor TCP retransmissions for hidden data channels.",
    "🔍 Investigate suspicious `.lnk` files in commonly accessed directories.",
    "📂 Check for unauthorized mounts of external file systems.",
    "🌐 Review HTTP request headers for automated browsing patterns.",
    "📡 Look for unauthorized use of tunneling protocols like SSH or RDP.",
    "🛠️ Investigate sandbox evasion techniques in malware samples.",
    "💻 Make sure your Host Agents are not disabled by the APT/Red Team.",
    "🛡️ Ensure EDR and antivirus solutions are actively monitoring all endpoints.",
    "🔒 Monitor for unusual attempts to disable or uninstall security agents.",
    "📊 Know what type of logs you are receiving.",
    "🔍 Understand your log sources and validate their integrity.",
    "📈 Ensure critical logs like authentication, network traffic, and process activity are being collected.",
    "📧 Phishing is a common initial access attempt.",
    "🛑 Train employees to recognize and report phishing emails promptly.",
    "🕵️‍♀️ Investigate email attachments or links for suspicious behavior.",
    "👽 Initial Access, Lateral Movement, and C2 are the easiest to catch.",
    "🌐 Watch for strange connections to uncommon IPs or ports for C2 detection.",
    "🔗 Track login patterns for signs of lateral movement across systems.",
    "🛠️ Create Alerts tailored to your APT.",
    "🚨 Develop rules based on TTPs of the threats your organization faces.",
    "👾 Use known threat actor behavior as a baseline for detection.",
    "🔐 Look for multiple failed login attempts followed by a success.",
    "👥 Monitor for the creation of suspicious or unusual accounts.",
    "🖋️ Keep an eye out for renamed files or sudden changes to file extensions.",
    "🛡️ Always investigate signs of persistence mechanisms like scheduled tasks or services.",
    "🔍 Check logs for lateral movement patterns within the network.",
    "📂 Look for data exfiltration attempts during off-hours.",
    "🕵️‍♂️ Watch for processes running in uncommon directories.",
    "🗂️ Review changes to sensitive directories like /etc or C:\\Windows\\System32.",
    "⚠️ Be alert to PowerShell scripts with obfuscation or base64 encoding.",
    "📥 Investigate unusual inbound or outbound traffic patterns.",
    "💻 Track the execution of unknown binaries or scripts.",
    "📊 Analyze event logs for sequences that indicate privilege escalation.",
    "🌐 Monitor for connections to known malicious IPs or domains.",
    "📈 Look for unusual spikes in network activity or CPU usage.",
    "🔑 Check for default or weak passwords in critical accounts.",
    "🔗 Watch for newly created symbolic links or junction points.",
    "🕒 Investigate task scheduler events outside of normal working hours.",
    "📦 Look for recently installed software that wasn’t approved.",
    "🔓 Monitor for attempts to disable antivirus or EDR tools.",
    "📜 Analyze browser history or bookmarks for connections to malicious sites.",
    "📂 Look for files with double extensions like `.exe.pdf`.",
    "🛠️ Check system startup items for unauthorized entries.",
    "📤 Investigate signs of data compression and outbound transfer.",
    "👀 Watch for registry modifications in persistence-related keys.",
    "🔍 Scan for unsigned drivers or DLLs in system directories.",
    "📡 Monitor DNS queries to unusual or high-risk domains.",
    "💽 Look for rogue virtual machines or snapshots.",
    "🖥️ Inspect remote desktop protocol (RDP) logs for unauthorized connections.",
    "🛡️ Review firewall logs for changes in access rules or port scans.",
    "📧 Analyze email headers for signs of phishing or spoofing.",
    "📌 Monitor USB activity for unauthorized devices.",
    "⚡ Look for processes with high privilege levels started by unprivileged users.",
    "🔗 Watch for changes to trusted system binaries.",
    "🛠️ Investigate event IDs related to new service installations.",
    "📂 Check shadow copies for deleted or modified files.",
    "🔍 Monitor account logins from unusual geographic locations.",
    "📂 Investigate tampering with backup files or schedules.",
    "🖥️ Look for signs of remote code execution (RCE) attempts.",
    "🌐 Review web server logs for suspicious parameter tampering.",
    "🚦 Monitor network flows for unusual traffic patterns or unexpected ports.",
    "📡 Be suspicious of repeated DNS queries to non-existent domains.",
    "🔒 Check for unauthorized changes to file or folder permissions.",
    "📤 Look for encrypted or compressed outbound traffic to unknown hosts.",
    "⚙️ Monitor changes in system startup configurations.",
    "🔍 Search for PowerShell scripts that include encoded commands.",
    "📁 Investigate files with zero-byte size in critical directories.",
    "🕒 Check for processes running at scheduled intervals outside business hours.",
    "📈 Review performance metrics for sudden resource spikes.",
    "🚀 Look for signs of process injection into legitimate applications.",
    "💻 Monitor for unauthorized changes to group memberships.",
    "🔗 Watch for symbolic links pointing to unexpected locations.",
    "🔍 Examine email attachments for hidden macros or scripts.",
    "⚠️ Scan for privilege escalation techniques in event logs.",
    "📦 Look for unexpected or unsigned updates to software packages.",
    "💾 Review logs for signs of removable media usage.",
    "🖥️ Investigate unusual usage of command-line utilities like `netstat` or `ipconfig`.",
    "📤 Track unusual outbound connections to high-risk countries.",
    "🔍 Look for registry keys with suspicious auto-start entries.",
    "🔧 Investigate changes to WMI subscriptions or filters.",
    "📊 Analyze account lockout patterns for brute-force attempts.",
    "🛡️ Monitor processes using suspicious parent-child relationships.",
    "📥 Investigate large file downloads from unusual IPs.",
    "⚡ Check for unauthorized applications installed via package managers.",
    "🔗 Look for SMB connections between unexpected hosts.",
    "🔍 Search for processes masquerading as system utilities.",
    "🖥️ Review logs for attempts to clear or disable event logging.",
    "📂 Look for hidden files in critical directories.",
    "🚦 Monitor outbound traffic for data transfers at odd hours.",
    "🔓 Check for unauthorized access to sensitive configuration files.",
    "🔧 Scan for unrecognized services or drivers in startup logs.",
    "🌐 Review web application logs for unauthorized access attempts.",
    "📜 Look for tampered audit logs or log file deletions.",
    "💡 Investigate systems with unusual uptime patterns.",
    "🕵️‍♂️ Monitor unusual changes to group policies.",
    "📂 Investigate abnormal growth in specific file directories.",
    "🛠️ Look for unusual process execution chains in forensic tools.",
    "📋 Check for clipboard monitoring or keylogging behavior.",
    "🚨 Monitor IDS/IPS alerts for common lateral movement patterns.",
    "🌍 Correlate login activity with geolocation inconsistencies.",
    "🔑 Investigate processes accessing security-critical files.",
    "📤 Look for repeated failed data upload attempts to unknown servers.",
    "🔍 Check for malicious scheduled tasks created recently.",
    "🛡️ Watch for unusual changes to user password policies.",
    "📈 Investigate sudden changes in user account activity levels.",
    "🖥️ Review temporary files for evidence of script execution.",
    "📦 Monitor endpoints for unauthorized package or library downloads.",
    "📂 Look for anomalies in recently accessed files.",
    "⚙️ Investigate mismatches in user-agent strings in web traffic.",
    "🔍 Look for attackers leaving test artifacts like `1.txt` or `test.ps1`.",
    "📜 Track file hashes for unauthorized changes to key binaries.",
    "🚦 Review network traffic for abnormal TTL values.",
    "🛡️ Identify rare parent-child process relationships in your environment.",
    "🔍 Investigate long-running processes, especially with elevated privileges.",
    "📊 Analyze PowerShell logs for encoded or obfuscated commands.",
    "🌐 Review TLS/SSL traffic for connections to self-signed certificates.",
    "📁 Monitor for temporary files with sensitive data remnants.",
    "🚦 Analyze unusual ICMP traffic patterns, often used in C2 communications.",
    "🔗 Watch for new shares created on file servers.",
    "🕵️‍♂️ Search for suspicious DNS TXT record queries.",
    "🔍 Investigate commands executed by `cmd.exe` or `bash`.",
    "🖥️ Look for abnormal usage of tools like `certutil` or `wget`.",
    "🔓 Monitor for attempted privilege escalation via sudo or su.",
    "📂 Search for files with names mimicking system executables.",
    "🚨 Look for multiple simultaneous logins to a single account.",
    "🛡️ Track binaries executed directly from the browser download folder.",
    "🌐 Monitor HTTP POST requests to unknown domains.",
    "📊 Analyze VPN connections for anomalies in duration or frequency.",
    "🔍 Check for DLLs loaded from unexpected directories.",
    "📂 Monitor `.tmp` files in system directories.",
    "🖋️ Look for encoded payloads in commonly abused file formats like `.docx`.",
    "🚦 Watch for network traffic containing known C2 patterns.",
    "🔧 Investigate changes to Local Security Authority (LSA) configuration.",
    "📈 Analyze system uptime for anomalies indicating potential reboots.",
    "🌐 Monitor unusual redirects in web server logs.",
    "📂 Investigate changes to `/etc/passwd` or SAM files.",
    "🛡️ Look for unauthorized modifications to PAM modules.",
    "🖋️ Examine email forwarding rules set by attackers for persistence.",
    "🚦 Analyze protocol mismatches in encrypted traffic.",
    "🔍 Search for executables or scripts hidden with spaces or special characters.",
    "📂 Look for ZIP/RAR archives with embedded malicious scripts.",
    "🌐 Monitor user-agent strings for indicators of automation.",
    "🚦 Watch for port scanning or unusual sequential connections.",
    "🔒 Track processes that directly modify system logs.",
    "📂 Monitor suspicious changes to file ownership or permissions.",
    "🛡️ Investigate suspicious network shares with modified permissions.",
    "🚀 Look for scripts invoking unauthorized API calls.",
    "🔧 Monitor changes to firewall rules allowing external access.",
    "🌍 Correlate suspicious geolocation patterns in remote logins.",
    "🖥️ Analyze command history for unusual usage.",
    "📤 Watch for data egress in unconventional formats.",
    "📊 Investigate mismatches between file metadata and actual content.",
    "🔍 Search for execution of commands like `nc` or `netcat`.",
    "🚨 Track endpoints with repeated failed DNS lookups.",
    "📂 Monitor files compressed using password protection.",
    "📡 Look for inbound SSH connections from unknown sources.",
    "🖋️ Investigate office documents with unusual macros.",
    "🚦 Watch for packet size anomalies in encrypted traffic.",
    "🔍 Analyze event logs for attempts to tamper with security settings.",
    "🛡️ Monitor software installations from untrusted certificates.",
    "📥 Investigate repeated connections to IPs without associated domains.",
    "📊 Look for binary downloads from suspicious URLs.",
    "🕵️‍♂️ Monitor registry changes related to persistence mechanisms.",
    "🛠️ Analyze anomalous changes in group memberships.",
    "📂 Investigate tampered antivirus exclusions or policies.",
    "📈 Search for inconsistencies in time-stamped files.",
    "🔧 Monitor default admin shares for unusual access.",
    "📜 Look for signs of log tampering in security audit logs.",
    "📡 Check SMB traffic for unauthorized access attempts.",
    "🖋️ Investigate PDFs with hidden payloads or JavaScript.",
    "🌐 Analyze web server headers for outdated or misconfigured software.",
    "📊 Look for modified or unexpected system images.",
    "🖥️ Monitor endpoint connections to public paste sites.",
    "🚦 Watch for stealthy TCP retransmissions in packet captures.",
    "📂 Investigate newly created service accounts with high privileges.",
    "🔧 Analyze processes creating non-standard network connections.",
    "📈 Monitor CPU and memory spikes during off-hours.",
    "🚀 Investigate scripts executed from uncommon locations.",
    "🌍 Correlate network traffic against threat intelligence sources.",
    "📤 Look for encrypted or compressed outbound data at odd times.",
    "📂 Monitor endpoints for large, unexpected file deletions.",
    "📡 Look for reverse shell attempts in network logs.",
    "🛡️ Investigate unusual browser plugins or extensions.",
    "📊 Search for unexplained registry run keys.",
    "🔧 Investigate unusual file naming conventions in backup locations.",
    "🖥️ Monitor desktop activity for unscheduled screenshots or keylogging.",
    "📜 Investigate systems with missing or altered critical files.",
    "🚦 Correlate failed authentications with brute-force patterns.",
    "📂 Analyze temporary folders for suspicious script files.",
    "🔍 Look for attackers testing connectivity via `ping` or traceroute.",
    "📊 Track spikes in file-sharing activity.",
    "🌐 Review web traffic logs for possible data leakage.",
    "🖋️ Investigate documents with high entropy in their metadata.",
    "📤 Look for staging directories with suspicious files.",
    "🕵️‍♂️ Monitor access logs for unauthorized application startups.",
    "📂 Investigate tampered scheduled jobs or cron entries.",
    "🛡️ Analyze unauthorized password resets or account creations.",
    "🔧 Search for hidden tasks in task scheduler or cron jobs.",
    "📡 Investigate unusual or repeated ARP requests.",
    "🌍 Correlate IoT device traffic patterns with known exploits.",
    "🚦 Monitor DNS requests with large or binary-like payloads.",
    "📈 Look for repeated HTTP 401 (Unauthorized) responses."
]

# Cybersecurity jokes
JOKES = [
    "🤖 Why did the hacker cross the road? To get to the other .NET.",
    "❄️ Why was the computer cold? It left its Windows open.",
    "🪥 How do hackers freshen their breath? With CyberTic Tac!",
    "❤️‍🩹 Why don't hackers ever get into relationships? They're afraid of commitments.",
    "🐾 What do you call a hacker who loves animals? A purr-sistence threat!",
    "💸 Why did the server go broke? It lost all its cache.",
    "😂 How do you make a malware laugh? Give it a worm joke!",
    "📉 Why did the sysadmin go broke? Too many root expenses.",
    "🥣 What’s a hacker’s favorite kind of cereal? Spy-ders!",
    "🛡️ Why did the password break up with the hacker? It was too weak.",
    "🔒 Why are cybersecurity experts bad at telling jokes? They always encrypt the punchline.",
    "🎵 What’s a hacker’s favorite music genre? Phishing!",
    "👓 Why do hackers wear glasses? Because they lost their focus.",
    "📶 Why did the WiFi break up with the laptop? It found a stronger connection.",
    "😌 Why was the antivirus program so relaxed? It knew how to quarantine stress.",
    "🍁 What’s a hacker’s favorite season? Phall.",
    "🌑 Why do programmers prefer dark mode? Because light attracts bugs.",
    "🚩 What’s a hacker’s favorite game? Capture the flag!",
    "☠️ Why don’t hackers get along with pirates? Too many patches.",
    "🎉 How do you throw a cybersecurity party? Invite everyone to the LAN!",
    "🔥 Why was the firewall so happy? It finally blocked its ex.",
    "🔑 Why was the keyboard locked out of the server room? Too many CAPS.",
    "🍺 What’s a hacker’s least favorite drink? Root beer.",
    "⚾ Why was the hacker bad at baseball? It couldn’t handle the curve (encryption).",
    "☕ How do cybersecurity experts like their coffee? Encrypted.",
    "😭 Why did the antivirus cry? It couldn’t handle the worm.",
    "🤫 Why don’t hackers tell secrets? They’re worried about key-loggers.",
    "🏕️ Why don’t hackers go camping? Too many phishing attacks.",
    "💃 What’s a hacker’s favorite dance? The worm.",
    "🐴 Why was the Trojan horse so good at infiltration? It always had the ‘write’ access.",
    "🧗 What’s the cybersecurity expert’s favorite sport? Fire-wall climbing.",
    "🕵️‍♂️ Why was the hacker great at hide-and-seek? It always hid in the registry.",
    "🛜 What did the router say to the server? You’ve got the bandwidth for this!",
    "🍽️ What’s a phishing scammer’s favorite dish? Spam.",
    "🌞 Why don’t hackers get sunburned? They stay in the shadows.",
    "🧑‍🔬 What do you call a group of math and science geeks at a party? Social engineers.",
    "🌐 What’s the best way to catch a runaway robot? Use a botnet.",
    "🐛 Why did the programmer leave the camping trip early? There were too many bugs."
]

TCODES = [
    "🛡️ T1003: Credential Dumping - Monitor for attempts to access LSASS or SAM files to extract credentials.",
    "📜 T1021: Remote Services - Review logs for suspicious RDP or SSH connections from unknown sources.",
    "🔍 T1059: Command and Scripting Interpreter - Look for PowerShell, bash, or Python commands running unusual scripts.",
    "🖥️ T1078: Valid Accounts - Check for legitimate credentials being used in unusual ways, such as geographic anomalies.",
    "📂 T1105: Ingress Tool Transfer - Investigate downloads of suspicious files from external IPs.",
    "🚦 T1071: Application Layer Protocol - Monitor for unexpected use of protocols like HTTP or DNS for command and control.",
    "📡 T1136: Create Account - Look for unauthorized user account creation on critical systems.",
    "🛠️ T1566: Phishing - Analyze email headers and attachments for signs of phishing attempts.",
    "🔧 T1113: Screen Capture - Investigate processes accessing screen-capturing APIs or creating screenshots.",
    "📊 T1046: Network Service Scanning - Track scans for open ports or services from internal or external sources.",
    "📤 T1041: Exfiltration Over C2 Channel - Monitor encrypted outbound traffic for unusual data size or frequency.",
    "🔍 T1218: Signed Binary Proxy Execution - Look for legitimate binaries like msbuild.exe or regsvr32.exe being used for execution.",
    "📈 T1053: Scheduled Task/Job - Review task scheduler logs for new or altered tasks.",
    "📂 T1106: Execution via API - Look for applications calling APIs like CreateProcess or ShellExecute suspiciously.",
    "🛡️ T1055: Process Injection - Monitor for signs of one process injecting code into another, such as DLL injection.",
    "📜 T1562: Impair Defenses - Look for attempts to disable antivirus, EDR, or firewalls.",
    "🕵️ T1082: System Information Discovery - Check for commands like systeminfo or uname executed by unrecognized users.",
    "🌐 T1203: Exploitation for Client Execution - Review crash or error logs for signs of exploitation attempts.",
    "🔗 T1098: Account Manipulation - Look for changes to user accounts, such as password resets or role changes.",
    "📂 T1547: Boot or Logon Autostart Execution - Monitor registry keys and startup folders for new entries.",
    "🔍 T1210: Exploitation of Remote Services - Look for brute force or vulnerability exploitation on RDP, SMB, or SSH.",
    "📡 T1571: Non-Standard Port - Monitor traffic on uncommon ports used for potential C2 communication.",
    "🚦 T1573: Encrypted Channel - Analyze TLS traffic to detect abnormal certificate usage or destinations.",
    "📋 T1543: Create or Modify System Process - Investigate creation of new services or changes to existing ones.",
    "🖥️ T1008: Fallback Channels - Look for changes in traffic patterns during primary C2 disruption.",
    "🔒 T1217: Browser Credential Theft - Check for access to browser profile directories or credential stores.",
    "📤 T1048: Exfiltration Over Alternative Protocol - Monitor file uploads using FTP, SCP, or similar tools.",
    "🛠️ T1056: Input Capture - Look for keylogger activity or suspicious hooks into input APIs.",
    "📊 T1016: System Network Configuration Discovery - Track execution of ipconfig, ifconfig, or network enumeration tools.",
    "🚨 T1129: Shared Module - Monitor shared libraries or modules loaded from unexpected paths.",
    "📊 T1083: File and Directory Discovery - Investigate processes enumerating sensitive files or directories.",
    "📦 T1095: Non-Application Layer Protocol - Check for unusual protocols used for data exfiltration.",
    "📜 T1027: Obfuscated Files or Information - Look for scripts or files with unusual encoding or compression.",
    "🛡️ T1107: File Deletion - Monitor for tools or commands used to delete logs or forensic evidence.",
    "🔧 T1070: Indicator Removal on Host - Investigate tampering with logs, disabling of EDR, or clearing event logs.",
    "📋 T1010: Application Window Discovery - Look for processes querying open window titles or processes.",
    "📂 T1050: New Service - Investigate the creation of new services as a persistence mechanism.",
    "🚦 T1134: Access Token Manipulation - Detect unusual impersonation or privilege escalation via tokens.",
    "🌐 T1204: User Execution - Monitor for users executing attachments, scripts, or software directly from emails.",
    "🔑 T1176: Browser Extensions - Investigate unauthorized or malicious extensions added to browsers.",
    "🔧 T1074: Data Staged - Check for large volumes of data being staged in temporary directories.",
    "📤 T1560: Archive Collected Data - Look for compressed files being prepared for exfiltration.",
    "🖋️ T1486: Data Encrypted for Impact - Monitor for ransomware-like encryption of files.",
    "🕵️ T1057: Process Discovery - Investigate commands or tools listing running processes.",
    "📁 T1132: Data Encoding - Check for unusual base64, hex, or XOR encoding in files or logs.",
    "📦 T1102: Web Service - Look for suspicious use of cloud services for C2 or exfiltration.",
    "🛠️ T1059.001: PowerShell - Analyze PowerShell logs for unusual or obfuscated commands.",
    "📈 T1049: System Network Connections Discovery - Investigate commands like netstat or scripts enumerating network connections.",
    "📂 T1216: Signed Scripts - Check for scripts signed by trusted certificates but used maliciously.",
    "🌐 T1104: Multi-Stage Channels - Monitor traffic for multiple hops or relays indicative of advanced attacks.",
    "🔍 T1555: Credentials from Password Stores - Investigate access to password managers or browser-stored credentials.",
    "📤 T1074.001: Remote Data Staging - Look for large data collections transferred to external hosts.",
    "🔧 T1574: Hijack Execution Flow - Check for modifications in binary execution flow like DLL search order hijacking.",
    "🔒 T1080: Taint Shared Content - Monitor for tampered shared files or directories in collaborative environments.",
    "📈 T1090: Proxy - Investigate unexpected use of VPNs or anonymization tools.",
    "🖋️ T1497: Virtualization/Sandbox Evasion - Detect attempts to identify and evade virtualized or sandboxed environments.",
    "🚦 T1108: Redundant Access - Monitor for backdoor creation or redundant persistence mechanisms.",
    "📜 T1485: Data Destruction - Track attempts to overwrite or corrupt critical files.",
    "📂 T1542: Pre-OS Boot - Investigate bootkits or changes to boot configurations.",
    "📡 T1558: Steal or Forge Kerberos Tickets - Look for tools like Mimikatz accessing Kerberos tickets.",
    "🔗 T1020: Automated Exfiltration - Monitor scripted data transfers to external servers.",
    "📥 T1123: Audio Capture - Check for processes accessing audio devices without user consent.",
    "🛠️ T1570: Lateral Tool Transfer - Look for file transfers to other hosts via SMB, SCP, or similar protocols.",
    "📤 T1040: Network Sniffing - Detect unauthorized packet capture or network monitoring tools.",
    "🔧 T1052: Exfiltration Over Physical Medium - Investigate large file transfers to USB drives or other external media.",
    "🔍 T1052.001: Exfiltration Over Bluetooth - Monitor Bluetooth activity for unexpected file transfers.",
    "🌐 T1018: Remote System Discovery - Investigate attempts to enumerate network-connected devices.",
    "📂 T1484: Domain Policy Modification - Check for changes to group policies or domain configurations.",
    "🔒 T1548: Abuse Elevation Control Mechanism - Look for processes bypassing UAC or sudo permissions.",
    "📜 T1552: Unsecured Credentials - Investigate plaintext or weakly protected credentials in configuration files.",
    "🖥️ T1546: Event Triggered Execution - Monitor for unusual triggers tied to task scheduling or logon events.",
    "📥 T1125: Video Capture - Look for processes using webcam APIs or recording software.",
    "🔧 T1012: Query Registry - Investigate registry queries for persistence-related keys.",
    "📈 T1018: System Network Connections Discovery - Look for reconnaissance attempts enumerating active connections.",
    "📂 T1120: Peripheral Device Discovery - Check logs for unexpected enumeration of hardware devices.",
    "🛡️ T1036: Masquerading - Detect renamed executables mimicking legitimate system files.",
    "🚦 T1048: Exfiltration Over Alternative Protocol - Monitor FTP, SCP, or non-standard protocols for data transfer.",
    "📦 T1074.002: Local Data Staging - Investigate large files being prepared in temporary directories.",
    "🔗 T1021.001: Remote Desktop Protocol - Review RDP logs for unusual connection patterns.",
    "📡 T1553: Subvert Trust Controls - Monitor attempts to bypass or forge trust certificates.",
    "📥 T1039: Data from Network Shared Drive - Look for unauthorized access to shared drives.",
    "🔧 T1033: System Owner/User Discovery - Investigate processes attempting to identify logged-in users.",
    "📂 T1552.004: Container Credential Dumping - Monitor container runtime logs for credential access attempts.",
    "🔍 T1568: Dynamic Resolution - Investigate use of domain generation algorithms or DNS tunneling for C2.",
    "🖋️ T1134.003: Token Impersonation/Theft - Detect impersonation of user tokens for privilege escalation.",
    "📜 T1014: Rootkit - Look for signs of kernel module tampering or hidden processes.",
    "📤 T1089: Disabling Security Tools - Track attempts to disable security tools via registry edits or system commands.",
    "🔒 T1087: Account Discovery - Investigate attempts to enumerate user accounts in local or domain environments."
]

ANSI_ESCAPE_REGEX = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
TCODE_PATTERN = re.compile(r'(T\d{4}(\.\d{3})?)')  # Matches T#### or T####.###

def get_random_tip_or_joke(clean=False):
    # Pick a random tip or joke
    item = random.choice(TIPS + JOKES + TCODES)
    
    # Replace T-Codes with clickable links
    def replace_tcode_with_link(match):
        tcode = match.group(1)
        return f'<a href="https://attack.mitre.org/techniques/{tcode}/" target="_blank">{tcode}</a>'
    
    formatted_item = TCODE_PATTERN.sub(replace_tcode_with_link, item)

    if clean:
        # Remove HTML tags for clean output
        formatted_item = re.sub(r'<[^>]+>', '', formatted_item)
    
    return formatted_item