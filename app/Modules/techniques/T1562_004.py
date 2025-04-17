def get_content():
    return {
        "id": "T1562.004",
        "url_id": "T1562/004",
        "title": "Impair Defenses: Disable or Modify System Firewall",
        "description": "Adversaries may disable or modify a system's firewall to bypass network restrictions and enable unauthorized communications. These modifications can be full deactivations or fine-grained rule changes, executed via command-line utilities (e.g., `netsh`, `ufw`, `iptables`), graphical interfaces, or registry edits (on Windows). Disabling or altering firewalls can allow Command and Control (C2), lateral movement, and data exfiltration that would otherwise be blocked.\n\nAdversaries may use techniques such as creating rules to permit known services (like RDP) on non-standard ports to evade detection. Additionally, they might indirectly affect firewall behavior through changes in host networking configurations, interface thresholds, or the enabling of remote access features.\n\nFirewall evasion is a common component of advanced post-exploitation and persistence routines.",
        "tags": ["firewall", "evasion", "network access", "netsh", "ufw", "iptables", "registry", "lateral movement"],
        "tactic": "Defense Evasion",
        "protocol": "",
        "os": "Linux, Windows, macOS, Network",
        "tips": [
            "Monitor firewall configurations regularly for unauthorized rule changes.",
            "Establish baselines for firewall rules and use configuration management tools to enforce them.",
            "Log all firewall-related system changes and correlate with authentication events."
        ],
        "data_sources": "Command, Firewall, Windows Registry",
        "log_sources": [
            {"type": "Command", "source": "CLI", "destination": ""},
            {"type": "Firewall", "source": "", "destination": ""},
            {"type": "Windows Registry", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Command Execution", "location": "netsh, Set-NetFirewallProfile, ufw, iptables", "identify": "Disabling firewall or creating allow rules"},
            {"type": "Registry Keys", "location": "HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy", "identify": "Modified to disable firewall profiles"},
            {"type": "Service Control", "location": "sc stop MpsSvc", "identify": "Firewall service manually stopped"}
        ],
        "destination_artifacts": [
            {"type": "Firewall Logs", "location": "Event Viewer (Microsoft-Windows-Windows Firewall With Advanced Security)", "identify": "Show unexpected rule changes"},
            {"type": "Rule Configurations", "location": "/etc/ufw or /etc/firewalld", "identify": "Custom allow-all or broad inbound access"},
            {"type": "System Registry", "location": "HKLM settings for firewall services", "identify": "Manipulated startup type or rule profiles"}
        ],
        "detection_methods": [
            "Monitor command-line invocations of `netsh`, `Set-NetFirewallProfile`, `ufw`, `iptables`, and related binaries",
            "Log and audit firewall configuration changes via GPO or security solution integrations",
            "Detect registry key changes related to Windows Firewall service or policy settings",
            "Correlate the appearance of new firewall rules with non-administrative user activity"
        ],
        "apt": ["APT30", "BeagleBoyz", "InvisiMole", "BlackCat", "Kimsuky"],
        "spl_query": [
            "index=sysmon OR wineventlog EventCode=4688 \n| search CommandLine IN (*netsh*, *Set-NetFirewallProfile*, *ufw*, *iptables*, *firewalld*) \n| stats count by host, user, CommandLine",
            "index=wineventlog EventCode=4946 OR EventCode=4947 OR EventCode=4948 \n| stats count by host, RuleName, Action"
        ],
        "hunt_steps": [
            "Search for disabled firewall services or startup modes in registry and service configurations",
            "Review firewall rules added or modified recently on endpoints or servers",
            "Check for presence of allow rules using uncommon ports (e.g., RDP over 4443)",
            "Correlate firewall manipulation with remote login or privilege escalation activity"
        ],
        "expected_outcomes": [
            "Identification of unauthorized firewall rule additions or service deactivation",
            "Detection of use of system utilities to suppress firewall protections",
            "Alerting on registry or service state changes related to host firewalls"
        ],
        "false_positive": "System administrators and legitimate automation tools may change firewall rules for patching or software installations. Investigate context and initiator identity.",
        "clearing_steps": [
            "Re-enable firewalls using `Set-NetFirewallProfile -All -Enabled True` or equivalent commands",
            "Delete unauthorized rules via command line or configuration GUI",
            "Reconfigure registry or startup settings to default security posture and audit via GPO or config management"
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1562.004", "example": "Using `netsh` or `Set-NetFirewallProfile` to disable firewall on infected host"},
            {"tactic": "Lateral Movement", "technique": "T1021", "example": "Opening ports for RDP or SMB to enable remote connection"}
        ],
        "watchlist": [
            "Repeated use of firewall-related commands by unexpected users",
            "Inbound traffic allowed on uncommon ports post rule change",
            "Event 4948 (A rule was modified) on critical assets"
        ],
        "enhancements": [
            "Use EDR solutions to lock and monitor system firewall configurations",
            "Leverage configuration monitoring (e.g., osquery, Wazuh) to detect drift in rule sets",
            "Deploy canary rules and alert if modified or deleted"
        ],
        "summary": "T1562.004 outlines how adversaries may weaken host defenses by disabling or modifying firewall settings. This technique enables lateral movement, C2, and data exfiltration, bypassing perimeter and host-based controls. Close monitoring of firewall service state and configuration changes is critical for detection and response.",
        "remediation": "Harden and monitor firewall configuration using Group Policy and system management tools. Set alerts for unexpected changes and maintain strict access controls for rule modifications.",
        "improvements": "Implement integrity checks for firewall policies and alert on rule modification attempts. Automate rollback procedures for unauthorized rule changes.",
        "mitre_version": "16.1"
    }
