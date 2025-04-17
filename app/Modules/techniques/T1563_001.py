def get_content():
    return {
        "id": "T1563.001",
        "url_id": "T1563/001",
        "title": "Remote Service Session Hijacking: SSH Hijacking",
        "description": "Adversaries may hijack a legitimate user's SSH session to move laterally within an environment. This may occur by compromising the SSH agent or gaining access to the agent's socket, allowing adversaries to pivot to systems where public key authentication has been established.",
        "tags": ["lateral movement", "ssh", "session hijacking", "agent socket", "ssh-agent"],
        "tactic": "Lateral Movement",
        "protocol": "SSH",
        "os": "Linux, macOS",
        "tips": [
            "Monitor for unauthorized use of SSH agent sockets by unexpected users.",
            "Flag sudden SSH session reuse from high-privileged users.",
            "Check for hijack attempts where ssh-agent forwarding is enabled."
        ],
        "data_sources": "Command, Logon Session, Network Traffic, Process",
        "log_sources": [
            {"type": "Command", "source": "", "destination": ""},
            {"type": "Logon Session", "source": "", "destination": ""},
            {"type": "Network Traffic", "source": "", "destination": ""},
            {"type": "Process", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Process List", "location": "/proc", "identify": "ssh-agent or hijack tools"},
            {"type": "File Access Times", "location": "~/.ssh", "identify": "socket file timestamps or reuse"},
            {"type": "Environment Variables", "location": "env", "identify": "SSH_AUTH_SOCK set"}
        ],
        "destination_artifacts": [
            {"type": "Network Connections", "location": "netstat/lsof", "identify": "persistent SSH tunnels"},
            {"type": "Logon Session", "location": "auth.log or journalctl", "identify": "unexpected reuse of sessions"},
            {"type": "Event Logs", "location": "/var/log/auth.log", "identify": "existing sessions reused"}
        ],
        "detection_methods": [
            "File integrity monitoring on SSH agent sockets",
            "Alert on ssh-agent forwarding from untrusted hosts",
            "Detect overlapping ssh sessions between users or reused agent keys"
        ],
        "apt": ["Lazarus Group", "APT28", "Equation Group"],
        "spl_query": [
            "index=linux_logs sourcetype=authlog ssh-agent\n| stats count by user, src_ip, dest_ip",
            "index=linux_logs sourcetype=ps command=\"*ssh-agent*\"\n| stats count by user, host"
        ],
        "hunt_steps": [
            "Enumerate all active SSH sessions and related sockets",
            "Check ~/.ssh/authorized_keys and ~/.ssh/config for anomalies",
            "Identify long-running agents and correlate with login sessions"
        ],
        "expected_outcomes": [
            "Detection of reused agent sockets",
            "Correlation between SSH hijack and lateral session pivots",
            "Identification of agent compromise tools or commands"
        ],
        "false_positive": "Legitimate use of ssh-agent forwarding in environments like development systems or automation pipelines.",
        "clearing_steps": [
            "Remove malicious public keys: `rm ~/.ssh/authorized_keys` (after validation)",
            "Kill hijacked sessions: `pkill -u <user>` or `kill <ssh pid>`",
            "Clear bash history: `> ~/.bash_history; history -c`"
        ],
        "clearing_playbook": ["https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-credential-theft"],
        "mitre_mapping": [
            {"tactic": "Credential Access", "technique": "T1552", "example": "The adversary may access SSH agent secrets stored in memory"},
            {"tactic": "Defense Evasion", "technique": "T1027", "example": "Use of stealthy scripts to access agent sockets"}
        ],
        "watchlist": [
            "Access to SSH_AUTH_SOCK by non-owner processes",
            "Unexpected users with long-lived ssh-agent sessions",
            "Agent forwarding on critical systems"
        ],
        "enhancements": [
            "Deploy endpoint monitoring of SSH agent usage",
            "Enable mandatory access control (MAC) to isolate agent sockets",
            "Disable ssh-agent forwarding in production environments"
        ],
        "summary": "SSH Hijacking involves taking over an already established SSH session—usually by exploiting the ssh-agent socket or memory—allowing attackers to reuse credentials and pivot laterally within the network without triggering new authentication.",
        "remediation": "Restrict agent forwarding, rotate SSH keys, apply least privilege to key usage, and enforce session locking.",
        "improvements": "Add logging for SSH_AUTH_SOCK usage, integrate alerting for agent misuse, and maintain audit trails for socket access.",
        "mitre_version": "16.1"
    }
