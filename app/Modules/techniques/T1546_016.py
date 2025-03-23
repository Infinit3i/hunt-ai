def get_content():
    return {
        "id": "T1546.016",
        "url_id": "T1546/016",
        "title": "Event Triggered Execution: Installer Packages",
        "description": "Adversaries may establish persistence and elevate privileges by using an installer to trigger the execution of malicious content.",
        "tags": ["installer abuse", "persistence", "privilege escalation", "macOS", "Linux", "Windows", "postinstall", "msi", "installer scripts"],
        "tactic": "Persistence, Privilege Escalation",
        "protocol": "",
        "os": "Linux, Windows, macOS",
        "tips": [
            "Monitor the execution of installer packages and scripts, especially those with elevated privileges.",
            "Track the creation of unusual files or daemons following an install."
        ],
        "data_sources": "Command, File, Process",
        "log_sources": [
            {"type": "Command", "source": "", "destination": ""},
            {"type": "File", "source": "", "destination": ""},
            {"type": "Process", "source": "", "destination": ""}
        ],
        "source_artifacts": [],
        "destination_artifacts": [],
        "detection_methods": [
            "Monitor file creation and command execution tied to installer scripts.",
            "Track processes launched from package installer paths with elevated privileges."
        ],
        "apt": [],
        "spl_query": [
            "index=linux OR index=osx process_name=*postinstall* OR process_name=*postinst*",
            "index=windows Image=*msiexec.exe* AND CommandLine=*custom action*"
        ],
        "hunt_steps": [
            "Hunt for installations creating Launch Daemons or services.",
            "Review installed packages for suspicious or modified maintainer scripts."
        ],
        "expected_outcomes": [
            "Identification of malicious installer logic used to persist or escalate privileges.",
            "Detection of unauthorized services or binaries installed via elevated install routines."
        ],
        "false_positive": "Legitimate software often includes pre- and post-install scripts. Validate integrity and origin of packages.",
        "clearing_steps": [
            "Remove any unauthorized Launch Daemons or services created.",
            "Manually review and remove suspicious files created post-install.",
            "Reinstall affected packages from trusted sources."
        ],
        "mitre_mapping": [
            {
                "tactic": "Execution",
                "technique": "T1059 - Command and Scripting Interpreter",
                "example": "Postinstall script launches terminal command with root privileges."
            }
        ],
        "watchlist": [
            "Monitor /etc/emond.d/rules/ and LaunchDaemon paths post install.",
            "Track execution of package manager binaries like dpkg, rpm, msiexec, and installer."
        ],
        "enhancements": [
            "Enable logging on installer framework tools.",
            "Use checksums to validate integrity of packages before install."
        ],
        "summary": "This technique leverages installer scripts to run malicious code during or after installation, typically with elevated privileges.",
        "remediation": "Only allow installation of packages from trusted and signed sources. Use endpoint protection tools to monitor installer behavior.",
        "improvements": "Implement allow-listing on script execution during install. Require user prompts or verification for high-privilege installs.",
        "mitre_version": "16.1"
    }
