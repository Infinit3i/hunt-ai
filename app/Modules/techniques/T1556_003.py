def get_content():
    return {
        "id": "T1556.003",
        "url_id": "T1556/003",
        "title": "Modify Authentication Process: Pluggable Authentication Modules",
        "description": "Adversaries may modify Pluggable Authentication Modules (PAM) on Unix-like systems to backdoor or intercept user credentials. PAM controls authentication through configurable modules like pam_unix.so, which interfaces with files like /etc/passwd and /etc/shadow. Attackers may patch these libraries or configuration files to bypass authentication or steal passwords.",
        "tags": ["PAM", "Linux", "macOS", "Credential Theft", "Backdoor", "Authentication Bypass"],
        "tactic": "Credential Access, Defense Evasion, Persistence",
        "protocol": "",
        "os": "Linux, macOS",
        "tips": [
            "Monitor /etc/pam.d/ for unauthorized changes.",
            "Use integrity checking tools like AIDE to baseline PAM files.",
            "Log login session events and correlate with physical access.",
            "Audit modified pam_unix.so binaries or other PAM libraries."
        ],
        "data_sources": "File: File Modification, Logon Session: Logon Session Creation",
        "log_sources": [
            {"type": "File", "source": "", "destination": ""},
            {"type": "Logon Session", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "File", "location": "/etc/pam.d/", "identify": "Modified PAM configuration files"},
            {"type": "Module", "location": "/lib/security/pam_unix.so", "identify": "Patched authentication logic"}
        ],
        "destination_artifacts": [],
        "detection_methods": [
            "Baseline comparison of PAM binaries and config files",
            "Auditd logging of access to pam_unix.so",
            "Login anomaly detection across shared accounts",
            "System call tracing for credential harvesting code"
        ],
        "apt": [
            "Skidmap",
            "Ebury"
        ],
        "spl_query": [
            "index=linux_logs path=/etc/pam.d/* OR path=*pam_unix.so\n| search action=modify OR hash!=baseline"
        ],
        "hunt_steps": [
            "Scan PAM config files for unknown module entries.",
            "Verify checksums of PAM shared objects.",
            "Check for abnormal shell spawns tied to PAM sessions."
        ],
        "expected_outcomes": [
            "Credential theft via modified PAM logic",
            "Bypass of standard account authentication"
        ],
        "false_positive": "System updates or legitimate configuration changes may modify PAM files. Validate changes against change control records.",
        "clearing_steps": [
            "Restore PAM files from trusted backup.",
            "Reinstall affected authentication libraries.",
            "Reaudit login sessions and force password changes."
        ],
        "clearing_playbook": [
            "https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-phishing"
        ],
        "mitre_mapping": [
            {"tactic": "Persistence", "technique": "T1547", "example": "PAM backdoor via config injection or binary patching."}
        ],
        "watchlist": [
            "Changes to pam_unix.so",
            "Unexpected modules loaded from non-default paths",
            "Repeated logins during inactive hours"
        ],
        "enhancements": [
            "Implement PAM config file monitoring with auditd.",
            "Hash verification alerts for PAM binaries"
        ],
        "summary": "PAM manipulation allows attackers to bypass or hijack authentication on Linux/macOS systems. Adversaries patch modules or config files to create persistent credential access or arbitrary login bypass.",
        "remediation": "Revert unauthorized PAM changes, verify file integrity, and force user password resets.",
        "improvements": "Extend auditd to include library and config hash tracking. Integrate anomaly detection for PAM-related session behaviors.",
        "mitre_version": "16.1"
    }
