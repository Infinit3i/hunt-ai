def get_content():
    return {
        "id": "T1111",
        "url_id": "T1111",
        "title": "Multi-Factor Authentication Interception",
        "description": "Adversaries may target multi-factor authentication (MFA) mechanisms, such as smart cards or token generators, to gain access to credentials that can be used to access systems, services, and network resources.",
        "tags": ["mfa", "interception", "credential access", "token replay", "sms hijack"],
        "tactic": "credential-access",
        "protocol": "",
        "os": "Linux, Windows, macOS",
        "tips": [
            "Monitor for keylogging activity and driver installations",
            "Alert on use of API calls linked to input capture (e.g., SetWindowsHookEx)",
            "Log and investigate anomalous logins using smart card auth"
        ],
        "data_sources": "Driver, Process, Windows Registry",
        "log_sources": [
            {"type": "Driver", "source": "endpoint", "destination": ""},
            {"type": "Process", "source": "EDR", "destination": ""},
            {"type": "Windows Registry", "source": "endpoint", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Registry Hives", "location": "HKLM\\SYSTEM\\CurrentControlSet\\Services", "identify": "Injected or malicious smart card drivers"},
            {"type": "Loaded DLLs", "location": "user32.dll, advapi32.dll", "identify": "Hooks or polling for keystrokes"},
            {"type": "Event Logs", "location": "Microsoft-Windows-Security-Auditing", "identify": "Login activity using smart card provider"}
        ],
        "destination_artifacts": [
            {"type": "Process List", "location": "Live memory or tasklist", "identify": "MFA-intercepting malware (keyloggers, proxy agents)"},
            {"type": "Clipboard Data", "location": "User context", "identify": "Copied MFA tokens or intercepted one-time codes"},
            {"type": "Windows Defender Logs", "location": "C:\\ProgramData\\Microsoft\\Windows Defender\\", "identify": "Detected keylogger activity or suspicious authentication proxy"}
        ],
        "detection_methods": [
            "Detect driver loads associated with input capture",
            "Monitor for registry modifications related to keyboard hooks or smart card services",
            "Correlate user logins with known active session input capture"
        ],
        "apt": [
            "Wocao", "Sykipot", "DEV-0537", "Chimera"
        ],
        "spl_query": [
            'index=wineventlog EventCode=4656 \n| search ObjectName="\\Device\\KeyboardClass0" OR ObjectName="\\Device\\MouClass0" \n| stats count by ProcessName, ObjectName',
            'index=sysmon EventCode=7 \n| search ImageLoaded="*\\keylogger.dll" OR ImageLoaded="*\\advapi32.dll" \n| stats count by Image, ImageLoaded',
            'index=wineventlog EventCode=4688 \n| where NewProcessName="*\\tokenproxy.exe" OR CommandLine="*smartcard*"'
        ],
        "hunt_steps": [
            "Hunt for unauthorized drivers targeting keyboard/mouse input classes",
            "Investigate abnormal registry changes tied to smart card services",
            "Review clipboard access events and suspicious MFA workflows"
        ],
        "expected_outcomes": [
            "Detection of keyloggers or token interception tools",
            "Identification of compromised systems acting as smart card proxies",
            "Disruption of adversary access dependent on MFA interception"
        ],
        "false_positive": "Legitimate remote desktop software or accessibility tools may hook input or interact with smart card services. Validate usage and source.",
        "clearing_steps": [
            "Remove unauthorized drivers and untrusted MFA-intercepting software",
            "Revoke and reissue smart cards or hardware tokens tied to compromised sessions",
            "Rotate associated passwords and seed values if OTP generators were exposed"
        ],
        "mitre_mapping": [
            {"tactic": "collection", "technique": "T1056.001", "example": "Keylogging used to capture smart card PINs"},
            {"tactic": "defense-evasion", "technique": "T1562.001", "example": "Disable or modify input logging tools"},
            {"tactic": "initial-access", "technique": "T1078", "example": "Use of captured MFA credentials for valid account login"}
        ],
        "watchlist": [
            "Smart card authentications from unusual machines or IP ranges",
            "Repeated failed OTP attempts followed by success",
            "Clipboard access by background services"
        ],
        "enhancements": [
            "Implement out-of-band verification for high-risk MFA",
            "Alert on unrecognized drivers touching device class: keyboard/mouse",
            "Use hardware-based FIDO tokens instead of SMS/email MFA"
        ],
        "summary": "Adversaries may attempt to intercept multi-factor authentication codes, including hardware token input or SMS messages, to bypass account security mechanisms and gain access to sensitive systems.",
        "remediation": "Use phishing-resistant MFA, monitor for interception behaviors, and rotate credentials tied to exposed tokens or smart cards.",
        "improvements": "Incorporate behavioral biometrics or FIDO2 authentication to reduce reliance on interceptable MFA channels.",
        "mitre_version": "16.1"
    }
