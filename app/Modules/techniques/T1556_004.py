def get_content():
    return {
        "id": "T1556.004",
        "url_id": "T1556/004",
        "title": "Modify Authentication Process: Network Device Authentication",
        "description": "Adversaries may modify operating system images of network devices to implant hardcoded backdoor passwords. These modifications allow bypassing of native authentication mechanisms, granting attackers access when a specific password is used. The injected code may check inputs for this backdoor password and only perform normal verification if it is not matched.",
        "tags": ["Network Device", "Backdoor Password", "System Image Patch", "Credential Bypass", "Persistence"],
        "tactic": "Credential Access, Defense Evasion, Persistence",
        "protocol": "",
        "os": "Network",
        "tips": [
            "Use firmware checksums to validate image integrity.",
            "Monitor for unauthorized firmware updates.",
            "Employ memory verification if supported by the device vendor.",
            "Review access logs for successful logins from non-standard credentials."
        ],
        "data_sources": "File: File Modification",
        "log_sources": [
            {"type": "File", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "File", "location": "/flash/system_image", "identify": "Patched firmware with embedded credentials"}
        ],
        "destination_artifacts": [],
        "detection_methods": [
            "Firmware hash verification",
            "Bootloader image validation",
            "Memory comparison with golden image",
            "Unexpected credential acceptance from audit logs"
        ],
        "apt": [
            "Synful Knock"
        ],
        "spl_query": [
            "index=network_logs source=auth_logs OR source=firmware\n| search event=auth_success AND user!=known_users"
        ],
        "hunt_steps": [
            "Identify systems with non-standard OS images.",
            "Scan for hardcoded strings in system image.",
            "Verify login logs for anomalous accounts."
        ],
        "expected_outcomes": [
            "Successful unauthorized access via backdoor password",
            "Detection of altered firmware image"
        ],
        "false_positive": "Vendor firmware updates may also alter image hashes. Always validate changes against signed and approved firmware baselines.",
        "clearing_steps": [
            "Reflash device with verified vendor image.",
            "Reset all administrative credentials.",
            "Verify secure boot and runtime image protection if available."
        ],
        "clearing_playbook": [
            "https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-phishing"
        ],
        "mitre_mapping": [
            {"tactic": "Persistence", "technique": "T1601", "example": "Hardcoded backdoor in network OS image."}
        ],
        "watchlist": [
            "Authentication from new or hidden credentials",
            "Image hash mismatches on firmware check",
            "Unexpected reboots or image loading operations"
        ],
        "enhancements": [
            "Deploy image verification solutions across fleet.",
            "Audit authentication flows for hardcoded password matches"
        ],
        "summary": "Attackers can bypass authentication on network devices by modifying the OS image to insert backdoor credentials. This grants persistent and covert access until the image is restored.",
        "remediation": "Immediately restore trusted firmware, rotate access credentials, and monitor for repeat compromise.",
        "improvements": "Implement image verification at boot time and ensure logs include credential source tracing.",
        "mitre_version": "16.1"
    }
