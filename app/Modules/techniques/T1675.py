def get_content():
    return {
        "id": "T1675",
        "url_id": "T1675",
        "title": "ESXi Administration Command",
        "description": "Adversaries may abuse ESXi administration services to execute commands on guest machines hosted within an ESXi virtual environment via VMware Tools Daemon Service or vSphere Web Services SDK APIs.",
        "tags": ["esxi", "execution", "vmware", "guest operations", "vmtoolsd", "vsphere api"],
        "tactic": "execution",
        "protocol": "",
        "os": "ESXi",
        "tips": [
            "Limit Guest Operations privileges on ESXi to only necessary accounts.",
            "Monitor vSphere SDK API calls such as StartProgramInGuest, ListProcessesInGuest.",
            "Use behavioral baselines to detect unusual API use from ESXi IPs."
        ],
        "data_sources": "Application Log",
        "log_sources": [
            {"type": "Application", "source": "ESXi Host", "destination": "Guest VM"}
        ],
        "source_artifacts": [
            {"type": "VMware Logs", "location": "/var/log/vmware/", "identify": "GuestOperations executed such as StartProgramInGuest"}
        ],
        "destination_artifacts": [
            {"type": "VM Guest Logs", "location": "/var/log/vmtoolsd.log", "identify": "Injected execution requests or file transfers"}
        ],
        "detection_methods": [
            "Monitor Guest Operation API activity from ESXi to VM (e.g., StartProgramInGuest)",
            "Watch for unusual operations involving non-admin users or rarely managed VMs"
        ],
        "apt": [],
        "spl_query": [
            "sourcetype=\"vmware:log\"| eval guest_operation=coalesce('eventMessage', 'message')\n| search guest_operation=\"StartProgramInGuest\" OR guest_operation=\"ListProcessesInGuest\" OR guest_operation=\"ListFileInGuest\" OR guest_operation=\"InitiateFileTransferFromGuest\"\n| stats count by host, vm_name, user, guest_operation, _time\n| eventstats count as total_operations by host\n| where total_operations > 10 OR (user!=\"expected_admin\" AND total_operations > 1)\n| table _time, host, vm_name, user, guest_operation"
        ],
        "hunt_steps": [
            "Identify VMs with unexpected guest operations from ESXi hosts.",
            "Correlate API calls with process execution or file changes inside the guest.",
            "Review admin account activity for abnormal volume or source IP anomalies."
        ],
        "expected_outcomes": [
            "Detection of abuse of ESXi Guest Operations APIs for hidden execution."
        ],
        "false_positive": "Automation tools using Guest Operations may resemble this behavior. Correlate with account and timing patterns.",
        "clearing_steps": [
            "Remove unauthorized application or script access to Guest Operations.",
            "Audit ESXi user privileges for anomalies.",
            "Restrict vmtoolsd service where possible."
        ],
        "mitre_mapping": [
            {"tactic": "execution", "technique": "T1675", "example": "Abuse of StartProgramInGuest to run code inside VM"}
        ],
        "watchlist": [
            "Excessive StartProgramInGuest from a single ESXi IP",
            "VMs with no admin activity showing unexpected guest operations"
        ],
        "enhancements": [
            "Enable verbose auditing on vmtoolsd or use hypervisor-based EDR hooks.",
            "Alert on Guest Operations targeting non-standard VM accounts."
        ],
        "summary": "This technique enables adversaries to run commands in guest OS environments from the hypervisor by leveraging legitimate ESXi administrative capabilities.",
        "remediation": "Enforce strict role-based access to vSphere Guest Operations. Monitor API usage and remove unnecessary permissions.",
        "improvements": "Automate alerting when Guest Operations are initiated outside maintenance windows or by unrecognized users.",
        "mitre_version": "17.0"
    }
