def get_content():
    return {
        "id": "T1542.005",
        "url_id": "T1542/005",
        "title": "Pre-OS Boot: TFTP Boot",
        "description": "Adversaries may abuse netbooting to load an unauthorized network device operating system from a Trivial File Transfer Protocol (TFTP) server. TFTP boot (netbooting) is commonly used by network administrators to load configuration-controlled network device images from a centralized management server. Adversaries may manipulate the configuration on the network device specifying use of a malicious TFTP server, which may be used in conjunction with Modify System Image to load a modified image on device startup or reset.",
        "tags": ["boot", "firmware", "tftp", "persistence", "defense evasion", "pre-os", "network device"],
        "tactic": "defense-evasion",
        "protocol": "tftp",
        "os": "Network",
        "tips": "Ensure all network boot servers are authorized and monitored. Maintain cryptographic integrity checks of images.",
        "data_sources": "Command: Command Execution, Firmware: Firmware Modification, Network Traffic: Network Connection Creation",
        "log_sources": [
            {"type": "network device", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            "TFTP boot request", "Boot configuration commands", "Startup config modifications"
        ],
        "destination_artifacts": [
            "Boot image replacement", "Unauthorized firmware load", "Untrusted TFTP server communication"
        ],
        "detection_methods": [
            "Compare device config and system image against known-good", 
            "Analyze command history and boot logs", 
            "Monitor TFTP traffic to/from sensitive devices"
        ],
        "apt": [
            "Synful Knock"
        ],
        "spl_query": [
            "`tftp_logs` \n| search command=put OR command=get \n| stats count by src_ip, dest_ip, filename, command \n| where filename IN ("*.bin", "*.img")"
        ],
        "hunt_steps": [
            "Review all TFTP transactions from the last 30 days.",
            "Check running configurations for boot image paths.",
            "Validate image hashes against golden images."
        ],
        "expected_outcomes": [
            "Unauthorized boot image detected.",
            "Unusual TFTP transfer to/from sensitive device."
        ],
        "false_positive": "Legitimate administrator actions using TFTP for authorized updates.",
        "clearing_steps": [
            "no boot system tftp://<malicious_ip>/<file>",
            "copy tftp://<trusted_ip>/<clean_image> flash:",
            "boot system flash:<clean_image>",
            "reload"
        ],
        "mitre_mapping": [
            {"tactic": "Persistence", "technique": "Pre-OS Boot: TFTP Boot", "example": "Loading malicious image via TFTP on Cisco device"}
        ],
        "watchlist": [
            "TFTP requests from internal network to unknown IPs",
            "Repeated configuration changes to boot system"
        ],
        "enhancements": [
            "Enable secure boot mechanisms",
            "Deploy firmware integrity validation tools"
        ],
        "summary": "TFTP boot is a potential pre-OS persistence vector for network device firmware modification and backdoor deployment.",
        "remediation": "Validate all boot configurations, verify image hashes, restrict TFTP access to management-only segments.",
        "improvements": "Adopt cryptographic signature enforcement for boot images. Utilize secure boot technologies.",
        "mitre_version": "16.1"
    }
