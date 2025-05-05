def get_content():
    return {
        "id": "G0011",
        "url_id": "PittyTiger",
        "title": "PittyTiger",
        "tags": [
            "China-attribution", "espionage", "APT", "Mimikatz", "gh0stRAT", "PoisonIvy", "gsecdump"
        ],
        "description": (
            "PittyTiger is a China-based cyber espionage threat group known for using a wide variety of malware families such as "
            "gh0st RAT, PoisonIvy, and Lurid. The group has leveraged both custom and publicly available tools to maintain long-term "
            "access to victim environments. PittyTiger is particularly notable for its use of credential dumping utilities such as Mimikatz and gsecdump, "
            "along with tactics such as process injection, screen capture, and the use of encrypted channels for command-and-control (C2)."
        ),
        "associated_groups": [],
        "campaigns": [],
        "techniques": [
            "T1588.002",  # Obtain Capabilities: Tool
            "T1078"       # Valid Accounts
        ],
        "contributors": [],
        "version": "1.2",
        "created": "31 May 2017",
        "last_modified": "16 April 2025",
        "navigator": "",
        "references": [
            {"source": "Eye of the Tiger", "url": "https://www.circl.lu/pub/tr-09/"},
            {"source": "Spy of the Tiger", "url": "https://citizenlab.ca/2014/07/spy-tiger/"}
        ],
        "resources": [],
        "remediation": (
            "Implement application whitelisting and restrict execution of unauthorized binaries. "
            "Enforce least privilege access, monitor for usage of credential dumping tools like Mimikatz and gsecdump, "
            "and audit creation of new services or registry modifications tied to persistence."
        ),
        "improvements": (
            "Enhance endpoint detection with rules for common RAT behavior such as keystroke logging, clipboard monitoring, "
            "and rundll32 misuse. Add YARA rules for variants of gh0st RAT and PoisonIvy, and correlate signs of LSA/SAM access "
            "to identify credential harvesting."
        ),
        "hunt_steps": [
            "Review logs for registry modifications to autostart keys linked to gh0st RAT or PoisonIvy.",
            "Detect use of gsecdump or Mimikatz through parent-child process trees or memory access to LSASS.",
            "Analyze outbound encrypted traffic to unusual destinations or domains tied to Fast Flux DNS."
        ],
        "expected_outcomes": [
            "Detection of RAT implants with persistence.",
            "Discovery of stolen credentials via memory dumps.",
            "Identification of lateral movement through reused valid accounts."
        ],
        "false_positive": (
            "Rundll32, registry keys, and service creation are commonly used by administrators. "
            "Correlate with threat behavior such as unexpected parent processes or outbound connections for C2."
        ),
        "clearing_steps": [
            "Terminate and remove malware implants like gh0st RAT, PoisonIvy, and Lurid.",
            "Revoke and rotate all discovered valid credentials.",
            "Purge malicious registry keys and scheduled tasks used for persistence."
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": []
        }
    }
