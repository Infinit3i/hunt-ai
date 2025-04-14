def get_content():
    return {
        "id": "T1201",
        "url_id": "T1201",
        "title": "Password Policy Discovery",
        "description": "Adversaries may attempt to access detailed information about the password policy used within an enterprise network or cloud environment. This information may help the adversary create password lists that conform to the organization's policy, improving the effectiveness of brute force or dictionary attacks while avoiding account lockouts.",
        "tags": ["discovery", "password policy", "recon", "brute force prep", "cloud recon"],
        "tactic": "Discovery",
        "protocol": "",
        "os": "IaaS, Identity Provider, Linux, Network, Office Suite, SaaS, Windows, macOS",
        "tips": [
            "Monitor for enumeration commands like net accounts, Get-ADDefaultDomainPasswordPolicy, or AWS GetAccountPasswordPolicy.",
            "Correlate password policy discovery attempts with other reconnaissance activity."
        ],
        "data_sources": "Command, Process, User Account",
        "log_sources": [
            {"type": "Command", "source": "", "destination": ""},
            {"type": "Process", "source": "", "destination": ""},
            {"type": "User Account", "source": "", "destination": ""}
        ],
        "source_artifacts": [],
        "destination_artifacts": [],
        "detection_methods": [
            "Alert on password policy discovery tools and commands.",
            "Monitor PowerShell and shell usage across endpoints.",
            "Inspect IAM and AD logs for read requests to password policies."
        ],
        "apt": ["Chimera", "Orangeworm", "ComRAT", "CuckooBees", "APT groups targeting cloud IAM"],
        "spl_query": [
            "index=windows sourcetype=Sysmon \n| search CommandLine=*Get-ADDefaultDomainPasswordPolicy* OR CommandLine=*net accounts* \n| stats count by user, host"
        ],
        "hunt_steps": [
            "Search endpoint telemetry for command usage tied to password policy reading.",
            "Review logs for access to password policy via cloud APIs like AWS GetAccountPasswordPolicy.",
            "Cross-reference with user role and activity context."
        ],
        "expected_outcomes": [
            "Identification of potential pre-attack reconnaissance for brute force.",
            "Baseline knowledge of password policy access patterns."
        ],
        "false_positive": "Administrators and auditors may use these commands during legitimate operations.",
        "clearing_steps": [
            "Restrict unnecessary user access to password policy information.",
            "Audit IAM permissions and PowerShell command usage logs."
        ],
        "clearing_playbook": [
            # "https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-credential-access"  # Not 200 OK at time of check
        ],
        "mitre_mapping": [
            {"tactic": "Credential Access", "technique": "T1110", "example": "Password policy discovery leads to tailored brute force attempts."}
        ],
        "watchlist": [
            "PowerShell usage of Get-ADDefaultDomainPasswordPolicy",
            "Cloud API calls to GetAccountPasswordPolicy from unusual roles"
        ],
        "enhancements": [
            "Enable script block logging in PowerShell.",
            "Set alerts for read access to IAM password policy settings."
        ],
        "summary": "Password policy discovery enables adversaries to tailor brute force or password spray attacks based on an organization’s credential standards.",
        "remediation": "Limit exposure of password policies to only those who require it. Monitor and restrict access through auditing and access control policies.",
        "improvements": "Enhance alerting around access to sensitive IAM policy data and improve script monitoring on endpoints.",
        "mitre_version": "16.1"
    }