def get_content():
    return {
        "id": "T1056.002",
        "url_id": "T1056.002",
        "title": "Input Capture: GUI Input Capture",
        "description": "Adversaries may mimic common operating system GUI components to prompt users for credentials with a seemingly legitimate prompt. When programs are executed that need additional privileges than are present in the current user context, it is common for the operating system to prompt the user for proper credentials to authorize the elevated privileges for the task. Adversaries may mimic this functionality to prompt users for credentials with a seemingly legitimate prompt for a number of reasons that mimic normal usage, such as a fake installer requiring additional access or a fake malware removal suite.",
        "tags": ["Collection", "Credential Access"],
        "tactic": "Collection",
        "protocol": "",
        "os": "Linux, Windows, macOS",
        "tips": [
            "Monitor process execution for unusual programs and malicious scripting interpreters that prompt users for credentials.",
            "Inspect input prompts for indicators of illegitimacy, such as non-traditional banners or text, unusual timing, or suspicious sources."
        ],
        "data_sources": "Command: Command Execution, Process: Process Creation, Script: Script Execution",
        "log_sources": [
            {"type": "Process", "source": "Process Creation", "destination": ""},
            {"type": "Command", "source": "Command Execution", "destination": ""},
            {"type": "Script", "source": "Script Execution", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Malicious Code", "location": "Injected into system prompts", "identify": "Fake credential prompts"}
        ],
        "destination_artifacts": [
            {"type": "Captured Input", "location": "Credential input dialogs", "identify": "Captured user credentials or sensitive information"}
        ],
        "detection_methods": [
            "Monitor for command/script history and abnormal parameters, such as requests for credentials or strings related to creating password prompts.",
            "Inspect prompt banners, text, and sources to detect potential illegitimacy in input capture techniques."
        ],
        "apt": ["Matthew Molyett, @s1air, Cisco Talos"],
        "spl_query": [
            "| index=sysmon sourcetype=process | search 'credential prompt' OR 'password input'"
        ],
        "hunt_steps": [
            "Monitor for processes that are masquerading as legitimate credential input dialogs.",
            "Detect unusual command or script executions attempting to create prompts that request credentials."
        ],
        "expected_outcomes": [
            "Detection of input capture attempts through GUI mimicry and credential input dialogs."
        ],
        "false_positive": "False positives may occur from legitimate user prompts for credentials, particularly in enterprise environments. Review for abnormal timing or request patterns.",
        "clearing_steps": [
            "Terminate the malicious process mimicking a legitimate prompt.",
            "Restore system integrity and remove any injected code that might have captured credentials."
        ],
        "mitre_mapping": [
            {"tactic": "Collection", "technique": "T1056.002", "example": "Mimic OS prompts to collect user credentials."}
        ],
        "watchlist": [
            "Watch for abnormal behavior in command execution and processes related to GUI prompts.",
            "Monitor for suspicious input dialogs and scripts that request sensitive user data."
        ],
        "enhancements": [
            "Improve detection rules by correlating suspicious process creation with known patterns of credential capture tools."
        ],
        "summary": "GUI Input Capture involves adversaries mimicking legitimate OS GUI components to deceive users into providing sensitive credentials. These fake prompts can be used in a variety of ways to collect user input, often exploiting user trust in common system dialogs.",
        "remediation": "Terminate the malicious process and restore system integrity by removing any injected code used for capturing credentials.",
        "improvements": "Adjust monitoring to include suspicious command or script executions that could trigger fake credential prompts.",
        "mitre_version": "16.1"
    }
