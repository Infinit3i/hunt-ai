def get_content():
    return {
        "id": "T1055.013",
        "url_id": "T1055/013",
        "title": "Process Injection: Process Doppelgänging",
        "description": "Adversaries may inject malicious code into process via process doppelgänging in order to evade process-based defenses as well as possibly elevate privileges. Process doppelgänging is a method of executing arbitrary code in the address space of a separate live process.",
        "tags": ["Defense Evasion", "Privilege Escalation"],
        "tactic": "Defense Evasion",
        "protocol": "",
        "os": "Windows",
        "tips": [
            "Monitor for API calls indicative of TxF activity such as CreateTransaction, CreateFileTransacted, RollbackTransaction, and others.",
            "Look for unusual process creation patterns and suspicious file objects with write access."
        ],
        "data_sources": "File: File Metadata, Process: OS API Execution",
        "log_sources": [
            {"type": "File", "source": "File System", "destination": ""},
            {"type": "Process", "source": "Windows API", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Malicious Code", "location": "TxF Transaction", "identify": "Injected code via process doppelgänging"}
        ],
        "destination_artifacts": [
            {"type": "Malicious Code", "location": "TxF Transaction", "identify": "Injected code via process doppelgänging"}
        ],
        "detection_methods": [
            "Monitor for the creation and rollback of TxF transactions.",
            "Detect suspicious process creation or memory modification attempts, especially those invoking NtCreateProcessEx or NtCreateThreadEx."
        ],
        "apt": ["Symantec Leafminer", "NCC Group Team9", "Kaspersky Lab SynAck"],
        "spl_query": [
            "| index=sysmon sourcetype=process | search CreateTransaction OR CreateFileTransacted OR RollbackTransaction"
        ],
        "hunt_steps": [
            "Monitor for API calls indicative of TxF activity and file system transactions.",
            "Analyze abnormal behavior in processes, such as unauthorized memory modifications or process creation."
        ],
        "expected_outcomes": [
            "Identify injected malicious code via process doppelgänging.",
            "Detect suspicious file and memory modifications related to process doppelgänging."
        ],
        "false_positive": "Legitimate uses of TxF or process creation may trigger false positives.",
        "clearing_steps": [
            "Terminate the malicious process and restore system integrity.",
            "Remove injected code and reverse any changes made by the attack."
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1055", "example": "Use process doppelgänging to inject code into a legitimate process."}
        ],
        "watchlist": [
            "Monitor for suspicious activity involving file system transactions and process memory modifications."
        ],
        "enhancements": [
            "Enhance detection by correlating TxF activity with other post-compromise indicators."
        ],
        "summary": "Process doppelgänging allows attackers to inject code into a running process while avoiding detection by using the TxF API to create a file-less variation of process injection.",
        "remediation": "Remove the injected code and restore the normal operation of the process.",
        "improvements": "Strengthen monitoring of TxF-related API calls and correlate them with process behavior analysis.",
        "mitre_version": "16.1"
    }
