def get_content():
    """
    Returns structured content for the Process Injection technique.
    """
    return {
        "id": "T1055",
        "url_id": "T1055",
        "title": "Process Injection",
        "tactic": "Defense Evasion, Privilege Escalation",
        "data_sources": "Process monitoring, Windows Event Logs, Memory forensic analysis",
        "protocol": "N/A",
        "os": "Windows, Linux, macOS",
        "objective": "Adversaries inject malicious code into legitimate processes to evade detection and gain higher privileges.",
        "scope": "Monitor process creation and memory modifications for unauthorized injections.",
        "threat_model": "Attackers leverage process injection to execute arbitrary code within another process, bypassing security controls and maintaining stealth.",
        "hypothesis": [
            "Are there unexpected process injections occurring on critical systems?",
            "Are security tools being targeted for injection to disable defenses?",
            "Are legitimate processes executing unexpected code?"
        ],
        "tips": [
            "Monitor API calls related to process injection, such as VirtualAllocEx, WriteProcessMemory, and CreateRemoteThread.",
            "Enable event logging for process creation (Event ID 4688) and command-line auditing.",
            "Analyze memory dumps for injected code and suspicious process relationships."
        ],
        "log_sources": [
            {"type": "Windows Event Logs", "source": "Security.evtx", "destination": "System.evtx"},
            {"type": "Process Monitoring", "source": "Sysmon Event ID 8, 10", "destination": "Memory Analysis"}
        ],
        "source_artifacts": [
            {"type": "Memory Analysis", "location": "Volatility Plugins", "identify": "Injected code segments"}
        ],
        "destination_artifacts": [
            {"type": "Process Execution", "location": "Task Manager, Process Explorer", "identify": "Suspicious parent-child process relationships"}
        ],
        "detection_methods": [
            "Monitor Sysmon logs for remote thread creation (Event ID 8, 10).",
            "Detect anomalies in process execution flow using behavior analytics.",
            "Analyze process memory for unauthorized code injections."
        ],
        "apt": ["G0032", "G0096"],
        "spl_query": [
            "index=windows EventCode=4688 | search NewProcessName IN (*rundll32.exe*, *regsvr32.exe*, *powershell.exe*)",
            "index=windows EventCode=10 | table Time, ProcessName, ParentProcess, InjectedThread"
        ],
        "hunt_steps": [
            "Identify processes exhibiting unusual memory modifications.",
            "Analyze injected code within running processes.",
            "Investigate parent-child process anomalies to detect injections."
        ],
        "expected_outcomes": [
            "Process injection attempts detected and mitigated.",
            "No malicious activity found, improving baseline detection."
        ],
        "false_positive": "Legitimate security tools and software updates may perform process injection as part of their normal operation.",
        "clearing_steps": [
            "Terminate and investigate injected processes using Process Explorer.",
            "Use memory forensics tools like Volatility to extract and analyze injected code.",
            "Reimage compromised systems if persistent injections are detected."
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1055.002 (Portable Executable Injection)", "example": "Adversaries may inject PE files into processes for stealth execution."}
        ],
        "watchlist": [
            "Monitor for unusual process creation and remote thread execution.",
            "Detect unexpected API calls related to memory allocation and execution."
        ],
        "enhancements": [
            "Implement endpoint detection and response (EDR) solutions.",
            "Harden security policies to restrict process modifications."
        ],
        "summary": "Process Injection is a technique used by adversaries to execute malicious code within legitimate processes to evade detection and escalate privileges.",
        "remediation": "Terminate injected processes, investigate persistence mechanisms, and apply security patches.",
        "improvements": "Strengthen process monitoring and enable enhanced logging for process execution events."
    }
