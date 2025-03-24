def get_content():
    return {
        "id": "T1056.004",
        "url_id": "T1056.004",
        "title": "Input Capture: Credential API Hooking",
        "description": "Adversaries may hook into Windows application programming interface (API) functions to collect user credentials. Malicious hooking mechanisms may capture API calls that include parameters that reveal user authentication credentials. Unlike Keylogging, this technique focuses specifically on API functions that include parameters that reveal user credentials. Hooking involves redirecting calls to these functions and can be implemented via:\n\n- Hooks procedures, which intercept and execute designated code in response to events such as messages, keystrokes, and mouse inputs.\n- Import address table (IAT) hooking, which uses modifications to a process’s IAT, where pointers to imported API functions are stored.\n- Inline hooking, which overwrites the first bytes in an API function to redirect code flow.",
        "tags": ["Collection", "Credential Access"],
        "tactic": "Collection",
        "protocol": "",
        "os": "Windows",
        "tips": [
            "Monitor for calls to the `SetWindowsHookEx` and `SetWinEventHook` functions, which install a hook procedure.",
            "Use tools to analyze hook chains and internal kernel structures to detect abnormal hooking behavior."
        ],
        "data_sources": "Process: OS API Execution, Process: Process Metadata",
        "log_sources": [
            {"type": "Process", "source": "OS API Execution", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Injected Code", "location": "API Hooking", "identify": "Malicious Hooking Code"}
        ],
        "destination_artifacts": [
            {"type": "Captured Credentials", "location": "Captured User Input", "identify": "User Authentication Credentials"}
        ],
        "detection_methods": [
            "Monitor for function calls such as `SetWindowsHookEx` and `SetWinEventHook`.",
            "Examine hook chains with specialized tools to detect unusual API redirections.",
            "Use rootkit detection tools to monitor for various types of hooking activity."
        ],
        "apt": [
            "TrendMicro Ursnif Mar 2015", "Talos ZxShell Oct 2014", "Github PowerShell Empire", "Unit 42 NOKKI Sept 2018", 
            "Microsoft PLATINUM April 2016", "TrendMicro Trickbot Feb 2019", "Securelist Sofacy Feb 2018", 
            "FireEye FIN7 Oct 2019", "Lumen Versa 2024", "FinFisher Citation", "GDATA Zeus Panda June 2017", 
            "Elastic Process Injection July 2017", "Prevx Carberp March 2011"
        ],
        "spl_query": [
            "| index=windows_logs sourcetype=api_calls | search 'SetWindowsHookEx' OR 'SetWinEventHook'"
        ],
        "hunt_steps": [
            "Identify any unusual hooking activity by analyzing API call flows.",
            "Look for instances where normal application execution is interrupted or redirected to malicious functions."
        ],
        "expected_outcomes": [
            "Detection of malicious API hooks capturing user credentials."
        ],
        "false_positive": "False positives may occur from legitimate use of hooks in software. Correlate detected hooks with known software behavior.",
        "clearing_steps": [
            "Remove any malicious hooks and restore the original API calls.",
            "Monitor for any new instances of the hooking behavior."
        ],
        "mitre_mapping": [
            {"tactic": "Collection", "technique": "T1056.004", "example": "Credential API Hooking to capture user authentication data."}
        ],
        "watchlist": [
            "Monitor for abnormal use of API hooking in security-sensitive applications.",
            "Investigate any unexpected modifications to in-memory IATs or inline hooks."
        ],
        "enhancements": [
            "Implement behavioral analysis to detect deviations in normal application API usage patterns."
        ],
        "summary": "Credential API Hooking involves redirecting API calls to capture user credentials by manipulating the application’s API flow. This technique is commonly used to intercept authentication-related API functions.",
        "remediation": "Remove any malicious hooks from the process and restore integrity to the affected system.",
        "improvements": "Strengthen monitoring and detection of unusual API call patterns, particularly related to credential access.",
        "mitre_version": "16.1"
    }
