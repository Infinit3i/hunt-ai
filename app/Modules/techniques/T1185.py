def get_content():
    return {
        "id": "T1185",  # Tactic Technique ID
        "url_id": "1185",  # URL segment for technique reference
        "title": "Browser Session Hijacking",  # Name of the attack technique
        "description": "Adversaries may take advantage of security vulnerabilities and inherent functionality in browser software to change content, modify user behaviors, and intercept information as part of various browser session hijacking techniques. A specific example is when an adversary injects software into a browser that allows them to inherit cookies, HTTP sessions, and SSL client certificates of a user then use the browser as a way to pivot into an authenticated intranet. Executing browser-based behaviors such as pivoting may require specific process permissions, such as SeDebugPrivilege and/or high-integrity/administrator rights. Another example involves pivoting browser traffic from the adversary's browser through the user's browser by setting up a proxy which will redirect web traffic. This does not alter the user's traffic in any way, and the proxy connection can be severed as soon as the browser is closed. The adversary assumes the security context of whichever browser process the proxy is injected into. With these permissions, an adversary could potentially browse to any resource on an intranet, such as SharePoint or webmail, that is accessible through the browser and which the browser has sufficient permissions. Browser pivoting may also bypass security provided by 2-factor authentication.",  
        "tags": [],  
        "tactic": "Collection",  
        "protocol": "Windows",  
        "os": "Windows",  
        "tips": [
            "Monitor for Process Injection against browser applications.",
            "Authentication logs can be used to audit logins to specific web applications.",
            "Monitor process behavior for suspicious modifications to browser memory.",
            "Monitor network traffic for abnormal patterns that may indicate session hijacking."
        ],  
        "data_sources": "Logon Session: Logon Session Creation, Process: Process Access, Process: Process Modification",  
        "log_sources": [  
            {"type": "Authentication Logs", "source": "Web Application Logins", "destination": "Security Logs"}  
        ],  
        "source_artifacts": [  
            {"type": "Browser Session Data", "location": "%APPDATA%/Mozilla/Firefox/Profiles", "identify": "Firefox User Sessions"},  
            {"type": "Browser Session Data", "location": "%LOCALAPPDATA%/Google/Chrome/User Data", "identify": "Chrome User Sessions"}  
        ],  
        "destination_artifacts": [  
            {"type": "Log File", "location": "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx", "identify": "Windows Security Event Logs"}  
        ],  
        "detection_methods": ["Process Injection Monitoring", "Authentication Log Analysis"],  
        "apt": ["TrickBot", "IcedID", "Qakbot", "Agent Tesla", "Dridex"],  
        "spl_query": ["index=windows_logs | search browser_session_hijack"],  
        "hunt_steps": ["Check for unauthorized access to browser session data.", "Analyze process injection attempts targeting browser processes."],  
        "expected_outcomes": ["Detection of unauthorized browser session hijacking activities."],  
        "false_positive": "Legitimate security tools may access browser session data for monitoring.",  
        "clearing_steps": ["Terminate unauthorized processes accessing browser session data.", "Reset active browser sessions and clear cookies."],  
        "mitre_mapping": [
            {"tactic": "Collection", "technique": "T1185", "example": "Adversaries injecting into browser processes to hijack authenticated sessions."}
        ],  
        "watchlist": ["Processes injecting into browsers", "Unusual authentication activity in web applications"],  
        "enhancements": ["Restrict access to browser session storage.", "Implement endpoint security tools that detect process injection attempts."],  
        "summary": "Browser session hijacking allows adversaries to gain unauthorized access to authenticated user sessions, potentially bypassing security controls such as multi-factor authentication.",  
        "remediation": "Monitor and restrict process injection into browser applications to prevent session hijacking.",  
        "improvements": "Enhance browser security configurations to prevent unauthorized access to session data."  
    }
