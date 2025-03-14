def get_content():
    return {
        "id": "T1119",
        "url_id": "1119",
        "title": "Automated Collection",
        "description": "Once established within a system or network, an adversary may use automated techniques for collecting internal data. Methods for performing this technique could include use of a Command and Scripting Interpreter to search for and copy information fitting set criteria such as file type, location, or name at specific time intervals. In cloud-based environments, adversaries may also use cloud APIs, data pipelines, command line interfaces, or extract, transform, and load (ETL) services to automatically collect data. This functionality could also be built into remote access tools.",
        "tags": ["Collection", "Automated", "Cloud", "Scripting"],
        "tactic": "Collection",
        "protocol": "Command Execution, File Access, Script Execution, User Account Authentication",
        "os": "IaaS, Linux, Office Suite, SaaS, Windows, macOS",
        "tips": [
            "Monitor for unusual process executions performing sequential file opens and copy actions.",
            "Detect remote access tools interacting with the Windows API for data collection.",
            "Monitor cloud API calls that may indicate large-scale data collection."
        ],
        "data_sources": "Command, File, Script, User Account",
        "log_sources": [
            {"type": "Command", "source": "CLI", "destination": "System Logs"},
            {"type": "File", "source": "File Access", "destination": "Audit Logs"},
            {"type": "Script", "source": "Scripting Engine", "destination": "Execution Logs"}
        ],
        "source_artifacts": [
            {"type": "Script Execution", "location": "/tmp/scripts/", "identify": "Automated file enumeration scripts"}
        ],
        "destination_artifacts": [
            {"type": "File", "location": "/var/tmp/collected_data/", "identify": "Compressed or staged data files"}
        ],
        "detection_methods": [
            "Analyze sequence of file access operations for anomalies.",
            "Monitor API interactions with cloud storage and database services.",
            "Track unusual authentication requests linked to data collection."
        ],
        "apt": ["UNC3944", "APT1", "FIN6"],
        "spl_query": [
            "| search process_name=\"powershell.exe\" command_line=\"Get-ChildItem\""
        ],
        "hunt_steps": [
            "Identify processes running file enumeration commands.",
            "Check for batch execution of commands accessing multiple files.",
            "Review cloud service API logs for mass data access events."
        ],
        "expected_outcomes": [
            "Potential identification of automated data collection.",
            "Detection of suspicious file access and cloud API activities."
        ],
        "false_positive": "Legitimate automated backup processes and system maintenance scripts may generate similar activities. Filter known benign activities accordingly.",
        "clearing_steps": [
            "Disable and remove unauthorized automation scripts.",
            "Restrict API access to sensitive data resources.",
            "Audit user accounts with access to data collection mechanisms."
        ],
        "mitre_mapping": [
            {"tactic": "Collection", "technique": "T1083", "example": "File and Directory Discovery"},
            {"tactic": "Lateral Movement", "technique": "T1570", "example": "Lateral Tool Transfer"}
        ],
        "watchlist": [
            "Monitor processes executing frequent file access operations.",
            "Check for sudden increases in cloud storage API calls."
        ],
        "enhancements": [
            "Implement behavioral analysis for sequential file operations.",
            "Monitor cloud API usage patterns for anomalies."
        ],
        "summary": "Automated Collection enables adversaries to systematically collect large amounts of data using scripts, cloud APIs, and remote access tools.",
        "remediation": "Restrict execution of unauthorized automation tools, enforce least privilege access, and monitor for unusual file and API activities.",
        "improvements": "Implement anomaly detection for sequential file access and large-scale data collection behaviors."
    }
