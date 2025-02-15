def get_content():
    return {
        "id": "",           # T1556.001
        "url_id": "",       # 1556/001
        "title": "",
        "tactic": "",
        "data_sources": "",
        "protocol": "",
        "os": "",
        "objective": "",
        "scope": "",
        "threat_model": "",
        "hypothesis": [],
        "log_sources": [
            {"type": "", "source": "", "destination": ""}
        ],
        "detection_methods": [],
        "spl_query": [], # spl queries to detect the technique
        "hunt_steps": [], # steps to hunt for the technique
        "expected_outcomes": [],
        "false_positive":"",
        "clearing_steps": [], # steps on machine to remove the technique
        "mitre_mapping": [
            {"tactic": "", "technique": "", "example": ""} # next technique that would happen after
        ],
        "watchlist": [],
        "enhancements": [],
        "summary": "",
        "remediation": "",
        "improvements": ""
    }
