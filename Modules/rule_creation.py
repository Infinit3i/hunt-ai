def get_rule_creation_content():
    """
    Returns structured content for the Rule Creation page.
    """
    return [
        {
            "title": "Detection Engineer Overview Websites",
            "content": """
Explore the world of detection engineering and learn from top resources to build your expertise.
            """,
            "links": [
                {"name": "Uptycs: What is Detection Engineering?", 
                 "url": "https://www.uptycs.com/blog/threat-research-report-team/what-is-detection-engineering"},
                {"name": "Cyb3rOps: About Detection Engineering", 
                 "url": "https://cyb3rops.medium.com/about-detection-engineering-44d39e0755f0"},
                {"name": "Palantir: Alerting and Detection Strategy Framework", 
                 "url": "https://blog.palantir.com/alerting-and-detection-strategy-framework-52dc33722df2"}
            ]
        },
        {
            "title": "Rule Creation Websites",
            "content": """
Dive into resources for creating and implementing detection rules for various platforms and frameworks.
            """,
            "links": [
                {"name": "MITRE ATT&CK Framework", 
                 "url": "https://attack.mitre.org/"},
                {"name": "SigmaHQ: Open Source SIEM Rules", 
                 "url": "https://github.com/SigmaHQ/sigma"},
                {"name": "Uncoder.IO: Compile Sigma Rules to Splunk", 
                 "url": "https://uncoder.io/"},
                {"name": "LOLBAS Project", 
                 "url": "https://lolbas-project.github.io/#"},
                {"name": "Litmus Test: Detection Framework", 
                 "url": "https://github.com/Kirtar22/Litmus_Test?tab=readme-ov-file"},
                {"name": "Splunk Research Detections", 
                 "url": "https://research.splunk.com/detections/"}
            ]
        }
    ]
