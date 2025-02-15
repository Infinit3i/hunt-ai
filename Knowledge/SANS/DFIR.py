def get_dfir_content():
    return [
        {
            "title": "PICERL Framework",
            "content": """
- Phases: Preparation, Identification, Containment, Eradication, Recovery, Lessons Learned.
- Example: Containment using decoys or monitoring tools.
            """,
            "resources": [
                "https://www.sans.org/",
                "https://www.cisa.gov/"
            ]
        },
        {
            "title": "Containment Challenges",
            "content": """
- Rapid containment avoids losing critical intelligence.
- No containment leads to prolonged adversary presence (whack-a-mole).
            """,
            "resources": [
                "https://www.ncsc.gov.uk/",
                "https://attack.mitre.org/"
            ]
        },
        {
            "title": "Hunt vs. Reactive Teams",
            "content": """
- Reactive (Incident Response): Firefighting approach, putting out fires.
- Hunt Teams: Proactive, leveraging threat intelligence to predict and disrupt.
            """,
            "resources": [
                "https://www.fireeye.com/",
                "https://www.mandiant.com/"
            ]
        },
        {
            "title": "Detection Engineering",
            "content": """
- Focus on enabling actionable and collaborative processes.
- Outsource or automate repetitive tasks while maintaining oversight of critical alerts.
            """,
            "resources": [
                "https://redcanary.com/",
                "https://www.crowdstrike.com/"
            ]
        },
        {
            "title": "Advanced Forensic Tools",
            "content": """
- Volatility: Memory analysis.
- Splunk and Loggly: Advanced log analysis and monitoring.
- MFT Analysis: Tools like MFTECmd for NTFS evidence.
            """,
            "resources": [
                "https://volatilityfoundation.org/",
                "https://www.splunk.com/"
            ]
        }
    ]
