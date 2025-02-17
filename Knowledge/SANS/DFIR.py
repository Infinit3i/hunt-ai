def get_dfir_content():
    return [
        {
            "title": "PICERL Framework",
            "content": """
- Phases: Preparation, Identification, Containment, Eradication, Recovery, Lessons Learned.
- Example: Containment using decoys or monitoring tools.
            """,
        },
        {
            "title": "Containment Challenges",
            "content": """
- Rapid containment avoids losing critical intelligence.
- No containment leads to prolonged adversary presence (whack-a-mole).
            """,
        },
        {
            "title": "Hunt vs. Reactive Teams",
            "content": """
- Reactive (Incident Response): Firefighting approach, putting out fires.
- Hunt Teams: Proactive, leveraging threat intelligence to predict and disrupt.
            """,
        },
        {
            "title": "Detection Engineering",
            "content": """
- Focus on enabling actionable and collaborative processes.
- Outsource or automate repetitive tasks while maintaining oversight of critical alerts.
            """,
        },
        {
            "title": "Advanced Forensic Tools",
            "content": """
- Volatility: Memory analysis.
- Splunk and Loggly: Advanced log analysis and monitoring.
- MFT Analysis: Tools like MFTECmd for NTFS evidence.
            """,
        }
    ]
