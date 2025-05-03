def get_content():
    return {
        "id": "G0095",
        "url_id": "Machete",
        "title": "Machete",
        "tags": ["state-sponsored", "espionage", "Latin America", "Venezuela", "Spanish-speaking"],
        "description": (
            "Machete is a suspected Spanish-speaking cyber espionage group active since at least 2010. "
            "The group primarily focuses on Latin American targets, especially Venezuela, but has also been observed "
            "operating in the US, Europe, Russia, and parts of Asia. Machete targets high-value organizations including "
            "government institutions, military organizations, intelligence services, and critical infrastructure providers."
        ),
        "associated_groups": ["APT-C-43", "El Machete"],
        "campaigns": [],
        "techniques": [
            "T1059.003", "T1059.005", "T1059.006", "T1189", "T1036.005", "T1566.001", "T1566.002",
            "T1053.005", "T1218.007", "T1204.001", "T1204.002"
        ],
        "contributors": ["Matias Nicolas Porolli, ESET"],
        "version": "2.0",
        "created": "13 September 2019",
        "last_modified": "16 April 2025",
        "navigator": "",
        "references": [
            {
                "source": "Cylance",
                "url": "https://threatvector.cylance.com/en_us/home/el-machetes-malware-attacks-cut-through-latam.html"
            },
            {
                "source": "Kaspersky",
                "url": "https://securelist.com/el-machete/65934/"
            },
            {
                "source": "ESET",
                "url": "https://www.welivesecurity.com/2019/07/09/machete-just-got-sharper-venezuelan-government-institutions-under-attack/"
            },
            {
                "source": "HpReact",
                "url": "https://apt.kpsec.xyz/posts/apt-c-43-venezuelan-military/"
            }
        ],
        "resources": [],
        "remediation": (
            "Implement email filtering for spearphishing attachments and links, enforce execution prevention on MSI installers, "
            "and restrict PowerShell, VBScript, and Python execution to trusted scripts only. Disable or alert on msiexec misuse."
        ),
        "improvements": (
            "Enhance endpoint visibility around user-initiated downloads, MSI execution, and scheduled task creation. "
            "Deploy memory-based detections for macro-laden Office files and monitor for Python script execution anomalies."
        ),
        "hunt_steps": [
            "Review task scheduler logs for Machete persistence indicators",
            "Inspect for suspicious MSI installations using msiexec",
            "Trace spearphishing email delivery containing ZIP/RAR payloads",
            "Hunt for Python or VB-based scripts launched from user temp directories"
        ],
        "expected_outcomes": [
            "Identification of spearphishing delivery mechanisms and payloads",
            "Detection of MSI-based malware deployments",
            "Discovery of macro execution behavior linked to Machete"
        ],
        "false_positive": "Scripts and MSI executions may be legitimate; confirm with context and source validation.",
        "clearing_steps": [
            "Remove persistence mechanisms such as scheduled tasks and registry run keys",
            "Delete dropped payloads and scripts from user-accessible folders",
            "Reset user credentials and monitor reentry vectors"
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": [
                "https://securelist.com/el-machete/65934/",
                "https://www.welivesecurity.com/2019/07/09/machete-just-got-sharper-venezuelan-government-institutions-under-attack/"
            ]
        }
    }
