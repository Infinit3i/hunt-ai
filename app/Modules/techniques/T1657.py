def get_content():
    return {
        "id": "T1657",
        "url_id": "T1657",
        "title": "Financial Theft",
        "description": "Adversaries may steal monetary resources from targets through extortion, social engineering, or technical theft for financial gain. This includes tactics like ransomware extortion, business email compromise (BEC), cryptocurrency exploitation, and impersonation schemes. Financial theft may also be used to divert attention from destructive goals such as data destruction or operational disruption.",
        "tags": ["financial-theft", "ransomware", "BEC", "impersonation", "fraud", "pig butchering", "crypto", "impact"],
        "tactic": "Impact",
        "protocol": "",
        "os": "Linux, Office Suite, SaaS, Windows, macOS",
        "tips": [
            "Establish multi-factor authentication and approval chains for wire transfers",
            "Monitor unusual login patterns from executives or finance personnel",
            "Integrate threat intelligence sources for cryptocurrency-based indicators"
        ],
        "data_sources": "Application Log: Application Log Content",
        "log_sources": [
            {"type": "Application Log", "source": "Email Gateway, CRM, Payment System", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "BEC Attempt", "location": "Email headers and logs", "identify": "spoofed sender domains and wire fraud language"},
            {"type": "Ransom Note", "location": "Filesystem, email, or pop-up", "identify": "demand note for payment in crypto"},
            {"type": "Impersonation Site", "location": "Phishing domains", "identify": "domains mimicking business communications"}
        ],
        "destination_artifacts": [
            {"type": "Crypto Wallet Address", "location": "Payment instructions", "identify": "ransomware or scam transfers"},
            {"type": "Compromised Bank Account", "location": "Transfer logs or CRM notes", "identify": "account changes linked to fraud"}
        ],
        "detection_methods": [
            "Monitor large outbound financial transfers without expected workflows",
            "Detect email rule creation or forwarding anomalies typical in BEC",
            "Correlate ransomware indicators with public wallet threat intel",
            "Flag internal discussions about fraudulent or unexpected payments"
        ],
        "apt": [
            "APT43", "Scattered Spider", "GOLD IONIC", "Elephant Beetle", "SilverTerrier"
        ],
        "spl_query": "index=email OR index=payment_logs \n| search subject=*invoice* OR subject=*payment* OR notes=*ransom* \n| stats count by src_user, dest_account, amount",
        "spl_rule": "https://research.splunk.com/detections/tactics/impact/",
        "elastic_rule": "https://grep.app/search?f.repo=elastic%2Fdetection-rules&q=T1657",
        "sigma_rule": "https://grep.app/search?f.repo=SigmaHQ%2Fsigma&q=T1657",
        "hunt_steps": [
            "Review email accounts for suspicious inbox rules or forwarding setups",
            "Trace large transactions that bypass regular finance approval workflows",
            "Investigate any mentions of ransomware, encryption, or suspicious invoices",
            "Perform OSINT and blockchain lookups for new crypto wallet addresses"
        ],
        "expected_outcomes": [
            "Detection of email-based financial fraud (e.g., BEC)",
            "Disruption of ransom payment operations",
            "Recovery of fraudulently transferred funds or reporting to banks/law enforcement"
        ],
        "false_positive": "Legitimate invoices and internal finance operations may resemble fraud indicators. Always correlate with behavioral context and known workflows.",
        "clearing_steps": [
            "Reset affected account credentials and revoke any malicious inbox rules",
            "Report fraudulent wire transfers to banking institutions immediately",
            "Notify customers or partners if spoofing or impersonation is involved"
        ],
        "mitre_mapping": [
            {"tactic": "Impact", "technique": "T1657", "example": "Scattered Spider extorting healthcare providers for crypto ransom"}
        ],
        "watchlist": [
            "Monitor changes to payment destinations in invoices",
            "Track email activity tied to executive or finance impersonation",
            "Alert on keywords like 'invoice', 'urgent payment', 'BTC', 'USDT'"
        ],
        "enhancements": [
            "Integrate business process anomaly detection for transfers",
            "Deploy anti-BEC AI tooling in email gateways",
            "Leverage blockchain intel feeds to enrich wallet IOC context"
        ],
        "summary": "Financial theft involves direct monetary loss due to adversary actions such as BEC, ransomware, impersonation, or cryptocurrency scams. These actions aim to extract funds from victims while sometimes masking deeper objectives such as disruption or data destruction.",
        "remediation": "Reverse or freeze fraudulent transfers where possible. Reestablish secure communication lines with affected users and partners. Rotate credentials and enforce MFA where applicable.",
        "improvements": "Create automated workflows to verify wire transfers via out-of-band methods. Improve employee phishing resistance training focused on financial fraud.",
        "mitre_version": "16.1"
    }
