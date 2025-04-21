def get_content():
    return {
        "id": "T1648",
        "url_id": "T1648",
        "title": "Serverless Execution",
        "description": "Adversaries may abuse serverless computing, application integration, and automation services in cloud environments to execute arbitrary code. This includes functions like AWS Lambda, Azure Functions, Google Cloud Functions, and productivity suite automations like Microsoft Power Automate or Google Apps Script. These can be triggered by events, operate without persistent infrastructure, and may escalate privileges or exfiltrate data via integration with other cloud services.",
        "tags": ["lambda", "Power Automate", "Apps Script", "GCP", "AWS", "Azure", "event-triggered", "IAM abuse", "cloud-native malware"],
        "tactic": "Execution",
        "protocol": "",
        "os": "IaaS, Office Suite, SaaS",
        "tips": [
            "Monitor event-driven executions tied to suspicious IAM roles.",
            "Correlate new function deployments with unusual data access or exfiltration.",
            "Investigate workflows created without legitimate admin involvement."
        ],
        "data_sources": "Application Log: Application Log Content, Cloud Service: Cloud Service Modification",
        "log_sources": [
            {"type": "Cloud Service", "source": "AWS CloudTrail, Azure Activity Logs, GCP Cloud Audit Logs", "destination": ""},
            {"type": "Application Log", "source": "Power Automate logs, Google Workspace audit logs", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Function Code", "location": "Cloud console / repository", "identify": "Serverless scripts with IAM modification or exfil logic"},
            {"type": "Trigger Configuration", "location": "Event sources", "identify": "Triggers bound to IAM events or new user creation"},
            {"type": "Automation Workflow", "location": "Office 365 / Google Workspace", "identify": "Flows/scripts sending data to external endpoints"}
        ],
        "destination_artifacts": [
            {"type": "Execution Artifacts", "location": "Logs", "identify": "Cloud function invocations tied to suspicious users/events"},
            {"type": "Permissions Escalation", "location": "IAM Policy Changes", "identify": "PassRole or actAs permissions granted to functions"},
            {"type": "Exfiltration Channels", "location": "External domains", "identify": "Anonymous sharing links or HTTP requests from scripts"}
        ],
        "detection_methods": [
            "Detect serverless function creations using sensitive permissions like `iam:PassRole`, `iam.serviceAccounts.actAs`.",
            "Monitor for automation flows/scripts that modify sharing settings, forward email, or interact with files/documents.",
            "Track anomalous invocations of event-based functions or scripts associated with privilege escalation or C2."
        ],
        "apt": [
            "Cloud-focused adversaries using living-off-the-land in SaaS/IaaS like UNC2452",
            "FIN12 leveraging AWS automation for persistence"
        ],
        "spl_query": "index=cloud sourcetype=*cloudtrail* OR sourcetype=*audit* \n| search eventName=CreateFunction OR eventName=UpdateFunctionConfiguration OR eventName=AddPermission\n| stats count by userIdentity.arn, requestParameters.runtime, sourceIPAddress",
        "spl_rule": "https://research.splunk.com/detections/tactics/execution/",
        "elastic_rule": "https://grep.app/search?f.repo=elastic%2Fdetection-rules&q=T1648",
        "sigma_rule": "https://grep.app/search?f.repo=SigmaHQ%2Fsigma&q=T1648",
        "hunt_steps": [
            "List all functions created in last 30 days with elevated IAM permissions",
            "Audit automation tools for scripts triggered by user provisioning, sharing, or email forwarding",
            "Check for usage of free-tier cloud services that operate outside billing alerts",
            "Review cloud IAM audit logs for event-driven privilege escalation attempts"
        ],
        "expected_outcomes": [
            "Detection of malicious serverless executions",
            "Blocked automation flows/scripts used for data exfiltration",
            "Privilege escalation pathways removed from serverless permissions"
        ],
        "false_positive": "Security automation and CI/CD workflows may also use serverless functions with sensitive permissions. Confirm role ownership and expected functionality.",
        "clearing_steps": [
            "Revoke unauthorized permissions from serverless functions or service accounts",
            "Delete unauthorized scripts and automation workflows",
            "Audit IAM policies for functions and restrict `PassRole`, `actAs`, or sharing link creation"
        ],
        "mitre_mapping": [
            {"tactic": "Execution", "technique": "T1648 (Serverless Execution)", "example": "Use of AWS Lambda function tied to CloudWatch Events to auto-grant IAM credentials"}
        ],
        "watchlist": [
            "Functions or workflows created by low-privileged users",
            "Event triggers bound to IAM role changes or new user creation",
            "Data exfiltration via anonymous sharing or outbound webhooks"
        ],
        "enhancements": [
            "Integrate CSPM tooling to alert on overprivileged serverless resources",
            "Enable least privilege reviews for function permissions",
            "Log all automation actions in Microsoft 365 / Google Workspace"
        ],
        "summary": "Serverless Execution is the abuse of cloud-native compute and automation capabilities to execute malicious code, exfiltrate data, or escalate privileges. Techniques span AWS Lambda, GCP Cloud Functions, Azure Logic Apps, and SaaS tools like Power Automate.",
        "remediation": "Revoke or delete malicious functions/workflows, audit service-linked roles, and restrict trigger creation to authorized admins.",
        "improvements": "Build detections for cloud automation platforms. Regularly rotate IAM credentials and review role assignment logs.",
        "mitre_version": "16.1"
    }
