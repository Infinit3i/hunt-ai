def get_content():
    return {
        "id": "T1674",
        "url_id": "T1674",
        "title": "Input Injection",
        "description": "Adversaries may simulate keystrokes on a victim’s computer by various means to perform any type of action on behalf of the user, such as launching the command interpreter, executing inline scripts, or interacting with GUI applications. These actions can be preprogrammed into adversary tooling or executed via physical Human Interface Devices (HIDs).",
        "tags": ["execution", "keystroke", "HID", "PowerShell", "AutoHotKey", "bash", "macOS", "Linux", "Windows"],
        "tactic": "execution",
        "protocol": "",
        "os": "Linux, Windows, macOS",
        "tips": [
            "Restrict USB port access or implement allowlists for HID-class devices.",
            "Monitor for rapid keystroke patterns that indicate automation.",
            "Log and investigate input-related process launches from explorer.exe or winlogon.exe."
        ],
        "data_sources": "Drive, Process, Script",
        "log_sources": [
            {"type": "Drive", "source": "USB HID", "destination": "Event Logs"},
            {"type": "Process", "source": "Input Simulation Tools", "destination": "Execution Traces"},
            {"type": "Script", "source": "Clipboard Injection", "destination": "PowerShell Logs"}
        ],
        "source_artifacts": [
            {"type": "USB Enumeration", "location": "System Logs", "identify": "Keyboard-like device with anomalous VID/PID"},
            {"type": "Clipboard History", "location": "Memory or Forensics Dump", "identify": "Unusual script commands injected via clipboard"}
        ],
        "destination_artifacts": [
            {"type": "Executed Commands", "location": "PowerShell Logs", "identify": "Scripts with base64 or obfuscated payloads launched via simulation"}
        ],
        "detection_methods": [
            "Monitor USB devices and trigger alerts on suspicious HID insertions.",
            "Analyze keyboard input timing for automated/scripted behavior.",
            "Correlate execution logs with HID insertion events."
        ],
        "apt": ["FIN7"],
        "spl_query": [
            "index=wineventlog sourcetype=\"WinEventLog:System\" EventCode=400 OR EventCode=20001\n| eval usb_device=coalesce(UsbDevice, DeviceName)\n| search usb_device=\"keyboard\" OR usb_device=\"HID\"\n| transaction usb_device maxspan=30s\n| join usb_device [ search index=main sourcetype=\"WinEventLog:Security\" (EventCode=4688 OR EventCode=4104) \n| stats count by usb_device, _time, CommandLine, ParentProcessName, NewProcessName ]\n| where count > 0\n| table _time, usb_device, NewProcessName, CommandLine, ParentProcessName"
        ],
        "hunt_steps": [
            "Collect logs of recent USB device connections classified as HID.",
            "Match keystroke event timing to any recent script execution.",
            "Review PowerShell/osascript executions that follow device enumeration."
        ],
        "expected_outcomes": [
            "Detection of HID emulation leading to malicious script execution."
        ],
        "false_positive": "Automated test environments or accessibility tools may produce similar patterns.",
        "clearing_steps": [
            "Unplug suspicious USB devices.",
            "Disable HID ports via BIOS or GPO.",
            "Audit PowerShell history and revoke any anomalous scripts."
        ],
        "mitre_mapping": [
            {"tactic": "execution", "technique": "T1674", "example": "Input Injection via simulated keystrokes"}
        ],
        "watchlist": [
            "New keyboard device insertion followed by script execution.",
            "Base64 PowerShell payloads with short execution gaps."
        ],
        "enhancements": [
            "Enable keyboard hook logging tools to trace non-human input patterns.",
            "Deploy USB device control with granular VID/PID restrictions."
        ],
        "summary": "Input Injection enables adversaries to execute commands by simulating keystrokes, often via rogue HIDs or automation tools, bypassing traditional security mechanisms.",
        "remediation": "Restrict USB usage, monitor for HID behaviors, and validate command origins through parent-child process relationships.",
        "improvements": "Integrate USB HID analytics into SIEM dashboards for behavior correlation.",
        "mitre_version": "17.0"
    }
