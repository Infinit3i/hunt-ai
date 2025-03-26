def get_content():
    return {
        "id": "T1125",
        "url_id": "T1125",
        "title": "Video Capture",
        "description": "An adversary can leverage a computer's peripheral devices (e.g., webcams) or video-related applications to record or capture images for intelligence gathering.",
        "tags": ["collection", "webcam", "video surveillance", "camera", "privacy invasion"],
        "tactic": "collection",
        "protocol": "",
        "os": "Linux, Windows, macOS",
        "tips": [
            "Alert on access to webcam APIs by non-video-conferencing applications",
            "Monitor image/video file creation from suspicious or background processes",
            "Investigate anomalies involving sudden access to devices like integrated cameras"
        ],
        "data_sources": "Command, Process",
        "log_sources": [
            {"type": "Command", "source": "endpoint", "destination": ""},
            {"type": "Process", "source": "Sysmon", "destination": ""},
            {"type": "Process", "source": "EDR", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Loaded DLLs", "location": "userland process memory", "identify": "avicap32.dll, mf.dll, camera-related libraries"},
            {"type": "Recent Files", "location": "C:\\Users\\<user>\\Videos or Temp", "identify": "Unexpected MP4, AVI, or JPG files"},
            {"type": "Process List", "location": "Live EDR telemetry", "identify": "Processes accessing or controlling webcam without user interaction"}
        ],
        "destination_artifacts": [
            {"type": "Prefetch Files", "location": "C:\\Windows\\Prefetch", "identify": "Execution of camera or video capture apps like ffmpeg.exe"},
            {"type": "Event Logs", "location": "Security logs or Camera privacy logs", "identify": "Trigger of webcam or camera sensor"},
            {"type": "Sysmon Logs", "location": "Event ID 1 & 11", "identify": "Image/video files written by uncommon processes"}
        ],
        "detection_methods": [
            "Flag access to camera APIs from processes like PowerShell, cmd.exe, or RATs",
            "Alert on creation of video files in non-standard folders",
            "Correlate image/video file writes with background processes and user absence"
        ],
        "apt": [
            "FIN7", "InvisiMole", "Transparent Tribe", "Agent Tesla", "TA505", "DarkComet", "NanoCore", "Oblique RAT", "Patchwork", "Machete"
        ],
        "spl_query": [
            'index=sysmon EventCode=1 \n| search CommandLine="*ffmpeg*" OR CommandLine="*record*" OR CommandLine="*webcam*" \n| stats count by CommandLine, Image',
            'index=sysmon EventCode=11 \n| search TargetFilename="*.mp4" OR TargetFilename="*.avi" OR TargetFilename="*.jpg" \n| stats count by TargetFilename, Image',
            'index=wineventlog \n| search Message="Camera access granted" OR Message="Device video stream started" \n| stats count by User, ComputerName'
        ],
        "hunt_steps": [
            "Hunt for video-related file creation (e.g., .avi, .mp4, .jpg) by unknown processes",
            "Review DLLs loaded by processes for presence of avicap32.dll or DirectShow modules",
            "Analyze endpoint telemetry for process behaviors that match RATs with camera access"
        ],
        "expected_outcomes": [
            "Identification of unauthorized webcam or video access by malware",
            "Detection of privacy-invasive collection techniques",
            "Recognition of use of system cameras by off-the-shelf or custom RATs"
        ],
        "false_positive": "Legitimate conferencing tools (e.g., Zoom, Teams, OBS) may access the camera. Validate parent-child process relationship and user activity at time of capture.",
        "clearing_steps": [
            "Delete unauthorized video/image files and remove malware responsible",
            "Block camera device access via Group Policy or Endpoint DLP rules",
            "Reset privacy permissions and audit access to camera APIs on affected systems"
        ],
        "mitre_mapping": [
            {"tactic": "collection", "technique": "T1113", "example": "Screen capture tools may be used alongside video capture"},
            {"tactic": "defense-evasion", "technique": "T1140", "example": "Malware hides camera recording code via obfuscation"},
            {"tactic": "exfiltration", "technique": "T1041", "example": "Captured media sent via HTTP/S or cloud sync for later retrieval"}
        ],
        "watchlist": [
            "Use of camera by processes not on approved allowlist",
            "Spike in media file creation during off-hours",
            "User complaints about webcam activity or LED light triggers"
        ],
        "enhancements": [
            "Enforce webcam access restrictions at the driver or firmware level",
            "Implement OS-level logging for all camera API calls and video recordings",
            "Use deception techniques like fake camera feeds or sensor monitoring"
        ],
        "summary": "Video Capture involves leveraging webcams or camera-enabled software to covertly record footage or images for intelligence gathering. Often used by spyware and RATs.",
        "remediation": "Disable camera access for unapproved applications, audit endpoint privacy permissions, and monitor for unauthorized video or image generation.",
        "improvements": "Deploy monitoring of USB camera connections and active session indicators to track camera usage at scale. Incorporate threat models targeting webcam abuse.",
        "mitre_version": "16.1"
    }
