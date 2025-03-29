def get_content():
    return {
        "id": "T1059.011",  
        "url_id": "T1059/011",  
        "title": "Command and Scripting Interpreter: Lua",  
        "description": "Adversaries may abuse Lua commands and scripts for execution. Lua is a cross-platform scripting and programming language primarily designed for embedded use in applications. Lua can be executed on the command-line (through the stand-alone lua interpreter), via scripts (.lua), or from Lua-embedded programs (through the struct lua_State). Lua scripts may be executed by adversaries for malicious purposes. Adversaries may incorporate, abuse, or replace existing Lua interpreters to allow for malicious Lua command execution at runtime.",  
        "tags": [
            "t1059_011",
            "lua execution",
            "lua scripting",
            "lua interpreter abuse",
            "embedded lua",
            "lua runtime exploitation",
            "malicious lua scripts"
        ],  
        "tactic": "Execution",  
        "protocol": "",  
        "os": "Linux, Network, Windows, macOS",  
        "tips": [
            "Monitor execution of Lua interpreters in unusual locations",
            "Analyze Lua script execution for abnormal patterns",
            "Detect unauthorized modifications to Lua-embedded programs"
        ],  
        "data_sources": "Command: Command Execution, Script: Script Execution",  
        "log_sources": [
            {"type": "Script", "source": "Lua Execution Logs", "destination": "SIEM"},
            {"type": "Command", "source": "System Command Logs", "destination": "SOC"}
        ],  
        "source_artifacts": [
            {"type": "Lua Script", "location": "User Download Folders", "identify": "Malicious Lua Script Execution"}
        ],  
        "destination_artifacts": [
            {"type": "Lua Interpreter", "location": "Application Directory", "identify": "Modified or Injected Lua Interpreter"}
        ],  
        "detection_methods": [
            "Monitor for execution of Lua scripts from untrusted locations",
            "Analyze processes invoking Lua runtime",
            "Detect attempts to modify or replace embedded Lua interpreters"
        ],  
        "apt": ["PoetRAT"],  
        "spl_query": [
            "index=script_logs source=*lua* action=execute\n| stats count by user, ip, script_path",
            "index=system_logs source=*lua.exe* OR source=*lua_interpreter*\n| search command=*lua*"
        ],  
        "hunt_steps": [
            "Identify unauthorized Lua script execution",
            "Monitor changes to embedded Lua runtime environments",
            "Detect suspicious use of Lua for persistence mechanisms"
        ],  
        "expected_outcomes": [
            "Malicious Lua script execution detected",
            "Unauthorized Lua interpreter modifications identified",
            "Lua-based malware persistence prevented"
        ],  
        "false_positive": "Legitimate software and embedded applications may use Lua scripting, requiring careful validation against known application behavior.",  
        "clearing_steps": [
            "Restrict execution of Lua scripts from untrusted locations",
            "Implement application whitelisting for Lua interpreters",
            "Monitor and validate Lua script execution logs"
        ],  
        "mitre_mapping": [
            {"tactic": "Execution", "technique": "T1059.011", "example": "An adversary uses Lua scripting to execute malicious commands."}
        ],  
        "watchlist": [
            "Unexpected Lua script execution",
            "Modification of embedded Lua interpreters",
            "Abnormal process activity involving Lua runtimes"
        ],  
        "enhancements": [
            "Enable strict script execution policies",
            "Implement behavioral analysis for Lua script execution",
            "Monitor Lua interpreter activity in embedded applications"
        ],  
        "summary": "Lua can be leveraged by adversaries to execute malicious code, modify embedded interpreters, and maintain persistence.",  
        "remediation": "Restrict unauthorized Lua execution, monitor script activity, and enforce strong endpoint security policies.",  
        "improvements": "Enhance script execution monitoring, integrate Lua-specific behavioral analytics, and implement runtime integrity validation."
    }
