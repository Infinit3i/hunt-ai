def get_content():
    return {
        "id": "T1542.003",
        "url_id": "T1542/003",
        "title": "Pre-OS Boot: Bootkit",
        "description": "Bootkits are malware implants that modify the Master Boot Record (MBR) or Volume Boot Record (VBR) of a system’s drive to execute adversary code during the boot process. Since bootkits operate below the OS, they provide persistent and stealthy access and can bypass many endpoint security controls. They divert execution during startup from the legitimate bootloader to adversary-controlled code, often allowing full control of the system before OS-level defenses activate.",
        "tags": ["bootkit", "MBR", "VBR", "persistence", "defense evasion", "T1542.003", "WhisperGate", "BOOTRASH", "APT41", "FinFisher"],
        "tactic": "Defense Evasion, Persistence",
        "protocol": "",
        "os": "Linux, Windows",
        "tips": [
            "Capture baseline MBR/VBR snapshots of critical assets and compare against current states.",
            "Use forensic tools to read raw disk sectors and verify boot sequence integrity.",
            "Implement Secure Boot with TPM attestation where feasible."
        ],
        "data_sources": "Drive: Drive Modification",
        "log_sources": [
            {"type": "Drive", "source": "MBR or VBR", "destination": ""},
            {"type": "Process", "source": "Firmware update utilities", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Bootloader Injection", "location": "Disk MBR/VBR sector", "identify": "Code mismatch or unexpected boot sequence"},
            {"type": "Bootkit Loader", "location": "Hidden disk partition", "identify": "Non-standard boot configuration"}
        ],
        "destination_artifacts": [
            {"type": "Malicious Boot Code", "location": "MBR (sector 0) or VBR (first sector of partition)", "identify": "Adversary code executed before OS"}
        ],
        "detection_methods": [
            "Compare snapshots of the MBR/VBR to known-good images for modification.",
            "Detect unauthorized write access to sector 0 (MBR) or VBR using low-level disk monitoring tools.",
            "Enable TPM and Secure Boot to alert or block modified boot chains."
        ],
        "apt": [
            "APT41 – used BOOTRASH bootkit in combination with malware loaders.",
            "FinFisher – leveraged UEFI/boot-level implants to maintain covert persistence.",
            "Sednit – deployed bootkits like Lojax targeting UEFI firmware and boot processes.",
            "WhisperGate – used bootkit-style modifications for disruptive campaigns in Ukraine."
        ],
        "spl_query": [
            'index=disk OR index=boot\n| search action="MBR write" OR action="boot sector modified"',
            'index=forensics\n| search artifact="boot_record" change_detected=true',
            'index=sysmon\n| search CommandLine="*dd if=/dev/sda*" OR Image="*bootsect.exe*"'
        ],
        "hunt_steps": [
            "Perform disk sector reads of MBR/VBR and compare hashes against trusted baselines.",
            "Inspect boot process execution flow for unexpected behavior or timing anomalies.",
            "Verify Secure Boot enforcement via UEFI/BIOS settings and system logs."
        ],
        "expected_outcomes": [
            "Detection of unauthorized MBR/VBR changes.",
            "Prevention of boot sequence manipulation using Secure Boot.",
            "Identification of persistent malware loading before OS initialization."
        ],
        "false_positive": "Legitimate disk imaging or repair utilities may write to MBR/VBR sectors—validate usage via process lineage and admin context.",
        "clearing_steps": [
            "Rebuild MBR/VBR from clean installation media or backup.",
            "Reinstall OS and verify bootloader integrity before reconnecting to the network.",
            "Re-enable Secure Boot and reflash BIOS/UEFI if needed to ensure chain-of-trust."
        ],
        "mitre_mapping": [
            {"tactic": "Persistence", "technique": "T1542.003", "example": "APT41’s BOOTRASH implanted into MBR to load malware early in the boot process."}
        ],
        "watchlist": [
            "Sector 0 and VBR access patterns from non-boot processes",
            "Installation of bootloader tools like GRUB without logging",
            "Inconsistent OS boot times or delayed Secure Boot failures"
        ],
        "enhancements": [
            "Automate periodic boot sector comparisons and hash validations.",
            "Implement EDR rules to flag tools accessing raw disk sectors.",
            "Utilize forensic bootkits like CHKDSK, GRR, or Velociraptor to verify boot integrity."
        ],
        "summary": "Bootkits are powerful persistence mechanisms that subvert the operating system by altering the initial boot sectors. Once deployed, they allow code execution before the OS loads, often bypassing EDRs and anti-malware tools. APT41 and WhisperGate have exploited this technique to gain deep access and deploy malware with resilience.",
        "remediation": "Overwrite and rebuild the boot record using clean install media. Re-enable Secure Boot with TPM-backed attestation to prevent reimplantation. Isolate infected systems and investigate lateral movement.",
        "improvements": "Include MBR/VBR scanning in regular vulnerability assessments. Equip IR teams with boot-level integrity verification tooling.",
        "mitre_version": "16.1"
    }
