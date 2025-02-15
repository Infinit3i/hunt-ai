def get_content():
    """
    Returns structured content for NTFS, journaling, and anti-forensics artifacts.
    """
    return [
        {
            "title": "NTFS Metadata and Attributes",
            "content": """
- MFT Attributes: Tracks MAC timestamps, $File_Name, $Data (resident or non-resident).
- $LogFile and $UsnJrnl: Log file changes and deletions.
            """
        },
        {
            "title": "Timeline Analysis",
            "content": """
- $SI and $FN timestamps: Can indicate timestomping or anti-forensic techniques.
- Exiftool: Verifies discrepancies in timestamps and metadata.
            """
        },
        {
            "title": "Advanced Analysis Tools",
            "content": """
- LogfileParser: Extracts NTFS transactional logs.
- Mftecmd: Parses MFT entries and supports Volume Shadow Copies.
- Icat: Extracts data streams like Zone.Identifier for ADS.
            """
        },
        {
            "title": "Deleted File Evidence",
            "content": """
- MFT metadata persists even after deletion.
- $INDEX_ROOT and $INDEX_ALLOCATION track directory changes.
            """
        }
    ]
