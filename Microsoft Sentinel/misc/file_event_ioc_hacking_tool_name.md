# File Event - IOC - Hacking Tool Name

## Description
This rule aims to identify files whose names match known offensive security, penetration testing, or other hacking tools. The presence of such tools may indicate that an adversary has the intent to support post-compromise activity, including credential theft, discovery, privilege escalation, lateral movement, defense impairment, or other malicious objectives. The detection is based on the _Im_FileEvent parser of Microsoft Sentinel which captures file activity across a variety of log sources, including Defender for Endpoint, Windows security logs, Sysmon and Microsoft Office. The results should be treated as evidence of a potentially suspicious tool being present on the environment, rather than confirmation that the identified tool was executed. Matches should be investigated in the context of the affected endpoint, user, file location, associated processes, and surrounding activity to determine whether the file is authorized or related to malicious activity. As also stated in the utilized IOC list, a proper detection engineering strategy should always be in place; this rule should only be considered a quick win.

## Severity

High

## Blind Spots

- File names missing from the source URL containing the IOCs will not trigger an alert
- A potential change of the URL or the URL content structure containing the IOCs will result in the query producing no results

## Common False Positives

- Authorized penetration testing, red team, vulnerability assessment, or security validation activities involving offensive security tools
- Security administrators or researchers legitimately storing or using multi-use tools within the environment
- Legitimate files that share the same file name as a known hacking tool but are unrelated to the corresponding offensive utility

## Investigation Guidelines

- Review the matched file name, file path, file hash, file system action, affected device, and associated user to determine the context in which the file was observed
- Identify the source log type where the file was identified (Defender for Endpoint, Windows security logs, Sysmon, Microsoft Office etc.)
- Determine which hacking tool or offensive capability is associated with the matched file name and review its expected functionality and potential use within an intrusion
- Investigate process creation telemetry for evidence that the identified file was executed and review its command line, parent process, execution account, and resulting child processes if available
- Review activity preceding the file event for potential download, file transfer, archive extraction, scripting, remote administration, or other activity that may explain how the tool reached the environment
- Search for the same file name and (if available) file hashes across other sources to determine whether the activity is isolated or part of a broader activity
- Determine whether the identified tool is expected within the environment, including authorized administrative, penetration testing, red team, or security research activity


## References

- https://github.com/netuserDoomdesire/IOCSniper
- https://www.crowdstrike.com/en-us/cybersecurity-101/threat-intelligence/indicators-of-compromise-ioc/

## Query

```KQL
// Changing this value is not recommended, since it increases the resources needed for the parser
let Timeframe = 1h;
// Exclude any file names that cause noise, are allowed, or have conflicting names with legitimate tools
let Exclusions = dynamic([""]);
// Pull the list of hacking tool names. Ignore first record is set to true because the public list has headers
let HackingToolNames = externaldata(ToolName:string, TacticID:string, TacticName:string, TechniqueID:string, Reference:string)
[
  h@"https://raw.githubusercontent.com/netuserDoomdesire/IOCSniper/refs/heads/main/ioc_hacking_tool_names.csv"
]
with(format="csv", ignoreFirstRecord=true);
// Search the file names of the list in _Im_FileEvent table based on FileName
_Im_FileEvent(ago(Timeframe))
| where not (FileName in (Exclusions))
| extend FileName = tolower(FileName)
| lookup kind = inner HackingToolNames on $left.FileName == $right.ToolName
```

## MITRE ATT&CK 

| Tactic              | Technique    | Reference                                                                 |
| ------------------- | ------------ | --------------------------------------------------------------------------------------------|
| Resource Development | T1102.002    | [Obtain Capabilities: Tool](https://attack.mitre.org/techniques/T1588/002/)  |


## Version History
| Version | Date       | Comment                                      |
| ------- |------------| ---------------------------------------------|
| 1.0     | 20-08-2026 | Initial release                              |