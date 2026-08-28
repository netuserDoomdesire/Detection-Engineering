# File Event - File Downloaded from Direct IP Address

## Description
This rule aims to identify files downloaded from an external resource where the download URL or referrer URL uses a direct IPv4 address instead of a domain name. Direct IP-based file delivery may be used by threat actors to retrieve payloads, tools, scripts, or additional malware from attacker-controlled infrastructure while avoiding domain-based reputation controls. The detection focuses on publicly routable IP addresses, excludes configured trusted IP addresses and selected commonly benign file extensions, and uses file origin metadata recorded by Microsoft Defender for Endpoint. While a direct IP address does not inherently indicate malicious activity, downloads of executable, script, archive, or other potentially actionable file types from unfamiliar external IP addresses should be investigated, particularly when followed by file execution or additional suspicious endpoint activity.

## Blind Spots

- Whitelisted file extensions can lead to missed file downloads
- Whitelisting multihosting IPs can lead to missed file downloads

## Common False Positives

- Legitimate software, installers, updates, or other files downloaded from services that use direct IP-address-based URLs
- Administrative or IT operations involving files retrieved directly from known external servers by IP address

## Investigation Guidelines

- Review the downloaded file name, extension, hash, and file prevalence within the environment to determine whether the file is expected
- Investigate the external IP address used in the origin or referrer URL, including its reputation, hosting provider, geolocation, and any association with known malicious infrastructure
- Review the process responsible for the file activity, including its executable, command line, parent process, user context, and whether the process would normally be expected to download files
- Investigate other network connections from the affected device to the same external IP address and determine whether additional files or communications were observed
- Determine whether the downloaded file was subsequently executed, loaded, extracted, or used by another process and investigate the resulting process activity
- Investigate whether the same external IP address, file hash, URL, or related indicators have been observed on other devices or associated with other alerts within the environment
- Review the activity of the involved user and device around the time of the download to determine whether there is any other indication of suspicious/unexpected activity

## References

- https://cloud.google.com/blog/topics/threat-intelligence/game-over-detecting-and-stopping-an-apt41-operation
- https://blog.talosintelligence.com/chaos-msarat-living-off-the-browser-to-build-covert-c2-channel/
- https://www.huntress.com/blog/curling-for-data-a-dive-into-a-threat-actors-malicious-ttps
- https://www.huntress.com/blog/wing-ftp-server-remote-code-execution-cve-2025-47812-exploited-in-wild

## Query

```KQL
let InternalIPv4CIDR = dynamic(["192.168.0.0/16", "172.16.0.0/12", "10.1.0.0/8", "127.0.0.0/8"]);
// Add any known and trusted IPs
let IPExclusions = dynamic([""]);
// Remove any extension you may want, and add any extension you do not want in the results. Adding an entry should be avoided unless necessary
let BenignFileExtensions = dynamic(["pdf", "csv", "html"]);
DeviceFileEvents
// Only include events that have Origin URL or Origin Referrer URL available
| where (isnotempty(FileOriginUrl) or isnotempty(FileOriginReferrerUrl))
// Parse File Extension
| extend ParsedPath = parse_path(FolderPath)
| extend FileExtension = ParsedPath.Extension
// Exclude benign file extensions
| where not (FileExtension in (BenignFileExtensions))
// Parse Origin URL and Origin Referrer URL
| extend ParsedURL = parse_url(FileOriginUrl)
| extend ParsedReferrer = parse_url(FileOriginReferrerUrl)
// Include events that have a direct IPv4 address as the host in either Origin URL or Origin Referrer URL
| where ParsedURL.Host matches regex @"(\d+\.\d+\.\d+\.\d+)" or ParsedReferrer.Host matches regex @"(\d+\.\d+\.\d+\.\d+)"
// Keep only remote IPs
| extend Host = format_ipv4(tostring(ParsedURL.Host))
| extend ReferrerHost = format_ipv4(tostring(ParsedReferrer.Host))
| where not(ipv4_is_in_any_range(Host, InternalIPv4CIDR)
        or ipv4_is_in_any_range(ReferrerHost, InternalIPv4CIDR))
// Exclude known and trusted IPs
| where not(Host in (IPExclusions) or ReferrerHost in (IPExclusions))
| project-away ParsedPath, ParsedURL, ParsedReferrer
```

## MITRE ATT&CK 

| Tactic              | Technique    | Reference                                                                                   |
| ------------------- | ------------ | --------------------------------------------------------------------------------------------|
| Command and Control | T1105        | [Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)                         |


## Version History
| Version | Date       | Comment                                      |
| ------- |------------| ---------------------------------------------|
| 1.0     | 28-08-2026 | Initial release                              |