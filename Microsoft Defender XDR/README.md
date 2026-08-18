## Microsoft Defender XDR Detection Rules

A collection of detection rules designed for Microsoft Defender XDR using Advanced Hunting and Custom Detection capabilities.

Detections in this folder are organized by Microsoft Defender product, such as Defender for Endpoint and Defender for Office 365. Within each product folder, detections are further categorized based on the type of activity they are designed to detect, such as network communication, process creation, image loading, and similar activity. While some detections may use multiple tables from the same Defender product, their categorization is based on the primary or final table used by the query.

Detections that correlate telemetry across multiple Defender products are placed in a separate folder named "xdr".

### References

| Description | Link |
|-------------| -----|
| Microsoft Defender XDR Overview | https://learn.microsoft.com/en-us/defender-xdr/microsoft-365-defender |
| Custom Detection Rules Overview |https://learn.microsoft.com/en-us/defender-xdr/custom-detections-overview |
| How to Create Custom Detection Rules | https://learn.microsoft.com/en-us/defender-xdr/custom-detection-rules |
| How to Manage Custom Detection Rules  |https://learn.microsoft.com/en-us/defender-xdr/custom-detection-manage |