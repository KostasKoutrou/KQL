# KQL Query: Email attachments with threats found in devices

## Description
This query detects device file events of files with the same SHA256 as email attachments with any threat type detection.
Essentially this means that the file was:
- Either downloaded to the device,
- Or previewed via outlook. In this case, the file path will include "Content.Outlook"

This is helpful in cases where the attachment is detected as phish or malware at a later time than the email delivery.


## Query
```kql
EmailAttachmentInfo
| where Timestamp > ago(30d)
| where isnotempty(ThreatTypes)
| distinct SHA256
| join kind=inner
(
DeviceFileEvents
| where Timestamp > ago(30d)
// You can uncomment the next line in case there are too many previous
// within Outlook and you prefer to investigate the actual file downloads.
// | where FolderPath !contains "Content.Outlook"
) on SHA256
| sort by DeviceId asc, Timestamp desc
```
