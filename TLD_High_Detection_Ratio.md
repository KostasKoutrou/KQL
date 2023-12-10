# KQL Query: TLD with High Detections Ratio

## Description
This query detects Top Level Domains (TLD) of email senders with a high ratio of detections.

For each TLD it counts the total detected emails (any detection) and the total number of emails, and it calculates the following ratio:

$\displaystyle \frac{Count\ of\ Emails\ with\ any\ Detection\ of\ TLD}{Count\ of\ total\Emails\ of\ TLD}$

You can use TLDs with high ratios to:
- Create an Exchange Transport Rule that appends a warning of suspicious sender (ref. for best looking warning append I have found https://lazyadmin.nl/it/add-external-email-warning-to-office-365-and-outlook/), or
- Potentially block TLDs.

## Query
```kql
//Calculate total count for each TLD
let TotalCounts = EmailEvents
| where Timestamp > ago(30d) //you can have a longer Timestamp if you stored the logs on a Log Analytics Workspace.
| extend TLD = tostring(split(SenderFromDomain, ".")[-1])
| summarize TotalCount = count() by TLD;
//Calculate sum of counts for all threat types per TLD
let ThreatCounts = EmailEvents
| where Timestamp > ago(30d)
| where isnotempty(ThreatTypes)
| extend TLD = tostring(split(SenderFromDomain, ".")[-1])
| summarize ThreatTypeCount = count() by TLD;
//Join results and calculate ratio
TotalCounts
| join kind=inner (ThreatCounts) on TLD
| project TLD, Ratio = todouble(ThreatTypeCount) / todouble(TotalCount), ThreatTypeCount, TotalCount
| sort by Ratio desc
```
