# KQL Query: Potential AitM

## Description
This query detects potential AitM attempts. The query is meant to be used as a Microsoft Sentinel Scheduled Analytics rule. https://learn.microsoft.com/en-us/azure/sentinel/detect-threats-custom

The query works like so:
1. Get all distinct UserId/IP Address combinations of all sign ins to OfficeHome/Office365 Apps.
2. For each combination, find the combinations that occurred fewer than 4 times.
3. Get the sign ins for these combinations to create the alert.

The thershold may require adapting based on users' usual activity, to reduce false positives.

## Query
```kql
//Get IP and UserId who have signed in to OfficeHome/Office365 at least once
let baseQuery = SigninLogs
| where TimeGenerated > ago(62m) //Slightly higher number than the query frequency to have an overlap.
| where ResultType in (0,50140,50074) //0=Success, 50140='Keep me signed in' prompt, 50074='Strong Authentication is required.'
| where AppId in ("4765445b-32c6-49b0-83e6-1d93765276ca","72782ba9-4490-4f03-8d82-562370ea3566") //OfficeHome and Office365 App IDs
| where IPAddress !in ("<IP1>","<IP2>") //Exclude most frequent IP addresses in your organization, e.g., Office IP Addresses.
| where isnull(DeviceDetail.deviceId) or DeviceDetail.deviceId == '' //Exclude any AAD Registered, Joined, Hybrid Joined device.
| distinct IPAddress, UserId; //Keep only IP Address / UserId combinations. It is better to keep UserId instead of UPN, because some sign in logs have the UserId in the filed of UPN, too, i.e., UPN is not reliable.
//For the IP/UserId combinations, find all sign ins and keep only occurences where there were <4 sign ins for each combination.
let lookupQuery = SigninLogs
| where TimeGenerated > ago(7d)
| where ResultType in (0,50140,50074)
| where IPAddress !in ("<IP1>","<IP2>")
| join kind=inner (baseQuery) on IPAddress, UserId
| summarize arg_max(TimeGenerated,*) by CorrelationId
| summarize IPCount = count() by IPAddress, UserId
| where IPCount < 4; //You can play around with this threshold. I have found 4 to provide a good false positive ratio
//For the IP/UserId combinations, get the original logs
SigninLogs
| where TimeGenerated > ago(62m)
| where ResultType in (0,50140,50074)
| where AppId in ("4765445b-32c6-49b0-83e6-1d93765276ca","72782ba9-4490-4f03-8d82-562370ea3566")
| where IPAddress !in ("<IP1>","<IP2>")
| where isnull(DeviceDetail.deviceId) or DeviceDetail.deviceId == ''
| join kind=inner lookupQuery on IPAddress, UserId
| where IPAddress !contains ":" and DeviceDetail !contains '"operatingSystem":"Ios"' //Exclude IPv6 and iOS because iPhones sign up automatically in that way.
| summarize arg_max(TimeGenerated,*) by CorrelationId
```
