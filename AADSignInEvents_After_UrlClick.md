# KQL Query: Sign in Logs after URL Click Event

## Description
These queries search for sign in logs after a URL click event. This can be used to identify any suspicious sign ins right after the URL click, indicating a potential phishing site.

Below are two variations for this query.


## Query starting from Emails

This version is where you start by knowing the suspicious emails, and want to check if there were any URL click events originating from URL clicks from these emails, and sign ins after the URL click events.

Remember to change the *\<email address\>* field with the sender you want to investigate.
```kql
let clickTimeWindow = 5; // define the time window in minutes for sign in after the click
// Search for EmailEvents. You can add any filter you prefer or have as info.
EmailEvents
| where Timestamp > ago(30d)
| where SenderFromAddress contains "<email address>"
// Find UrlClickEvents for the identified EmailEvents.
| join kind=inner (
    UrlClickEvents
    | where Timestamp > ago(30d)
    | extend UrlClickTimestamp=Timestamp, UrlClickIP = IPAddress
) on NetworkMessageId
// Then join that with sign in logs that occurred within the specified time window after the click.
| join kind=inner (
    AADSignInEventsBeta
    | where Timestamp > ago(30d)
    | extend SignInTimestamp=Timestamp, SigninIP = IPAddress
) on AccountUpn
| extend endTime = datetime_add('minute', clickTimeWindow, UrlClickTimestamp)
| where SignInTimestamp > UrlClickTimestamp and SignInTimestamp <= endTime
//Timestamp is the Timestamp that the email was sent at. If you rename it for better readability, the "hyperlink" NetworkMessageId get disabled, so the name was left as is.
| project Timestamp, NetworkMessageId, SenderFromAddress, SenderDisplayName, EmailSenderIP = SenderIPv4, RecipientEmailAddress,
Subject, LatestDeliveryLocation, UrlClickTimestamp, Url, ActionType, UrlClickIP, SignInTimestamp, Application, LogonType, ErrorCode, ResourceDisplayName,
DeviceName, AadDeviceId, OSPlatform, DeviceTrustType, IsManaged, IsCompliant, UserAgent, Browser, ConditionalAccessPolicies, SigninIP, Country
| sort by SignInTimestamp asc
```

## Query starting from the URL click event
The second version is where you know the URL and want to search for sign ins after the URL Click Event.

Remember to change the *\<URL\>* field with the URL that you want to investigate.

```kql
let clickTimeWindow = 5; // define the time window in minutes for sign in after the click
// Start by getting the timestamp and user info for each URL click event
UrlClickEvents
| where Timestamp > ago(30d)
| where Url contains "<URL>"
| extend UrlClickTimestamp=Timestamp, UrlClickIP = IPAddress
// Then join that with sign in logs that occurred within the specified time window after the click
| join kind=inner (
    AADSignInEventsBeta
    | where Timestamp > ago(30d)
    | extend SignInTimestamp=Timestamp, SigninIP = IPAddress
) on AccountUpn
| extend endTime = datetime_add('minute', clickTimeWindow, UrlClickTimestamp)
| where SignInTimestamp > UrlClickTimestamp and SignInTimestamp <= endTime
| project Timestamp, NetworkMessageId, UrlClickTimestamp, Url, ActionType, UrlClickIP, SignInTimestamp, Application, LogonType, ErrorCode, ResourceDisplayName,
DeviceName, AadDeviceId, OSPlatform, DeviceTrustType, IsManaged, IsCompliant, UserAgent, Browser, ConditionalAccessPolicies, SigninIP, Country
| sort by SignInTimestamp asc
```