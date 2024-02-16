# KQL Query: camapaign.adobe.com open redirect URLs in emails

## Description
campaign.adobe.com open redirect is used to send phishing URLs. 

hxxps[:]//tap-rt-prod1-t[.]campaign[.]adobe[.]com/r/?id=h9ecb88b,c1e96b3,69fe0fb&p1=ryda[.]letsgrowth[.]org//90/<base64 of recipient's email address>

When clicking the above link, the user is redirected to the site of the "p1" parameter.

The following KQL query detects emails with such URLs, which can then be reported and deleted.

You can convert this query to a custom detection rule by removing the two Timestamp lines.

## Query
```kql
EmailUrlInfo
| where Timestamp > ago(30d)
| where Url contains "campaign.adobe.com"
| extend Redirect = split(Url, "&p1=")[1]
| where Redirect contains "." //I found this condition to be enough to keep the URLs only
| join
(
EmailEvents
| where Timestamp > ago(30d)
) on NetworkMessageId
| where LatestDeliveryLocation contains "inbox" or LatestDeliveryLocation contains "junk" //You can comment this line out to see successful blocks
| project-away Timestamp1, NetworkMessageId1
```
