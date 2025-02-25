# 🌐 Visualizing Network Activities with World Maps A Creative Approach to Cybersecurity Monitoring
In this project, I focused on building world map visualizations to understand and analyze network activities. Using logs generated within our environment—a mix of legitimate user data and malicious actor activities—I created interactive maps that visually represent what’s happening across the network. These maps help identify patterns, potential threats, and anomalies, providing actionable insights for improving cybersecurity defenses.

Here, I’ll walk you through five scenarios that were visualized using KQL (Kusto Query Language) in Azure Sentinel. For each, I’ve included screenshots and detailed KQL scripts to demonstrate how these visualizations were built.
1. Entra ID (Azure) Authentication Success

Objective

Visualizing successful authentication attempts allows us to identify where legitimate users are accessing the network, enabling us to establish a baseline of normal activity.
```
SigninLogs
| where ResultType == 0
| summarize LoginCount = count() by Identity, Latitude = tostring(LocationDetails["geoCoordinates"]["latitude"]), Longitude = tostring(LocationDetails["geoCoordinates"]["longitude"]), City = tostring(LocationDetails["city"]), Country = tostring(LocationDetails["countryOrRegion"])
| project Identity, Latitude, Longitude, City, Country, LoginCount, friendly_label = strcat(Identity, " - ", City, ", ", Country)
```
![1](https://github.com/user-attachments/assets/9a9dcf3a-acdc-4658-8a61-b8cc2102ff5e)

2. Entra ID (Azure) Authentication Failures

Objective

Failed authentication attempts can signal unauthorized access attempts or brute-force attacks. Mapping these attempts geographically helps identify suspicious patterns.
```
SigninLogs
| where ResultType != 0
| summarize LoginCount = count() by Identity, Latitude = tostring(LocationDetails["geoCoordinates"]["latitude"]), Longitude = tostring(LocationDetails["geoCoordinates"]["longitude"]), City = tostring(LocationDetails["city"]), Country = tostring(LocationDetails["countryOrRegion"])
| project Identity, Latitude, Longitude, City, Country, LoginCount, friendly_label = strcat(Identity, " - ", City, ", ", Country)
```
![2](https://github.com/user-attachments/assets/fa6bebc2-4284-4903-a8b9-3615d08b493c)

3. Azure Resource Creation

Objective

Mapping the creation of Azure resources ensures that these activities align with expected geographic locations, helping detect unauthorized changes.
```
// Only works for IPv4 Addresses
let GeoIPDB_FULL = _GetWatchlist("geoip");
let AzureActivityRecords = AzureActivity
| where not(Caller matches regex @"^[{(]?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}[)}]?$")
| where CallerIpAddress matches regex @"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
| where OperationNameValue endswith "WRITE" and (ActivityStatusValue == "Success" or ActivityStatusValue == "Succeeded")
| summarize ResouceCreationCount = count() by Caller, CallerIpAddress;
AzureActivityRecords
| evaluate ipv4_lookup(GeoIPDB_FULL, CallerIpAddress, network)
| project Caller, 
          CallerPrefix = split(Caller, "@")[0],
          CallerIpAddress, 
          ResouceCreationCount, 
          Country = countryname, 
          Latitude = latitude, 
          Longitude = longitude, 
          friendly_label = strcat(split(Caller, "@")[0], " - ", cityname, ", ", countryname)
```
![3](https://github.com/user-attachments/assets/daf006a2-65f0-4e4b-9b32-fe570a87d962)

4. VM Authentication Failures

Objective

Failed VM authentication attempts are a strong indicator of malicious activity. Visualizing these failures can help pinpoint sources of potential breaches.
```
let GeoIPDB_FULL = _GetWatchlist("geoip");
DeviceLogonEvents
| where ActionType == "LogonFailed"
| order by TimeGenerated desc
| evaluate ipv4_lookup(GeoIPDB_FULL, RemoteIP, network)
| summarize LoginAttempts = count() by RemoteIP, City = cityname, Country = countryname, friendly_location = strcat(cityname, " (", countryname, ")"), Latitude = latitude, Longitude = longitude;
```
![4](https://github.com/user-attachments/assets/07bcb68d-cd10-410f-9974-2cb2204f8fbd)

5. Malicious Traffic Entering the Network

Objective

Understanding the origin of malicious traffic helps security teams implement targeted defenses. Mapping this traffic geographically uncovers high-risk regions.
```
let GeoIPDB_FULL = _GetWatchlist("geoip");
let MaliciousFlows = AzureNetworkAnalytics_CL 
| where FlowType_s == "MaliciousFlow"
| order by TimeGenerated desc
| project TimeGenerated, FlowType = FlowType_s, IpAddress = SrcIP_s, DestinationIpAddress = DestIP_s, DestinationPort = DestPort_d, Protocol = L7Protocol_s, NSGRuleMatched = NSGRules_s;
MaliciousFlows
| evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network)
| project TimeGenerated, FlowType, IpAddress, DestinationIpAddress, DestinationPort, Protocol, NSGRuleMatched, latitude, longitude, city = cityname, country = countryname, friendly_location = strcat(cityname, " (", countryname, ")")
```
![5](https://github.com/user-attachments/assets/55fd6bea-2fef-483f-a421-64a2e4f1afef)




Conclusion

These visualizations provide a vivid and practical way to monitor network activity, track potential threats, and enhance your organization’s cybersecurity posture. By leveraging the power of Azure Sentinel and KQL, security teams can create tailored dashboards to address specific needs and scenarios. The KQL scripts provided here offer a solid starting point for building your own world map visualizations—a crucial tool in today’s cybersecurity landscape.

---------
To create a KQL map in Microsoft Sentinel through Workbooks, follow these steps:

- Open Microsoft Sentinel in the Azure Portal.
- Navigate to your designated workspace and select Workbooks.
- Click on + Add Workbook to create a new one.
- Choose a data source that suits your requirements, such as SigninLogs.
- Write your KQL query, ensuring it includes geospatial data fields like Latitude and Longitude. For example:
```kql
SigninLogs
| summarize LoginCount by Latitude, Longitude
```
- Click + Add Visualization and select the Map option.
- Map the Latitude and Longitude fields to the visualization settings. Customize the map as needed, such as adding labels or adjusting visuals.
- Save your workbook and, if needed, Pin to Dashboard for easy access.
- With this approach, you’ll have an interactive and informative KQL map ready to monitor and analyze network activity! 🌍
