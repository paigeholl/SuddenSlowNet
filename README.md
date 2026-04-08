**Sudden Network Slowdown Investigation**
====================================================================

This threat hunt focuses on identifying the cause of sudden network slowdowns reported by the server team. After ruling out external attacks, we shifted our attention to internal hosts and uncovered suspicious port‑scanning behavior originating from an older device on the 10.0.0.0/16 network.

**1\. Preparation**
-------------------

**Goal:** Set up the hunt by defining what we're looking for.

The server team noticed significant performance degradation on several older devices in the 10.0.0.0/16 network. External DDoS attacks were ruled out, so the security team suspected something internal. Since internal traffic is unrestricted and PowerShell is widely allowed, it was possible someone was downloading large files or scanning ports across the network.

**Activity:** Develop a hypothesis based on internal risks.

Because internal traffic is implicitly trusted and older devices lack restrictions, our working hypothesis was:

**"A device inside the network may be generating excessive traffic --- possibly port scanning or repeatedly failing connections --- causing the slowdown."**

**2\. Data Collection**
-----------------------

**Goal:** Gather relevant data from logs, network traffic, and endpoints.

We focused on identifying devices generating excessive failed or successful connections. If anything looked abnormal, we would pivot into file and process events.

**Activity:** Verify that the following tables contain recent logs:

-   DeviceNetworkEvents
-   DeviceFileEvents
-   DeviceProcessEvents

We started by checking which devices were generating large amounts of failed connections.

```
DeviceNetworkEvents
| where DeviceName == "king-th-vm"
| where ActionType == "ConnectionFailed"
| summarize FailedConnectionsAttempts = count() by DeviceName, ActionType, LocalIP
| order by FailedConnectionsAttempts

```

**Finding:** The device was failing a large number of connection attempts to multiple internal hosts.

**3\. Data Analysis**
---------------------

**Goal:** Analyze the data to test the hypothesis.

**Activity:** Look for patterns of excessive network connections, repeated failures, or sequential port activity.

We pivoted into the failed connections for a specific internal IP.

```
let IPInQuestion = "10.0.0.5";
DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| where LocalIP == IPInQuestion
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, RemoteIP, RemotePort

```

**Finding:** The failed connections showed a clear sequential pattern across common ports --- a strong indicator of a port scan. Multiple port scans appeared to be taking place.

**4\. Investigation**
---------------------

**Goal:** Investigate suspicious findings and determine their scope.

**Activity:** Search DeviceFileEvents and DeviceProcessEvents around the same timestamps to identify what triggered the port scans.

We checked for processes running around the time the port scan activity began.

```
let VMName = "";
let specificTime = datetime(2024-10-18T04:09:37.5180794Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 10m) .. (specificTime + 10m))
| where DeviceName == VMName
| order by Timestamp desc
| project Timestamp, FileName, InitiatingProcessCommandLine

```

**Finding:** A PowerShell script named **portscan.ps1** was executed on the device at `2026-04-08T19:53:44Z`.

We then narrowed the search to identify who launched the script.

```
let VMName = "king-th-vm";
let specificTime = datetime(2026-04-08T19:54:08.5350886Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 10m) .. (specificTime + 10m))
| where DeviceName == VMName
| where InitiatingProcessCommandLine contains "portscan"
| order by Timestamp desc
| project Timestamp, AccountName, FileName, InitiatingProcessCommandLine

```

**Finding:** The script was launched under the user account **paige**, who was unaware of the activity. This behavior was not authorized by admins.

### **MITRE ATT&CK TTPs Identified**

```
T1595 -- Active Scanning
T1046 -- Network Service Scanning
T1018 -- Remote System Discovery
T1059 -- Command and Scripting Interpreter (PowerShell)
T1105 -- Ingress Tool Transfer (portscan.ps1 script)
T1204 -- User Execution
T1569 -- System Services

```

**5\. Response**
----------------

**Goal:** Mitigate the threat and prevent further impact.

**Activity:** Because the user did not intentionally run the script and the behavior was unexpected, the device was isolated and scanned for malware.

**Finding:** The malware scan returned clean, but due to the suspicious activity and potential compromise, the device remained isolated and a ticket was submitted to have it reimaged/rebuilt.

**6\. Documentation**
---------------------

**Goal:** Record findings and lessons learned.

**Activity:** This investigation documented:

-   The source of the network slowdown
-   Evidence of internal port scanning
-   Identification of the script and user context
-   Isolation and remediation steps taken

Screenshots or log snippets can be added here as needed.

**7\. Improvement**
-------------------

**Goal:** Improve security posture and refine future hunts.

**Activity:** Potential improvements include:

-   Restricting PowerShell usage on older devices
-   Implementing application control
-   Monitoring for sequential port activity
-   Adding alerts for excessive failed connections
-   Hardening internal network segmentation
-   Reviewing user permissions on legacy systems

These steps would help prevent similar internal scanning activity and improve detection speed in future hunts.
