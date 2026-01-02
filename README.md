# botsv3-incident-analysis  

## Table of contents
- [Introduction](#introduction)
- [SOC Roles & Incident Handling Reflection](#soc-roles--incident-handling-reflection)
- [Installation & Data Preparation](#installation--data-preparation)
- [Guided Questions](#guided-questions)
- [Conclusion, References and Presentation](#conclusion-references-and-presentation)

## Introduction
This report documents an incident analysis of the Splunk "Boss of the SOC v3 (BOTSv3)" dataset to simulate a compromised company; in this instance, Frothly Brewing Company. The scope of this report analyses the email-related and endpoint-related events.

The purpose of this report is to identify the attack from initial access to execution, persistence, lateral movement and impact. It will convey how SOC analysts work when detecting, investigating and mapping findings through MITRE ATT&CK which will guide us through the remediation necessary.

Frothly Brewing Company has provided 320 MB pre-indexed logs, which will be useful in determining how this attack occurred. The exercise assumes the skills of a Tier 1-3 SOC analyst, mapping to MITRE ATT&CK tactics, which will gain stronger development, towards a future in that role.

Splunk Enterprise 10.0.2 and a base64 decoding tool for forensic analysis will be used.

The methodology involves looking at the triage alerts, the network, host or email files to extract the raw data. With this data, mapping through MITRE ATT&CK will guide remediation.


## SOC Roles & Incident Handling Reflection
SOC security analyst tiers, which are structured into three, are reflected in the way alerts are acted on. 

To better understand them, we will need to go through them one by one:

Tier 1 - Monitoring and triage  
This tier's primary focus is on alert triage and prioritisation. When discovered, it is important that it is categorised and escalated to the higher tiers. On this occasion, Tier 1 would be focusing on the phishing email alert.

Tier 2 - Investigation and correlation  
Next, this role will act as incident responders, they will conduct in-depth investigations. Threat intelligence will be used to identify attackers, investigate the attacks and enforce containment and improvement strategies. This would be important when analysing Q3-Q6 around malware execution.

Tier 3 - Threat hunting and improvement  
Lastly, these are the threat hunters, which will search for harder threats and locate vulnerabilities, this can also include any unknown attack patterns which were inflicted on the network. Looking for C2 listener on port 1337 from Q7 as well as the tool deployment will be critical before any further network impact.


## Installation & Data Preparation

Splunk Enterprise 10.0.1 was downloaded from splunk.com and installed. This was then configured with the BOTSV3 dataset to give access to the emails, endpoints and network sources.

![Screenshot from 2025-11-24 13-57-39](https://github.com/user-attachments/assets/268c4319-3a08-432a-aeed-1f51223484da)

The dataset includes the email logs, Windows endpoint logs, Linux system logs and network traffic. Having this configuration allows for a diverse analysis through all layers. As the data is already tagged it will make searching more efficient.

Having the email layer, which is O365 management logs and SMTP traffic, will help with tracking the phishing attachment. 

As for the endpoint layer, it will reveal the malware execution. The security event logs, Sysmon process logs and application logs are important for this. 

The Linux layer will uncover the backdoor creation and movement. Authentication logs as well as osquery snapshots will direct towards the information on the account creation and listeners on the network.


## Guided Questions

#### Q1 — What is the full user agent string that uploaded the malicious link file to OneDrive?

![OneDrive upload screenshot](https://github.com/user-attachments/assets/066c8824-507a-4832-82ee-f58df389bab1)

As we must check OneDrive, sourcetype="ms:o365:management" was added to look through the logs of uploaded files. To identify files that were uploaded, Operation=fileUploaded was then added on to this, which presented seven events, but we would have to look deeper to find the specific file.  

| Search Term | Purpose |
| sourcetype="ms:o365:management" | O365 management logs |
| Operation=fileUploaded | File uploads only |

![Splunk fileUploaded search](https://github.com/user-attachments/assets/c8b7d2db-3a35-453e-af59-17f0d815d357)

Next, SourceFileName="*.lnk" was added as it is commonly used as an exploit and is used to hide executable files to install malware. By doing this, it narrows it down to one event. Looking at the event details, you can see the SourceFileName to be BRUCE BIRTHDAY HAPPY OUR PICS.lnk.  

|Sourcetype| Description |
| :--- | :--- |
| SourceFileName=".lnk" | Identifying any filenames that have .lnk as their extension |

![Identified .lnk filename](https://github.com/user-attachments/assets/6131af68-d5f0-4019-87a8-2f605c8d9697)

Including the SourceFileName in the search bar was the next step, while also making it into a table which includes the time, UserID, SourceFileName and the Operation.  

|Sourcetype| Description |
| :--- | :--- |
| SourceFileName="BRUCE BIRTHDAY HAPPY OUR PICS.lnk" | Specifying the .lnk file |
| _time, UserID, SourceFileName, Operation | Presenting output in a neat table |

As you can see from the screenshot above, the answer is:  

```text
Mozilla/5.0 (X11; U; Linux i686; ko-KP; rv: 19.1br) Gecko/20130508 Fedora/1.9.1-2.5.rs3.0 NaenaraBrowser/3.5b4
```
The user agent string shows that a Linux-based browser, which originates from North Korea. Uploading the malicious .lnk file, confirms initial access via spear-phishing (T1566.001).

---

#### Q2 — What was the name of the macro-enabled attachment identified as malware?

![SMTP alert screenshot](https://github.com/user-attachments/assets/e8139788-a831-462e-aaf1-965adfc099da)

We need to check the mail traffic data to find out which file was the malware. By checking the alert, and looking at the attached filename section, it showed Malware_Alert_Text.txt to be the suspicious file.

|Sourcetype| Description |
| :--- | :--- |
| sourcetype="stream:smtp" | Analysing SMTP (Simple Mail Transfer Protocol) traffic data |

![SMTP evidence screenshot](https://github.com/user-attachments/assets/a8932a52-d9d5-48e1-883f-cc42724180e3)

Clicking on the name presented the raw data which led to discovering a base64 string, which will need to be decoded to reveal the real name of the attachment.

![Base64 decoded filename evidence](https://github.com/user-attachments/assets/96265dae-67d4-4882-a91e-24d3b10c71f7)

Using base64decoder.org, the output showed:

|Decode data|
| :--- |
| Frothly-Brewery-Financial-Planning-FY2019-D |

As it ends with D, we can presume that it is probably a draft and because it is a macro-enabled Excel document, the file type would be .xlsm.

So the name of the file was:

```text
Frothly-Brewery-Financial-Planning-FY2019-Draft.xlsm
```
The macro-enabled .xlsm was used as a hidden vehicle to deliver malware, behind a trusted financial doc to activate a payload fit under as it was embedded (T1559.002).

---

#### Q3 — What is the name of the executable that was embedded in the malware?

To look for the application, you must check:  

|Source| Description |
| :--- | :--- |
| source="WinEventLog:Application" | Identifying event logs for applications |  

![Windows application logs screenshot](https://github.com/user-attachments/assets/9e748248-7e67-447c-92b8-dc6ca311d7d2)

This will show all the applications that were used and logged on the Windows system.

![Application usage screenshot](https://github.com/user-attachments/assets/5f1ce885-b5b1-4757-aae3-74c71abf2fd2)

Once selecting the Symantec AntiVirus on the left menu, it revealed the contents that was scanned. 

|Source Name| Description |
| :--- | :--- |
| SourceName="Symantec AntiVirus" | The name of the antivirus | 

![Symantec scan screenshot](https://github.com/user-attachments/assets/52250289-bad5-45a0-8cbd-b1c0fa5bad49)

By adding \*Frothly\* to the end, as we are looking for a specific event that relates.  

![Frothly filter screenshot](https://github.com/user-attachments/assets/2d66e961-3c92-4483-a8f3-7a0b4f3c4405)

|Source Name| Description |
| :--- | :--- |
| sourceName="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" | Checking system monitoring | 

By checking this location, it allows us to see what the malware was using on the system.

\*xlsm\* | reverse  was added to the end, to focus the search for any .xlsm extensions and reverse was to have the relevant event at the top.

Looking at the event information, as highlighted in the screenshot, the executable is stated as:

```text
HxTsr.exe
```
As the payload is via the Excel macro (T1204.002), it is moved from initial access to execution.

---

#### Q4 — What is the password for the user that was successfully created by the user "root" on the on-premises Linux system?

![Linux auth screenshot](https://github.com/user-attachments/assets/a89a6705-ca6f-4c81-95b9-d2e59f7f984c)

| Command | Description |
| :--- | :--- |
| (adduser OR useradd ) | Adding the user |

![adduser event screenshot](https://github.com/user-attachments/assets/fa04b36e-f617-47c2-87c4-50fbee866ae4)

| Source | Description |
| :--- | :--- |
| /var/log/auth.log | This shows all the user events |

![auth.log screenshot](https://github.com/user-attachments/assets/6e911984-3c36-4c44-b326-7343d20dfbdc)

When clicking on the linked text, it presented one event stating the new user was tomcat7. It shows it was added by UID=0, which is the root user.

![tomcat7 creation screenshot](https://github.com/user-attachments/assets/50eef10f-bab7-4d12-8365-17856f22a16b)

Replacing the search with tomcat7, it showed twelve events. Looking at the source type on the left, osquery:results was presented.

![osquery results screenshot](https://github.com/user-attachments/assets/34257954-7d97-41f7-8e1c-639ebb50b640)


After clicking on the linked text, it revealed one event. Clicking on show as raw text on the first event, the password revealed itself to be:

```text
ilovedavidverve
```
The tomcat7 account (T1136.001) is an account that was created to further movement.

---

#### Q5 — What is the name of the user that was created after the endpoint was compromised?

To identify the name of the user, the malware execution would need to be followed so it will reveal the event logs of the Windows Security on user account creations.

|Search Query| Description |
| :--- | :--- |
| index="botsv3" | Searching within the BOTSv3 dataset |
| source="wineventlog:security" | Windows Security event logs containing authentication and account management activities |
| EventCode=4720 | Event code specifically for "A user account was created" |

![Screenshot from 2025-12-19 21-04-58](https://github.com/user-attachments/assets/7a1ab20a-0c97-44d8-b72d-cf3a8ca49c27)

Using the search query `index="botsv3" source="wineventlog:security" EventCode=4720`, we can see there is only one event that was created.

To identify that the account was created after the endpoint was compromised, we needed to sort them chronologically to correlate with the timeline from Q3.

![Screenshot from 2025-12-19 21-06-13](https://github.com/user-attachments/assets/bb929476-4b6b-4182-9e36-26004a0490a4)

Looking closer at the event details, we can see that the user account was named "svcvnc". The reason it is suspicious is that it suggests an account for VNC (Virtual Network Computing), which is a remote desktop protocol, was used by an attacker.

As shown in the first screenshot, the account was created 19/08/2018 at 22:08:17.


```text
svcvnc
```
This provides a backdoor to continue their control of the endpoint.

---

#### Q6 — Based on the previous question, what groups was this user assigned to after the endpoint was compromised?

|Search Query| Description |
| :--- | :--- |
| EventCode=4732 | Event code for "A member was added to a security-enabled global group" |
| TargetUserName="svcvnc" | Filtering for events related to the svcvnc account being added to groups |
| GroupName | Field containing the name of the group the user was added to |

![Screenshot from 2025-12-19 21-08-31](https://github.com/user-attachments/assets/321a5e95-038e-43c2-9f69-3fa8a737922b)

When including svcvnc in the search bar, it revealed EventCode=4732 combined with it.

![Screenshot from 2025-12-19 21-11-18](https://github.com/user-attachments/assets/948d843d-3824-497b-ada8-9c73e23606e6)

EventCode=4732 was then included, which revealed two events.
Both events were expanded to show more detail.

![Screenshot from 2025-12-19 21-11-31](https://github.com/user-attachments/assets/3904b237-2cd8-4d80-9cdd-af611c4aea7d)

This screenshot shows the creation of GroupName = administrator.

![Screenshot from 2025-12-19 21-11-50](https://github.com/user-attachments/assets/967ddcf0-c92e-4e78-9edb-9d2aeccbcb25)

Lastly, GroupName = user is shown in the second event.

```text
administrators,user
```
Escalating or manipulating account (T1098.002), provides improved recon and persistence.

---

#### Q7 — What is the process ID of the process listening on a "leet" port?

| Search Query | Description |
| :--- | :--- |
| index="botsv3" 1337 | Searching the BOTSv3 dataset for port 1337 |
| sourcetype="osquery:results" | Filtering for osquery system monitoring results |
| columns.port=1337 | Narrowing to processes specifically listening on port 1337 |

![Screenshot from 2025-12-19 21-16-28](https://github.com/user-attachments/assets/5bdf1fbc-2eb0-48cf-b9e0-72022e15c4cf)

First, we need to search for the port 1337 across the dataset.

![Screenshot from 2025-12-19 21-17-22](https://github.com/user-attachments/assets/e1380b6d-641b-42e6-8711-86c06bedaee3)

Adding osquery results will bring us closer to more system-level processes.

![Screenshot from 2025-12-19 21-17-51](https://github.com/user-attachments/assets/9fd0323a-3d2c-4784-8833-2e656691ff41)

As you can see in the port column, it reveals port 1337.

![Screenshot from 2025-12-19 21-18-40](https://github.com/user-attachments/assets/ac3332be-5d04-4084-a946-e9c9bd4fa916)

By adding columns.port=1337 to the search, the process connected to the port has process ID:

```text
14356
```

Using 14356 on port 1337 reveals a backdoor C2 listener (T1571), which is a communication channel.

---

#### Q8 — What is the MD5 value of the file downloaded to Fyodor's endpoint system and used to scan Frothly's network?

| Search Query | Description |
| :--- | :--- |
| index="botsv3" host="FYODOR-L" | Searching within the BOTSv3 dataset filtered to Fyodor's endpoint |
| sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" | Sysmon logs capturing process execution and file activity |
| EventID=1 | Process creation events |
| TargetFileName | File path field showing executable locations |
| Hashes | MD5 hash field from Sysmon file metadata |

![Screenshot from 2025-12-19 21-21-59](https://github.com/user-attachments/assets/0b4c2b28-16f4-4ac3-ba03-74e621a1091f)

Next, Fyodor's activity was searched in the dataset.

![Screenshot from 2025-12-19 21-22-47](https://github.com/user-attachments/assets/38f7eb72-7666-4aca-849a-bcbbac8f0a50)

The Sysmon logs were looked through and revealed the events on FYODOR-L.

![Screenshot from 2025-12-30 22-51-26](https://github.com/user-attachments/assets/4419179e-b3ee-4b73-9a0d-0e0d6c2971a1)

To find the name of the file, TargetFileName was added to the search.

![Screenshot from 2025-12-30 22-51-55](https://github.com/user-attachments/assets/4e7b4b54-531a-4883-8bb6-4a28bbba8f76)

In one of the events, **C:\windows\temp\hdoor.exe** was identified which could be a possible malicious executable.

![Screenshot from 2025-12-30 22-52-30](https://github.com/user-attachments/assets/89e2d4f1-8f1d-4677-8281-4fbcc6623749)

Checking through MITRE ATT&CK confirms that hdoor.exe is a known network scanning tool used for reconnaissance.

![Screenshot from 2025-12-19 23-46-47](https://github.com/user-attachments/assets/d672732b-0077-4eeb-99e3-a9dc8589da37)

Finally, the events showed that the MD5 hash of hdoor.exe is:

```text
586ef56f4d8963dd546163ac31c865d7
```

The network scanning tool (T1046) was deployed to map out the internal network.


---

### Attack Chain Visualisation

![Screenshot from 2025-12-20 00-48-49](https://github.com/user-attachments/assets/95be2fc8-78a3-45c4-84dd-a7a27635ff0d)


The timeline shows correlation of the events across Q1-Q8, from initial access to persistence.

| Time     | Event                       | MITRE Technique      | Evidence |
|----------|-----------------------------|---------------------|----------|
| 09:57:XX | Malicious LNK to OneDrive   | T1566.001           | Q1       |
| 10:08:XX | svcvnc admin user created   | T1136.001           | Q5/Q6    |
| 11:24:XX | tomcat7 Linux backdoor      | T1053.005           | Q4       |

## Conclusion, References and Presentation

Each section of the analysis revealed that Frothly Brewing Company was under a multi-stage attack. These are the listed stage attacks:

Phishing, which was the initial access, presented itself as a malicious OneDrive-hosted.lnk file. In this instance it would be called 'spear-phishing' as it is targeted towards a specific individual, group or organisation.

Malware Deployment, which is execution, was presented as an embedded payload named HxTsr.exe. Persistence Mechanisms under the category accounts/services, creating the backdoor accounts through svcvnc. Tomcat7 was another account created by root to enable further access. 

Network Reconnaissance, stated as Scanning was the final step, an executable run by the attacker, which in this case is hdoor.exe from C:\windows\temp\ targeting the 192.168.9.1-192.168.9.50 range.

As a takeaway, these three bullet points would have prevented each attack from progressing:

- With the initial access driven by spear-phishing, implementing email controls to mitigate the issue.

- Monitoring account would have alerted the account creation.

- As the recon scanning was noisy, hdoor.exe could have been detected by a network EDR.
