# botsv3-incident-analysis  

## Table of contents
 - [Introduction (10%)](#introduction--10--)
 - [SOC Roles & Incident Handling Reflection (10%)](#soc-roles---incident-handling-reflection--10--)
 - [Installation & Data Preparation (15%)](#installation---data-preparation--15--)
 - [Guided Questions (40%)](#guided-questions--40--)
 - [Conclusion, References and Presentation (5%)](#conclusion--references-and-presentation--5--)

## Introduction (10%)
This report documents an incident analysis of the Splunk "Boss of the SOC v3 (BOTSv3)" dataset to simulate what it would be like to have a compromised company, which in this instance is 'Frothly Brewing Company'.

The purpose of this report is to identify the attack from initial access to execution, persistence, lateral movement to impact. It will convey how SOC analysts work when detecting, investigating and map finding through MITRE ATT&CK which will guide us through the remediation neccessary.

Frothly Brewing Company provided 320MB pre-indexed logs, including their network traffic which will be useful towards the correct answers to how this attack had happened. The excercise provides the skills of a Tier 1-3 SOC analyst, mapping to MITRE ATT&CK tactics. 

Tools that will be used are Splunk Enterprise 10.0.2 through search & reporting and a base64 decoding tool to inspect attachments.

For the Methodology, the dataset will need to be identified, looking through the triage alerts, the network, host or email files to extract the raw data. With this data, we would need to map out the activity through MITRE ATT&CK and come to an understating on the best cause of action.


## SOC Roles & Incident Handling Reflection (10%)
To better understand the SOC security analyst tiers, we will have to go through them one by one:

Tier 1 - Monitoring and triage
This tier primary focus is on alert triage and prioritisation. When discovered it is important that it is categorised and escalated to the higher tiers.

Tier 2 - Investigation and correlation
Next, this role will ace as incident responders, they will conduct in-depth investigations. Threat intelligence will be used to identify attackers, investigate the attacks and inforce containment and improvement strategies.

Tier 3 - Threat hunting and improvement
Lastly, these are the threat hunters, which will search for harder threats and locate vulnerabilities, this can also include any unknown attack patterns which was afflicted on the network.

## Installation & Data Preparation (15%)
Splunk was installed from: 

| Download Page |
| :--- |
| https://www.splunk.com/en_us/download/splunk-enterprise.html |  

The wget link was copied for .tgz at:  

| wget link |
| :--- | 
| wget -O splunk-10.0.2-e2d18b4767e9-linux-amd64.tgz "https://download.splunk.com/products/splunk/releases/10.0.2/linux/splunk-10.0.2-e2d18b4767e9-linux-amd64.tgz" |  

![Screenshot from 2025-11-24 13-57-39](https://github.com/user-attachments/assets/268c4319-3a08-432a-aeed-1f51223484da)

## Guided Questions (40%)

#### Q1 — What is the full user agent string that uploaded the malicious link file to OneDrive?

![OneDrive upload screenshot](https://github.com/user-attachments/assets/066c8824-507a-4832-82ee-f58df389bab1)

As we have to check OneDrive, sourcetype="ms:o365:management" was added to look through the logs of uploaded files. To identify files that were uploaded, Operation=fileUploaded was then added on to this, which presented seven events but we would have to look deeper to find the specific file.  

| Sourcetype | Description |
| :--- | :--- |
| sourcetype="ms:o365:management | Capturing Microsoft 365 management logs |
| Operation=fileUploaded | Revealing uploaded files |

![Splunk fileUploaded search](https://github.com/user-attachments/assets/c8b7d2db-3a35-453e-af59-17f0d815d357)

Next, SourceFileName="*.lnk" was added as it is commonly used as an exploit and is used to hide excutable files to install malware. By doing this, it narrows it down to one event. Looking at the event details you can see the SourceFileName to be BRUCE BIRTHDAY HAPPY OUR PICS.lnk.  

|Sourcetype| Description |
| :--- | :--- |
| SourceFileName=".lnk" | Identifying any filenames that have .lnk as their extension |

![Identified .lnk filename](https://github.com/user-attachments/assets/6131af68-d5f0-4019-87a8-2f605c8d9697)

Including the SourceFileName in the search bar was the next step, while also making it into a table which includes the time, Userid, SourceFileName and the Operation.  

|Sourcetype| Description |
| :--- | :--- |
| SourceFileName="BRUCE BIRTHDAY HAPPY OUR PICS.lnk" | Specifying the .lnk file |
| _time, Userid, SourceFileName, Operation | Presenting output in a neat table |

As you can see from the screenshot above, the answer is:  

```text
Mozilla/5.0 (X11; U; Linux i686; ko-KP; rv: 19.1br) Gecko/20130508 Fedora/1.9.1-2.5.rs3.0 NaenaraBrowser/3.5b4
```


---

#### Q2 — What was the name of the macro-enabled attachment identified as malware?

![SMTP alert screenshot](https://github.com/user-attachments/assets/e8139788-a831-462e-aaf1-965adfc099da)

We need to check the mail traffic data to find out which file was the malware. By checking the alert, and looking at the attached filename section, it showed Malware_Alert_Text.txt to be the suspicious file.

|Sourcetype| Description |
| :--- | :--- |
| sourcetype="stream:smtp" | Analysing SMTP (Simple Mail Transfer Protocol) traffic data |

![SMTP evidence screenshot](https://github.com/user-attachments/assets/a8932a52-d9d5-48e1-883f-cc42724180e3)

Clicking on the name presented the raw data which lead to discovering a base64 string, which will need to be decoded to reveal the real name of the attachment.

![Base64 decoded filename evidence](https://github.com/user-attachments/assets/96265dae-67d4-4882-a91e-24d3b10c71f7)

Through using website base64decoder.org, the output showed:

|Decode data|
| :--- |
| Frothly-Brewery-Financial-Planning-FY2019-D |

As it ends with D, we can presume that it is probably a draft and because it is a macro-enabled excel document, the file type would be .xlsm.

So the name of the file was:

```text
Frothly-Brewery-Financial-Planning-FY2019-Draft.xlsm
```


---

#### Q3 — What is the name of the executable that was embedded in the malware?

To look for the application, you have to check:  

|Source| Description |
| :--- | :--- |
| source="WinEventLog:Application" | Identifying event logs for applications |  

![Windows application logs screenshot](https://github.com/user-attachments/assets/9e748248-7e67-447c-92b8-dc6ca311d7d2)

This will show all of the applications that were used and logged on the Windows system.

![Application usage screenshot](https://github.com/user-attachments/assets/5f1ce885-b5b1-4757-aae3-74c71abf2fd2)

Once selecting the Symantec AntiVirus on the left menu, it revealed the contents that was scanned. 

|Source Name| Description |
| :--- | :--- |
| SourceName="Symantec AntiVirus" | The name of the antivirus | 

![Symantec scan screenshot](https://github.com/user-attachments/assets/52250289-bad5-45a0-8cbd-b1c0fa5bad49)

By adding \*Frothly\* to end as we are looking for a specific event that relates.  

![Frothly filter screenshot](https://github.com/user-attachments/assets/2d66e961-3c92-4483-a8f3-7a0b4f3c4405)

|Source Name| Description |
| :--- | :--- |
| sourceName="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" | Checking System monitoring | 

By checking this location, it allows us to see what the malware was using on the system.

\*xlsm\* | reverse  was added to the end to focus the search for any .xlsm extentions and reverse was to have the relevent event at the top.

Looking the event information, as highlighted in the screenshot, the executable is stated as:

```text
HxTsr.exe
```


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

When clicking on the linked text, it presented 1 event stating the new user was tomcat7. It shows that it was add by UID=0, which is the root user.

![tomcat7 creation screenshot](https://github.com/user-attachments/assets/50eef10f-bab7-4d12-8365-17856f22a16b)

Replacing the search with tomcat7, it showed 12 events. Looking at the source type on the left, osquery:results was presented.

![osquery results screenshot](https://github.com/user-attachments/assets/34257954-7d97-41f7-8e1c-639ebb50b640)


After clicking on the linked text, it revealed 2 events. Clicking on show as raw text on the first event, the password revealed itself to be:

```text
ilovedavidverve
```

---

#### Q5 — What is the name of the user that was created after the endpoint was compromised?


---

#### Q6 — Based on the previous question, what groups was this user assigned to after the endpoint was compromised?


---

#### Q7 — What is the process ID of the process listening on a "leet" port?


---

#### Q8 — What is the MD5 value of the file downloaded to Fyodor's endpoint system and used to scan Frothly's network?


## Conclusion, References and Presentation (5%)
