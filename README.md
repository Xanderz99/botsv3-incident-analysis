# botsv3-incident-analysis  

## Table of contents
  * [Introduction (10%)](#introduction--10--)
  * [SOC Roles & Incident Handling Reflection (10%)](#soc-roles---incident-handling-reflection--10--)
  * [Installation & Data Preparation (15%)](#installation---data-preparation--15--)
  * [Guided Questions (40%)](#guided-questions--40--)
  * [Conclusion, References and Presentation (5%)](#conclusion--references-and-presentation--5--)  

## Introduction (10%)
The Security Operations Centers (SOCs) have to face the challenges of detecting multi-stage attacks which ranges over hybrid cloud environments. 

A way to better understand, Splunk has developed a dataset called 'The Boss of the SOC v3' (BOTSv3). It is able to simulate what it would be like to have a compromised company, which in this instance is 'Frothly Brewing Company'. 

They provided 320MB pre-indexted logs, including their network traffic which will be useful to answering the correct answers to how this attack had happened. The excercise provides the skills of a Tier 1-3 SOC analyst, mapping to MITRE ATT&CK tactics.


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

<p>
<img width="1920" height="1080" alt="Screenshot from 2025-11-24 13-57-39" src="https://github.com/user-attachments/assets/268c4319-3a08-432a-aeed-1f51223484da" />
</p>

## Guided Questions (40%)
### What is the full user agent string that uploaded the malicious link file to OneDrive?  

<p>
<img width="1920" height="1080" alt="Screenshot from 2025-11-24 14-34-48" src="https://github.com/user-attachments/assets/066c8824-507a-4832-82ee-f58df389bab1" />  
</p>

As we have to check OneDrive, sourcetype="ms:o365:management" was added to look through the logs of uploaded files. To identify files that were uploaded, Operation=fileUploaded was then added on to this, which presented seven events but we would have to look deeper to find the specific file.  

| Sourcetype | Description |
| :--- | :--- |
| sourcetype="ms:o365:management | Capturing Microsoft 365 management logs |
| Operation=fileUploaded | Revealing uploaded files |

<p>
<img width="1920" height="1080" alt="Screenshot from 2025-11-24 14-39-28" src="https://github.com/user-attachments/assets/c8b7d2db-3a35-453e-af59-17f0d815d357" />  
</p>

Next, SourceFileName="*.lnk" was added as it is commonly used as an exploit and is used to hide excutable files to install malware. By doing this, it narrows it down to one event. Looking at the event details you can see the SourceFileName to be BRUCE BIRTHDAY HAPPY OUR PICS.lnk.  

|Sourcetype| Description |
| :--- | :--- |
| SourceFileName=".lnk" | Identifying any filenames that have .lnk as their extension |

<p>
  <img width="1920" height="1080" alt="Screenshot from 2025-11-24 14-43-16" src="https://github.com/user-attachments/assets/6131af68-d5f0-4019-87a8-2f605c8d9697" />
</p>

Including the SourceFileName in the search bar was the next step, while also making it into a table which includes the time, Userid, SourceFileName and the Operation.  

|Sourcetype| Description |
| :--- | :--- |
| SourceFileName="BRUCE BIRTHDAY HAPPY OUR PICS.lnk" | Specifying the .lnk file |
| _time, Userid, SourceFileName, Operation | Presenting output in a neat table |

As you can see from the screenshot above, the answer is:  
<b> Mozilla/5.0 (X11; U; Linux i686; ko-KP; rv: 19.1br) Gecko/20130508 Fedora/1.9.1-2.5.rs3.0 NaenaraBrowser/3.5b4 </b>

### What was the name of the macro-enabled attachment identified as malware?

<p>
<img width="1714" height="874" alt="Screenshot from 2025-11-24 15-00-48" src="https://github.com/user-attachments/assets/e8139788-a831-462e-aaf1-965adfc099da" />
</p>

We need to check the mail traffic data to find out which file was the malware. By checking the alert, and looking at the attached filename section, it showed Malware_Alert_Text.txt to be the suspicious file.

|Sourcetype| Description |
| :--- | :--- |
| sourcetype="stream:smtp" | Analysing SMTP (Simple Mail Transfer Protocol) traffic data |

<p>
 <img width="1714" height="874" alt="Screenshot from 2025-11-24 15-04-22" src="https://github.com/user-attachments/assets/a8932a52-d9d5-48e1-883f-cc42724180e3" />
</p>

Clicking on the name presented the raw data which lead to discovering a base64 string, which will need to be decoded to reveal the real name of the attachment.

<p>
<img width="1714" height="874" alt="Screenshot from 2025-11-24 15-07-18" src="https://github.com/user-attachments/assets/96265dae-67d4-4882-a91e-24d3b10c71f7" />
</p>

Through using website base64decoder.org, the output showed:

|Decode data|
| :--- |
| Frothly-Brewery-Financial-Planning-FY2019-D |

As it ends with D, we can presume that it is probably a draft and because it is a macro-enabled excel document, the file type would be .xlsm.

So the name of the file was <b> Frothly-Brewery-Financial-Planning-FY2019-Draft.xlsm </b>.

### What is the name of the executable that was embedded in the malware?  

To look for the application, you have to check:  

|Source| Description |
| :--- | :--- |
| source="WinEventLog:Application" | Identifying event logs for applications |  

<p>
<img width="1714" height="874" alt="Screenshot from 2025-12-01 19-49-35" src="https://github.com/user-attachments/assets/9e748248-7e67-447c-92b8-dc6ca311d7d2" />
</p>

This will show all of the applications that were used and logged on the Windows system.

<p>
<img width="1714" height="874" alt="Screenshot from 2025-12-01 20-09-44" src="https://github.com/user-attachments/assets/5f1ce885-b5b1-4757-aae3-74c71abf2fd2" />
</p>

Once selecting the Symantec AntiVirus on the left menu, it revealed the contents that was scanned. 

|Source Name| Description |
| :--- | :--- |
| SourceName="Symantec AntiVirus" | The name of the antivirus | 

<p>
 <img width="1714" height="874" alt="Screenshot from 2025-12-01 20-12-09" src="https://github.com/user-attachments/assets/52250289-bad5-45a0-8cbd-b1c0fa5bad49" />
</p> 

By adding \*Frothly\* to end as we are looking for a specific event that relates.  

<p>
 <img width="1714" height="874" alt="Screenshot from 2025-12-01 20-32-20" src="https://github.com/user-attachments/assets/2d66e961-3c92-4483-a8f3-7a0b4f3c4405" />
</p>

|Source Name| Description |
| :--- | :--- |
| sourceName="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" | Checking System monitoring | 

By checking this location, it allows us to see what the malware was using on the system.

\*xlsm\* | reverse  was added to the end to focus the search for any .xlsm extentions and reverse was to have the relevent event at the top.

Looking the event information, as highlighted in the screenshot, the executable is stated as HxTsr.exe  

### What is the password for the user that was successfully created by the user "root" on the on-premises Linux system? ###

<p>
 <img width="1714" height="874" alt="Screenshot from 2025-12-11 13-55-05" src="https://github.com/user-attachments/assets/a89a6705-ca6f-4c81-95b9-d2e59f7f984c" />
</p>

| Command | Description |
| :--- | :--- |
| (adduser OR useradd ) | Adding the user |

<p>
 <img width="1714" height="874" alt="Screenshot from 2025-12-11 13-56-32" src="https://github.com/user-attachments/assets/fa04b36e-f617-47c2-87c4-50fbee866ae4" />
</p>

| Source | Description |
| :--- | :--- |
| /var/log/auth.log | This shows all the user events |

<p>
 <img width="1714" height="874" alt="Screenshot from 2025-12-11 13-58-15" src="https://github.com/user-attachments/assets/6e911984-3c36-4c44-b326-7343d20dfbdc" />
</p>

When clicking on the linked text, it presented 1 event stating the new user was tomcat7. It shows that it was add by UID=0, which is the root user.

<p>
 <img width="1714" height="874" alt="Screenshot from 2025-12-11 13-59-55" src="https://github.com/user-attachments/assets/50eef10f-bab7-4d12-8365-17856f22a16b" />
</p>

Replacing the search with tomcat7, it showed 12 events. Looking at the source type on the left, osquery:results was presented.

<p>
 <img width="1714" height="874" alt="Screenshot from 2025-12-11 14-00-28" src="https://github.com/user-attachments/assets/34257954-7d97-41f7-8e1c-639ebb50b640" />
</p>

After clicking on the linked text, it revealed 2 events. Clicking on show as raw text on the first event, the password revealed itself to be <b> ilovedavidverve </b>

## Conclusion, References and Presentation (5%)
