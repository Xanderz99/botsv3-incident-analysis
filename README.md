# botsv3-incident-analysis  

# Table of contents
  * [Introduction (10%)](#introduction--10--)
  * [SOC Roles & Incident Handling Reflection (10%)](#soc-roles---incident-handling-reflection--10--)
  * [Installation & Data Preparation (15%)](#installation---data-preparation--15--)
  * [Guided Questions (40%)](#guided-questions--40--)
  * [Conclusion, References and Presentation (5%)](#conclusion--references-and-presentation--5--)  

## Introduction (10%)
•	Overview of the SOC context

•	Overview of the BOTSv3 exercise

•	Overview of the objects of investigation


## SOC Roles & Incident Handling Reflection (10%)


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

As we have to check OneDrive, sourcetype="ms:o365:management" to look through the logs. To identify files that were uploaded, Operation=fileUploaded was then added, which presented seven events but we would have to look deeper to find the specific file.  

| Sourcetype | Description |
| :--- | :--- |
| sourcetype="ms:o365:management | Capturing Microsoft 365 management logs |
| Operation=fileUploaded | Revealing uploaded files|

<p>
<img width="1920" height="1080" alt="Screenshot from 2025-11-24 14-39-28" src="https://github.com/user-attachments/assets/c8b7d2db-3a35-453e-af59-17f0d815d357" />  
</p>

Next, SourceFileName="*.lnk" was added which narrowed it down to one event. Looking at the event details you can see the SourceFileName to be BRUCE BIRTHDAY HAPPY OUR PICS.lnk.  

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


## Conclusion, References and Presentation (5%)
