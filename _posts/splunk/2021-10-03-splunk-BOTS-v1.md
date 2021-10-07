---
layout: post
current: post
cover:  assets/built/images/bots-v1.jpg
navigation: True
title: splunk-bots-v1 write up
date: '2021-10-03 20:04:36 +0530'
tags: [splunk]
class: post-template
subclass: 'post tag-splunk'
author: wind-flow
---

## Splunk SOC 대회인 BOSS OF THE SOC(BOTS) Write up

{% include bots-table-of-contents.html %}

![록히드마틴 사이버킬체인 7단계]({{site.baseurl}}/cyberkillchain.jpg)

101	What is the likely IP address of someone from the Po1s0n1vy group scanning imreallynotbatman.com for web application vulnerabilities?  
\(웹 애플리케이션 취약점에 대해 imreallynotbatman.com을 스캔하는 Po1s0n1vy 그룹의 누군가의 가능한 IP 주소는 무엇입니까??)

  ---
<details>
  <summary>hint1</summary>
Start your search with "sourcetype=stream:http" and review the rich data captured in these events.
</details>

<details>
  <summary>hint2</summary>
You'll notice that source and destination IP addresses are stored in fields called src_ip and dest_ip respectively. Determine top-talkers for HTTP by combining : "sourcetype=stream:http | stats count by src_ip, dest_ip | sort -count" </span>
</details>


102 What company created the web vulnerability scanner used by Po1s0n1vy? Type the company name. (For example "Microsoft" or "Oracle")
---

hint#1 : <span style="color:white"> Many commercial web vulnerability scanners clearly identify themselves in the headers of the HTTP request. Inspect the HTTP source headers (src_headers) of requests from the IP identified in question 101. </span>

```
index=botsv1 imreallynotbatman.com sourcetype=stream:http http_method=POST
```

103	What content management system is imreallynotbatman.com likely using?(Please do not include punctuation such as . , ! ? in your answer. We are looking for alpha characters only.)
---
hint#1 : <span style="color:white"> Look for successful (http status code of 200) GET requests from the scanning IP address (identified previously) and inspect the fields related to URL/URI for clues to the CMS in use. </span>

 104	What is the name of the file that defaced the imreallynotbatman.com website? Please submit only the name of the file with extension (For example "notepad.exe" or "favicon.ico")
---
hint#1 : <span style="color:white"> First find the IP address of the web server hosting imreallynotbatman.com. You may have found this IP during the course of answering the previous few questions. </span>
hint#2 : <span style="color:white"> Revealing sourcetypes include stream:http, fgt_utm, and suricata. </span>
hint#3 : <span style="color:white"> The key here is searching for events where the IP address of the web server is the source. Because it's a web server, we most often see it as a destination but in this case the intruder took control of the server and pulled the defacement file from an internet site. </span>

 105	This attack used dynamic DNS to resolve to the malicious IP. What fully qualified domain name (FQDN) is associated with this attack?
---
hint#1 : <span style="color:white"> </span>


 106	What IP address has Po1s0n1vy tied to domains that are pre-staged to attack Wayne Enterprises?
---
hint#1 : <span style="color:white"> </span>


 107	Based on the data gathered from this attack and common open source intelligence sources for domain names, what is the email address that is most likely associated with Po1s0n1vy APT group?
---
hint#1 : <span style="color:white"> </span>


 108	What IP address is likely attempting a brute force password attack against imreallynotbatman.com?
---
hint#1 : <span style="color:white"> </span>


 109	What is the name of the executable uploaded by Po1s0n1vy? Please include file extension. (For example, "notepad.exe" or "favicon.ico")
---
hint#1 : <span style="color:white"> </span>


 110	What is the MD5 hash of the executable uploaded?
---
hint#1 : <span style="color:white"> </span>


 111	GCPD reported that common TTPs (Tactics, Techniques, Procedures) for the Po1s0n1vy APT group, if initial compromise fails, is to send a spear phishing email with custom malware attached to their intended target. This malware is usually connected to Po1s0n1vys initial attack infrastructure. Using research techniques, provide the SHA256 hash of this malware.
---
hint#1 : <span style="color:white"> </span>


 112	What special hex code is associated with the customized malware discussed in question 111? (Hint: It's not in Splunk)
---
hint#1 : <span style="color:white"> </span>


 113	One of Po1s0n1vy's staged domains has some disjointed "unique" whois information. Concatenate the two codes together and submit as a single answer.
---
hint#1 : <span style="color:white"> </span>


 114	What was the first brute force password used?
---
hint#1 : <span style="color:white"> </span>


 115	One of the passwords in the brute force attack is James Brodsky's favorite Coldplay song. Hint: we are looking for a six character word on this one. Which is it?
---
hint#1 : <span style="color:white"> </span>


 116	What was the correct password for admin access to the content management system running "imreallynotbatman.com"?
---
hint#1 : <span style="color:white"> </span>


 117	What was the average password length used in the password brute forcing attempt? (Round to closest whole integer. For example "5" not "5.23213")
---
hint#1 : <span style="color:white"> </span>


 118	How many seconds elapsed between the time the brute force password scan identified the correct password and the compromised login? Round to 2 decimal places.
---
hint#1 : <span style="color:white"> </span>


 119	How many unique passwords were attempted in the brute force attempt?
---
hint#1 : <span style="color:white"> </span>


 200	What was the most likely IP address of we8105desk on 24AUG2016?
---
hint#1 : <span style="color:white"> </span>


 201	Amongst the Suricata signatures that detected the Cerber malware, which one alerted the fewest number of times? Submit ONLY the signature ID value as the answer. (No punctuation, just 7 integers.)
---
hint#1 : <span style="color:white"> </span>


 202	What fully qualified domain name (FQDN) does the Cerber ransomware attempt to direct the user to at the end of its encryption phase?
---
hint#1 : <span style="color:white"> </span>


 203	What was the first suspicious domain visited by we8105desk on 24AUG2016?
---
hint#1 : <span style="color:white"> </span>


 204	During the initial Cerber infection a VB script is run. The entire script from this execution, pre-pended by the name of the launching .exe, can be found in a field in Splunk. What is the length in characters of the value of this field?
---
hint#1 : <span style="color:white"> </span>


 205	What is the name of the USB key inserted by Bob Smith?
---
hint#1 : <span style="color:white"> </span>


 206	Bob Smith's workstation (we8105desk) was connected to a file server during the ransomware outbreak. What is the IP address of the file server?
---
hint#1 : <span style="color:white"> </span>


 207	How many distinct PDFs did the ransomware encrypt on the remote file server?
---
hint#1 : <span style="color:white"> </span>


 208	The VBscript found in question 204 launches 121214.tmp. What is the ParentProcessId of this initial launch?
---
hint#1 : <span style="color:white"> </span>


 209	The Cerber ransomware encrypts files located in Bob Smith's Windows profile. How many .txt files does it encrypt?
---
hint#1 : <span style="color:white"> </span>


 210	The malware downloads a file that contains the Cerber ransomware cryptor code. What is the name of that file?
---
hint#1 : <span style="color:white"> </span>


 211	Now that you know the name of the ransomware's encryptor file, what obfuscation technique does it likely use?
---
hint#1 : <span style="color:white"> </span>
