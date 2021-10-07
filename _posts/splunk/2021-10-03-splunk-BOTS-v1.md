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

Scenario 1 (APT):

The focus of this hands on lab will be an APT scenario and a ransomware scenario. You assume the persona of Alice Bluebird, the analyst who has recently been hired to protect and defend Wayne Enterprises against various forms of cyberattack.

In this scenario, reports of the below graphic come in from your user community when they visit the Wayne Enterprises website, and some of the reports reference "P01s0n1vy." In case you are unaware, P01s0n1vy is an APT group that has targeted Wayne Enterprises. Your goal, as Alice, is to investigate the defacement, with an eye towards reconstructing the attack via the Lockheed Martin Kill Chain.

![Scenario 1](https://cyberdefenders.org/static/img/BOTSv1/Defacement.png)

Scenario 2 (Ransomeware):

In the second scenario, one of your users is greeted by this image on a Windows desktop that is claiming that files on the system have been encrypted and payment must be made to get the files back. It appears that a machine has been infected with Cerber ransomware at Wayne Enterprises and your goal is to investigate the ransomware with an eye towards reconstructing the attack. 

![Scenario 2](https://cyberdefenders.org/static/img/BOTSv1/ransomewere.png)

요약 : 

![록히드마틴 사이버킬체인 7단계]({{site.url}}/assets/built/images/botsv1/cyberkillchain.jpg)

101	What is the likely IP address of someone from the Po1s0n1vy group scanning imreallynotbatman.com for web application vulnerabilities?  
\(웹 애플리케이션 취약점에 대해 imreallynotbatman.com을 스캔하는 Po1s0n1vy 그룹의 누군가의 가능한 IP 주소는 무엇입니까??)
<details><summary>hint#1</summary>
Start your search with "sourcetype=stream:http" and review the rich data captured in these events.
</details>

<details>
  <summary>hint#2</summary>
You'll notice that source and destination IP addresses are stored in fields called src_ip and dest_ip respectively. Determine top-talkers for HTTP by combining : "sourcetype=stream:http | stats count by src_ip, dest_ip | sort -count" </span>
</details>
ㅇㅇ


102 What company created the web vulnerability scanner used by Po1s0n1vy? Type the company name. (For example "Microsoft" or "Oracle")  

<details>
  <summary>hint#1</summary>
</details>

```
index=botsv1 imreallynotbatman.com sourcetype=stream:http http_method=POST
```

103	What content management system is imreallynotbatman.com likely using?(Please do not include punctuation such as . , ! ? in your answer. We are looking for alpha characters only.)


<details>
  <summary>hint#1</summary>
</details>

104	What is the name of the file that defaced the imreallynotbatman.com website? Please submit only the name of the file with extension (For example "notepad.exe" or "favicon.ico")


<details>
  <summary>hint#1</summary>
</details>

<details>
  <summary>hint#2</summary>
</details>

<details>
  <summary>hint#3</summary>
</details>


105	This attack used dynamic DNS to resolve to the malicious IP. What fully qualified domain name (FQDN) is associated with this attack?

<details>
  <summary>hint#1</summary>
</details>


106	What IP address has Po1s0n1vy tied to domains that are pre-staged to attack Wayne Enterprises?

107	Based on the data gathered from this attack and common open source intelligence sources for domain names, what is the email address that is most likely associated with Po1s0n1vy APT group?

108	What IP address is likely attempting a brute force password attack against imreallynotbatman.com?

109	What is the name of the executable uploaded by Po1s0n1vy? Please include file extension. (For example, "notepad.exe" or "favicon.ico")

110	What is the MD5 hash of the executable uploaded?

111	GCPD reported that common TTPs (Tactics, Techniques, Procedures) for the Po1s0n1vy APT group, if initial compromise fails, is to send a spear phishing email with custom malware attached to their intended target. This malware is usually connected to Po1s0n1vys initial attack infrastructure. Using research techniques, provide the SHA256 hash of this malware.

112	What special hex code is associated with the customized malware discussed in question 111? (Hint: It's not in Splunk)

113	One of Po1s0n1vy's staged domains has some disjointed "unique" whois information. Concatenate the two codes together and submit as a single answer.

114	What was the first brute force password used?

115	One of the passwords in the brute force attack is James Brodsky's favorite Coldplay song. Hint: we are looking for a six character word on this one. Which is it?

116	What was the correct password for admin access to the content management system running "imreallynotbatman.com"?

117	What was the average password length used in the password brute forcing attempt? (Round to closest whole integer. For example "5" not "5.23213")

118	How many seconds elapsed between the time the brute force password scan identified the correct password and the compromised login? Round to 2 decimal places.

119	How many unique passwords were attempted in the brute force attempt?

200	What was the most likely IP address of we8105desk on 24AUG2016?

201	Amongst the Suricata signatures that detected the Cerber malware, which one alerted the fewest number of times? Submit ONLY the signature ID value as the answer. (No punctuation, just 7 integers.)

202	What fully qualified domain name (FQDN) does the Cerber ransomware attempt to direct the user to at the end of its encryption phase?

203	What was the first suspicious domain visited by we8105desk on 24AUG2016?

204	During the initial Cerber infection a VB script is run. The entire script from this execution, pre-pended by the name of the launching .exe, can be found in a field in Splunk. What is the length in characters of the value of this field?

205	What is the name of the USB key inserted by Bob Smith?

206	Bob Smith's workstation (we8105desk) was connected to a file server during the ransomware outbreak. What is the IP address of the file server?

207	How many distinct PDFs did the ransomware encrypt on the remote file server?

208	The VBscript found in question 204 launches 121214.tmp. What is the ParentProcessId of this initial launch?

209	The Cerber ransomware encrypts files located in Bob Smith's Windows profile. How many .txt files does it encrypt?

210	The malware downloads a file that contains the Cerber ransomware cryptor code. What is the name of that file?

211	Now that you know the name of the ransomware's encryptor file, what obfuscation technique does it likely use?