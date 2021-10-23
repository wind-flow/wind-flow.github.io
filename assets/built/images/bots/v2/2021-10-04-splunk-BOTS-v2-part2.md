---
layout: post
current: post
cover:  assets/built/images/bots/v2/bots-v2.jpg
navigation: True
title: splunk-bots-v2 write up(2)
date: '2021-10-04 20:04:36 +0530'
tags: [splunk]
class: post-template
subclass: 'post tag-splunk'
author: wind-flow
---
{% include bots-table-of-contents.html %}

APT Scenarios:

In this hands-on exercise, you assume the persona of Alice Bluebird, the analyst who successfully assisted Wayne Enterprises and was recommended to Grace Hoppy at Frothly to assist them with their recent issues.  
이 실습에서는 Wayne Enterprises를 성공적으로 지원하고 Frothly의 Grace Hoppy에게 최근 문제를 지원하도록 추천된 분석가 Alice Bluebird의 페르소나를 가정합니다.

Hunting Scenarios:

PowerShell: Adversaries will use PowerShell Empire to establish a foothold and carry out attacks.  
PowerShell: 적들은 PowerShell Empire를 사용하여 거점을 구축하고 공격을 수행합니다.  
Exfiltration Over Alternative Protocol - FTP: Data Exfiltration may occur using common network protocols, principally FTP  
Exfiltration Over Alternative Protocol - FTP: 데이터 유출은 주로 FTP와 같은 일반적인 네트워크 프로토콜을 사용하여 발생할 수 있습니다.  
Exfiltration Over Alternative Protocol - DNS: Data Exfiltration may occur using common network protocols, specifically DNS  
Exfiltration Over Alternative Protocol - DNS: 데이터 유출은 일반적인 네트워크 프로토콜, 특히 DNS를 사용하여 발생할 수 있습니다.  
Adversary Infrastructure: The adversary has established multiple components of infrastructure beyond what we have already uncovered.  
Adversary Infrastructure: 적군은 우리가 이미 밝혀낸 것 이상의 기반 시설의 여러 구성 요소를 구축했습니다.  
Spearphishing Attachment: Adversaries will attempt to establish a foothold within Froth.ly using Phishing.  
Spearphishing Attachment: 적들은 피싱을 사용하여 Froth.ly 내에 거점을 구축하려고 시도합니다.  
User Execution: Adversaries will attempt to establish a foothold within Froth.ly by enticing a user to execute an action on a file.  
User Execution: 공격자는 사용자가 파일에 대해 작업을 실행하도록 유인하여 Froth.ly 내에서 거점을 설정하려고 시도합니다.  
Persistence - Create Account: An adversary will look to maintain persistence across an enterprise by creating user accounts.  
Persistence - Create Account: 공격자는 사용자 계정을 생성하여 기업 전체에서 지속성을 유지하려고 합니다.  
Persistence - Scheduled Task: An adversary will look to maintain persistence across reboots by using a task scheduler.  
Persistence - Scheduled Task: 공격자는 작업 스케줄러를 사용하여 재부팅 시 지속성을 유지하려고 합니다.  
Indicator Removal On Host: Clearing of audit / event logs could indicate an adversary attempting to cover their tracks.  
Indicator Removal On Host: 감사/이벤트 로그를 지우면 공격자가 자신의 흔적을 덮으려는 것을 나타낼 수 있습니다.  
Reconaissance: User Agent Strings may provide insight into an adversary that they may not have intended to show.  
Reconaissance: 사용자 에이전트 문자열은 의도하지 않은 적에 대한 통찰력을 제공할 수 있습니다.
OSINT: Identifying publicly available company information and who is accessing it may provide insight into the adversary.  
OSINT: 공개적으로 사용 가능한 회사 정보와 해당 정보에 액세스하는 사람을 식별하면 적에 대한 통찰력을 제공할 수 있습니다.  
Lateral Movement: Adversaries will look to move laterally to other systems using Windows Management Instrumentation (WMI).  
Lateral Movement: 공격자는 WMI(Windows Management Instrumentation)를 사용하여 측면으로 다른 시스템으로 이동합니다.  
Data Staging: Adversaries will stage data prior to exfiltration to make it easier to extract data at a time of their choosing as well as have a central place to place information as it is identified.  
Data Staging: 공격자는 데이터 유출 전에 데이터를 준비하여 원하는 시간에 데이터를 쉽게 추출할 수 있을 뿐만 아니라 식별된 정보를 배치할 중앙 위치를 확보합니다.  


![Scenario 1]({{site.url}}/assets/built/images/bots/v2/b21.jpg)

The data included in this app was generated in August of 2017 by members of Splunk's Security Specialist team - Dave Herrald, Ryan Kovar, Steve Brant, Jim Apger, John Stoner, Ken Westin, David Veuve and James Brodsky. They stood up a few lab environments connected to the Internet. Within the environment they had a few Windows endpoints instrumented with the Splunk Universal Forwarder and Splunk Stream. The forwarders were configured with best practices for Windows endpoint monitoring, including a full Microsoft Sysmon deployment and best practices for Windows Event logging. The environment included a Palo Alto Networks next-generation firewall to capture traffic and provide web proxy services, and Suricata to provide network-based IDS. This resulted in the dataset below.  
이 앱에 포함된 데이터는 2017년 8월 Splunk의 보안 전문가 팀(Dave Herrald, Ryan Kovar, Steve Brant, Jim Apger, John Stoner, Ken Westin, David Veuve 및 James Brodsky)이 생성한 것입니다. 그들은 인터넷에 연결된 몇 개의 실험 환경을 구축했습니다. 환경 내에는 Splunk Universal Forwarder 및 Splunk Stream으로 계측된 몇 개의 Windows 엔드포인트가 있었습니다. Forwarder는 전체 Microsoft Sysmon 배포 및 Windows 이벤트 로깅을 위한 모범 사례를 포함하여 Windows endpoint 모니터링을 위한 모범 사례로 구성되었습니다. 이 데이터셋은 트래픽을 캡처하고 웹 프록시 서비스를 제공하는 Palo Alto Networks 차세대 방화벽과 네트워크 기반 IDS를 제공하는 Suricata가 포함되었습니다. 그 결과 아래 데이터세트가 생성되었습니다.

![Scenario 2]({{site.url}}/assets/built/images/bots/v2/b22.jpg)

200	What is the public IPv4 address of the server running www.brewertalk.com?  
www.brewertalk.com의 공개 IPv4 주소는 무엇입니까?

<details>
  <summary>hint#1</summary>
  Do you have access to a network diagram? If you do, use it!
  네트워크 다이어그램에 액세스할 수 있습니까? 있으면, 사용하세요!
</details>

<details>
  <summary>hint#2</summary>
  A Splunk Stream forwarder running in the Frothly on-prem environment would observe http traffic destined for www.brewertalk.com as having an internet routable IP address.<br>
  Frothly 온프레미스 환경에서 실행되는 Splunk Stream forwarder는 www.brewertalk.com으로 향하는 http 트래픽이 인터넷 라우팅 가능한 IP 주소를 갖는 것으로 관찰합니다.
</details>

stream:http에서 해당 URL로 검색한 후, dest_ip필드에서 찾을 가능성이 높습니다.
```
sourcetype=stream:http www.brewertalk.com
| dedup site dest_ip
| table site dest_ip
```


site|	dest_ip|
|---|---|
|www.brewertalk.com|172.31.4.249|
|www.brewertalk.com|52.42.208.228|
|ec2-52-40-10-231.us-west-2.compute.amazonaws.com:8088|172.31.10.10|
|ec2-52-40-10-231.us-west-2.compute.amazonaws.com:8088|52.40.10.231|
|45.77.65.211:9999|45.77.65.211|
|brewertalk.com|172.31.4.249|

www.brewertalk.com의 dest_ip의 값을 보면 172.31.4.249와 52.42.208.228이 있습니다.
문제에서 공개IP를 물어봤으니 사설IP대역은 172.31.4.249이 아닌, 52.42.208.228이 공개 IP입니다.

답 : 52.42.208.228

201	Provide the IP address of the system used to run a web vulnerability scan against www.brewertalk.com.  
www.brewertalk.com에 대해 웹 취약점 스캔을 실행하는 데 사용되는 시스템의 IP 주소를 제공하십시오.

<details>
  <summary>hint#1</summary>
  App scanners are often 'noisy' and therefore easy to detect with automated correlation searches.<br>
  앱 스캐너는 '잡음'일 경우가 많기 때문에 자동화된 상관 관계 검색으로 쉽게 감지할 수 있습니다.
</details>

<details>
  <summary>hint#2</summary>
  Drill down into contributing events if you can!<br>
  가능하면 기여 이벤트를 자세히 살펴보십시오!
</details>

scan이면 request 횟수가 많을것입니다.

www.berkbeer.com의 ip(52.42.208.228, 172.31.4.249)를 dest_ip로 설정하고 count해봅시다.
그리고, header에 

쿼리결과를 토대로 검증해봅니다.(스캔치고 이벤트 수가 적습니다.)

```
sourcetype=stream:http dest_ip=52.42.208.228 OR dest_ip=172.31.4.249
| stats count by src_ip dest_ip
| sort -count
```

|src_ip	dest_ip	count
|45.77.65.211|172.31.4.249|9708|
|52.40.10.231|172.31.4.249|634|
|172.31.10.10|52.42.208.228|303|
|71.39.18.125|172.31.4.249|160|
|174.209.13.154|172.31.4.249|134|
|10.0.2.109|52.42.208.228|84|
|136.0.2.138|172.31.4.249|24|
|136.0.0.125|172.31.4.249|8|

답 : 45.77.65.211

202	The IP address from question 201 is also being used by a likely different piece of software to attack a URI path. What is the URI path? Answer guidance: Include the leading forward slash in your answer. Do not include the query string or other parts of the URI. Answer example: /phpinfo.php  
201번 문제의 IP 주소는 URI 경로를 공격하기 위해 다른 소프트웨어에서도 사용되고 있습니다. URI 경로는 무엇입니까? 답변 안내: 답변에 선행 슬래시를 포함하십시오. 쿼리 문자열이나 URI의 다른 부분을 포함하지 마십시오. 답변 예시: /phpinfo.php
<details>
  <summary>hint#1</summary>
  Analyze all HTTP traffic from the scanning system to www.brewertalk.com, and inspect the different HTTP user agents. A different HTTP user agent often indicates a different HTTP client program was in use.<br>
  스캐닝 시스템에서 www.brewertalk.com으로의 모든 HTTP 트래픽을 분석하고 다양한 HTTP 사용자 에이전트를 검사합니다. 다른 HTTP 사용자 에이전트는 종종 다른 HTTP 클라이언트 프로그램이 사용 중임을 나타냅니다.
</details>

203	What SQL function is being abused on the uri path from question 202?

<details>
  <summary>hint#1</summary>

</details>

204	What is Frank Ester's password salt value on www.brewertalk.com?

<details>
  <summary>hint#1</summary>

</details>

205	What is user btun's password on brewertalk.com?

<details>
  <summary>hint#1</summary>

</details>

206	What are the characters displayed by the XSS probe? Answer guidance: Submit answer in native language or character set.

<details>
  <summary>hint#1</summary>

</details>

207	What was the value of the cookie that Kevin's browser transmitted to the malicious URL as part of a XSS attack? Answer guidance: All digits. Not the cookie name or symbols like an equal sign.

<details>
  <summary>hint#1</summary>

</details>

208	The brewertalk.com web site employed Cross Site Request Forgery (CSRF) techniques. What was the value of the anti-CSRF token that was stolen from Kevin Lagerfield's computer and used to help create an unauthorized admin user on brewertalk.com?

<details>
  <summary>hint#1</summary>

</details>

209	What brewertalk.com username was maliciously created by a spearphishing attack?

<details>
  <summary>hint#1</summary>

</details>

300	According to Frothly's records, what is the likely MAC address of Mallory's corporate MacBook? Answer guidance: Her corporate MacBook has the hostname MACLORY-AIR13.

<details>
  <summary>hint#1</summary>

</details>

301	What episode of Game of Thrones is Mallory excited to watch? Answer guidance: Submit the HBO title of the episode.

<details>
  <summary>hint#1</summary>

</details>

302	What is Mallory Krauesen's phone number? Answer guidance: ddd-ddd-dddd where d=[0-9]. No country code.

<details>
  <summary>hint#1</summary>

</details>

303	Enterprise Security contains a threat list notable event for MACLORY-AIR13 and suspect IP address 5.39.93.112. What is the name of the threatlist (i.e. Threat Group) that is triggering the notable?

<details>
  <summary>hint#1</summary>

</details>

304	Considering the threatlist you found in the question above, and related data, what protocol often used for file transfer is actually responsible for the generated traffic?

<details>
  <summary>hint#1</summary>

</details>

305	Mallory's critical PowerPoint presentation on her MacBook gets encrypted by ransomware on August 18. At what hour, minute, and second does this actually happen? Answer guidance: Provide the time in PDT. Use the 24h format HH:MM:SS, using leading zeroes if needed. Do not use Splunk's _time (index time).

<details>
  <summary>hint#1</summary>

</details>

~~~
PDT(Pacific Daylight Time)
출처 : https://luran.me/339
~~~

306	How many seconds elapsed between the time the ransomware executable was written to disk on MACLORY-AIR13 and the first local file encryption? Answer guidance: Use the index times (_time) instead of other timestamps in the events.

<details>
  <summary>hint#1</summary>

</details>

307	Kevin Lagerfield used a USB drive to move malware onto kutekitten, Mallory's personal MacBook. She ran the malware, which obfuscates itself during execution. Provide the vendor name of the USB drive Kevin likely used. Answer Guidance: Use time correlation to identify the USB drive.

<details>
  <summary>hint#1</summary>

</details>

308	What programming language is at least part of the malware from the question above written in?

<details>
  <summary>hint#1</summary>

</details>

309	The malware from the two questions above appears as a specific process name in the process table when it is running. What is it?

<details>
  <summary>hint#1</summary>

</details>

310	The malware infecting kutekitten uses dynamic DNS destinations to communicate with two C&C servers shortly after installation. What is the fully-qualified domain name (FQDN) of the first (alphabetically) of these destinations?

<details>
  <summary>hint#1</summary>

</details>

311	From the question above, what is the fully-qualified domain name (FQDN) of the second (alphabetically) contacted C&C server?

<details>
  <summary>hint#1</summary>

</details>

312	What is the average Alexa 1M rank of the domains between August 18 and August 19 that MACLORY-AIR13 tries to resolve while connected via VPN to the corporate network? Answer guidance: Round to two decimal places. Remember to include domains with no rank in your average! Answer example: 3.23 or 223234.91

<details>
  <summary>hint#1</summary>

</details>


313	Two .jpg-formatted photos of Mallory exist in Kevin Lagerfield's server home directory that have eight-character file names, not counting the .jpg extension. Both photos were encrypted by the ransomware. One of the photos can be downloaded at the following link, replacing 8CHARACTERS with the eight characters from the file name. https://splunk.box.com/v/8CHARACTERS After you download the file to your computer, decrypt the file using the encryption key used by the ransomware. What is the complete line of text in the photo, including any punctuation? Answer guidance: The encryption key can be found in Splunk.

<details>
  <summary>hint#1</summary>

</details>

400	A Federal law enforcement agency reports that Taedonggang often spearphishes its victims with zip files that have to be opened with a password. What is the name of the attachment sent to Frothly by a malicious Taedonggang actor?

<details>
  <summary>hint#1</summary>

</details>

401	The Taedonggang APT group encrypts most of their traffic with SSL. What is the "SSL Issuer" that they use for the majority of their traffic? Answer guidance: Copy the field exactly, including spaces.

<details>
  <summary>hint#1</summary>

</details>

402	Threat indicators for a specific file triggered notable events on two distinct workstations. What IP address did both workstations have a connection with?

<details>
  <summary>hint#1</summary>

</details>

403	Based on the IP address found in question 402, what domain of interest is associated with that IP address?

<details>
  <summary>hint#1</summary>

</details>

404	What unusual file (for an American company) does winsys32.dll cause to be downloaded into the Frothly environment?

<details>
  <summary>hint#1</summary>

</details>

405	What is the first and last name of the poor innocent sap who was implicated in the metadata of the file that executed PowerShell Empire on the first victim's workstation? Answer example: John Smith

<details>
  <summary>hint#1</summary>

</details>

406	What is the average Shannon entropy score of the subdomain containing UDP-exfiltrated data? Answer guidance: Cut off, not rounded, to the first decimal place. Answer examples: 3.2 or 223234.9

<details>
  <summary>hint#1</summary>

</details>


407	To maintain persistence in the Frothly network, Taedonggang APT configured several Scheduled Tasks to beacon back to their C2 server. What single webpage is most contacted by these Scheduled Tasks? Answer guidance: Remove the path and type a single value with an extension. Answer example: index.php or images.html

<details>
  <summary>hint#1</summary>

</details>

408	The APT group Taedonggang is always building more infrastructure to attack future victims. Provide the IPV4 IP address of a Taedonggang controlled server that has a completely different first octet to other Taedonggang controlled infrastructure. Answer guidance: 4.4.4.4 has a different first octet than 8.4.4.4

<details>
  <summary>hint#1</summary>

</details>

409	The Taedonggang group had several issues exfiltrating data. Determine how many bytes were successfully transferred in their final, mostly successful attempt to exfiltrate files via a method using TCP, using only the data available in Splunk logs. Use 1024 for byte conversion.

<details>
  <summary>hint#1</summary>

</details>

500	Individual clicks made by a user when interacting with a website are associated with each other using session identifiers. You can find session identifiers in the stream:http sourcetype. The Frothly store website session identifier is found in one of the stream:http fields and does not change throughout the user session. What session identifier is assigned to dberry398@mail.com when visiting the Frothly store for the very first time? Answer guidance: Provide the value of the field, not the field name.

<details>
  <summary>hint#1</summary>

</details>

501	How many unique user ids are associated with a grand total order of $1000 or more?

<details>
  <summary>hint#1</summary>

</details>

502	Which user, identified by their email address, edited their profile before placing an order over $1000 in the same clickstream? Answer guidance: Provide the user ID, not other values found from the profile edit, such as name.

<details>
  <summary>hint#1</summary>

</details>

503	What street address was used most often as the shipping address across multiple accounts, when the billing address does not match the shipping address? Answer example: 123 Sesame St

<details>
  <summary>hint#1</summary>

</details>

504	What is the domain name used in email addresses by someone creating multiple accounts on the Frothly store website (http://store.froth.ly) that appear to have machine-generated usernames?

<details>
  <summary>hint#1</summary>

</details>

505	Which user ID experienced the most logins to their account from different IP address and user agent combinations? Answer guidance: The user ID is an email address.

<details>
  <summary>hint#1</summary>

</details>

506	What is the most popular coupon code being used successfully on the site?

<details>
  <summary>hint#1</summary>

</details>

507	Several user accounts sharing a common password is usually a precursor to undesirable scenario orchestrated by a fraudster. Which password is being seen most often across users logging into http://store.froth.ly.

<details>
  <summary>hint#1</summary>

</details>

508	Which HTML page was most clicked by users before landing on http://store.froth.ly/magento2/checkout/ on August 19th? Answer guidance: Use earliest=1503126000 and latest=1503212400 to identify August 19th. Answer example: http://store.froth.ly/magento2/bigbrew.html

<details>
  <summary>hint#1</summary>

</details>

509	Which HTTP user agent is associated with a fraudster who appears to be gaming the site by unsuccessfully testing multiple coupon codes?

<details>
  <summary>hint#1</summary>

</details>