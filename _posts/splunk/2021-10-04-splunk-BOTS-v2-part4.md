---
layout: post
current: post
cover:  assets/built/images/bots/v2/bots-v2.jpg
navigation: True
title: splunk-bots-v2 write up(4)
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

400	A Federal law enforcement agency reports that Taedonggang often spearphishes its victims with zip files that have to be opened with a password. What is the name of the attachment sent to Frothly by a malicious Taedonggang actor?  
연방 법 집행 기관은 대동강이 종종 비밀번호로 열어야 하는 zip 파일로 피해자를 스피어피싱한다고 보고합니다. 대동강이 Frothly에게 보낸 첨부 파일 이름은 무엇입니까?

<details>
  <summary>hint#1</summary>
    Frothly uses the Splunk wiredata product 'Stream' to collect email metadata. Look at the sourcetype stream:smtp<br>
    Frothly는 Splunk wiredata 제품 'Stream'을 사용하여 이메일 메타데이터를 수집합니다. sourcetype stream:smtp을 살펴보세요.
</details>
<details>
  <summary>hint#2</summary>
    The question mentions that Taedonggang sends a 'zip' file. Look in the sourcetype in hint 1 for attachments with a .zip extension.<br>
    질문은 대동강이 'zip' 파일을 보낸다고 언급합니다. .zip 확장자를 가진 첨부 파일에 대해서는 힌트 1의 소스 유형을 확인하십시오.
</details>

메일에 있는 확장자.zip의 첨부파일명을 확인해봅시다. 

```
sourcetype=stream:smtp *.zip*
```

invoice.zip 한가지 결과만 나옵니다.
![]({{site.url}}/assets/built/images/bots/v2/2021-10-27-17-24-28.png)

뒷문제를 풀기위해 필요한 정보를 파악해둡니다.

|_time|	sender|	receiver{}|	attach_filename{}|	attach_content_md5_hash{}|	received_by_name|	src_ip|
|---|---|---|---|---|---|---|
|2017/08/24 03:27:29.837|	Jim Smith <jsmith@urinalysis.com>|	<btun@froth.ly>	      | invoice.zip	| 20e368e2c9c6e91f24eeddd09369c4aa	| MWHPR18CA0034.outlook.office365.com	| 104.47.37.62
|2017/08/24 03:27:14.323|	Jim Smith <jsmith@urinalysis.com>|	<abungstein@froth.ly>	| invoice.zip	| 20e368e2c9c6e91f24eeddd09369c4aa	| CY4PR18CA0071.outlook.office365.com	| 104.47.41.43
|2017/08/24 03:27:33.239|	Jim Smith <jsmith@urinalysis.com>|	<fyodor@froth.ly>	    | invoice.zip	| 20e368e2c9c6e91f24eeddd09369c4aa	| BY1PR18CA0020.outlook.office365.com	| 104.47.38.87
|2017/08/24 03:27:24.557|	Jim Smith <jsmith@urinalysis.com>|	<klagerfield@froth.ly>|	invoice.zip	| 20e368e2c9c6e91f24eeddd09369c4aa	| CY4PR18CA0058.outlook.office365.com	| 104.47.42.76

답 : invoice.zip

401	The Taedonggang APT group encrypts most of their traffic with SSL. What is the "SSL Issuer" that they use for the majority of their traffic? Answer guidance: Copy the field exactly, including spaces.  
대동강 APT 그룹은 대부분의 트래픽을 SSL로 암호화합니다. 대부분의 트래픽에 사용하는 "SSL 발급자"는 무엇입니까? 답변 지침: 공백을 포함하여 필드를 정확하게 복사합니다.

<details>
  <summary>hint#1</summary>
    You might need to get more information before you tackle this question. Have you figured out the IP address of Taedonggang's server?<br>
    이 질문을 다루기 전에 더 많은 정보를 얻어야 할 수도 있습니다. 대동강 서버의 IP 주소를 알아내셨나요?
</details>
<details>
  <summary>hint#2</summary> 
    Frothly currently only collects SSL data with Stream. Look at the sourcetype 'stream:TCP' for more information about SSL data.<br>
    Frothly는 현재 Stream으로 SSL 데이터만 수집합니다. SSL 데이터에 대한 자세한 내용은 소스 유형 'stream:TCP'를 확인하세요.
</details>
<details>
  <summary>hint#3</summary>
    Issuer' is a value found in a TLS/SSL certificate. Try and find SSL/TLS certificates tied to the IP address of Taedonggang's attacking server.<br>
    Issuer'는 TLS/SSL 인증서에 있는 값입니다. 대동강 공격 서버의 IP 주소에 연결된 SSL/TLS 인증서를 찾아보십시오.
</details>
<details>
  <summary>hint#4</summary>
    Look in sourcetype=stream:tcp with the IP address of Taedonggang and the field ssl_issuer.<br>
    대동강의 IP 주소와 ssl_issuer 필드가 있는 sourcetype=stream:tcp를 찾습니다.
</details>

SSL관련 데이터는 stream:tcp에 있을것입니다. 키워드 ssl을 넣고 검색해봅니다.
```
sourcetype=stream:tcp *ssl*
```


402	Threat indicators for a specific file triggered notable events on two distinct workstations. What IP address did both workstations have a connection with?  
특정 파일에 대한 위협 표시기는 두 개의 개별 워크스테이션에서 주목할만한 이벤트를 트리거했습니다. 두 워크스테이션이 연결된 IP 주소는 무엇입니까?

<details>
  <summary>hint#1</summary>
    Check out the Incident Review dashboard.<br>
    Incident Review dashboard를 확인하십시오.
</details>
<details>
  <summary>hint#2</summary>
    Open notable events for more details.<br>
    자세한 내용은 주목할만한 이벤트를 엽니다.
</details>
<details>
  <summary>hint#3</summary>
    Look for two notable events with the exact same title that has a filename in it.<br>
    파일 이름이 있는 정확히 동일한 제목을 가진 두 개의 주목할만한 이벤트를 찾으십시오.
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