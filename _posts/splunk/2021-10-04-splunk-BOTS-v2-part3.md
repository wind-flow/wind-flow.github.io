---
layout: post
current: post
cover:  assets/built/images/splunk/bots/v2/bots-v2.jpg
navigation: True
title: splunk-bots-v2 write up(3)
date: '2021-10-04 20:04:36 +0900'
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


![Scenario 1]({{site.url}}/assets/built/images/splunk/bots/v2/b21.jpg)

The data included in this app was generated in August of 2017 by members of Splunk's Security Specialist team - Dave Herrald, Ryan Kovar, Steve Brant, Jim Apger, John Stoner, Ken Westin, David Veuve and James Brodsky. They stood up a few lab environments connected to the Internet. Within the environment they had a few Windows endpoints instrumented with the Splunk Universal Forwarder and Splunk Stream. The forwarders were configured with best practices for Windows endpoint monitoring, including a full Microsoft Sysmon deployment and best practices for Windows Event logging. The environment included a Palo Alto Networks next-generation firewall to capture traffic and provide web proxy services, and Suricata to provide network-based IDS. This resulted in the dataset below.  
이 앱에 포함된 데이터는 2017년 8월 Splunk의 보안 전문가 팀(Dave Herrald, Ryan Kovar, Steve Brant, Jim Apger, John Stoner, Ken Westin, David Veuve 및 James Brodsky)이 생성한 것입니다. 그들은 인터넷에 연결된 몇 개의 실험 환경을 구축했습니다. 환경 내에는 Splunk Universal Forwarder 및 Splunk Stream으로 계측된 몇 개의 Windows 엔드포인트가 있었습니다. Forwarder는 전체 Microsoft Sysmon 배포 및 Windows 이벤트 로깅을 위한 모범 사례를 포함하여 Windows endpoint 모니터링을 위한 모범 사례로 구성되었습니다. 이 데이터셋은 트래픽을 캡처하고 웹 프록시 서비스를 제공하는 Palo Alto Networks 차세대 방화벽과 네트워크 기반 IDS를 제공하는 Suricata가 포함되었습니다. 그 결과 아래 데이터세트가 생성되었습니다.

![Scenario 2]({{site.url}}/assets/built/images/splunk/bots/v2/b22.jpg)

300	According to Frothly's records, what is the likely MAC address of Mallory's corporate MacBook? Answer guidance: Her corporate MacBook has the hostname MACLORY-AIR13.  
Frothly의 기록에 따르면 Mallory의 회사 MacBook의 MAC 주소는 무엇입니까? 답변 안내: 그녀의 회사 MacBook의 호스트 이름은 MACLORY-AIR13입니다.

<details>
  <summary>hint#1</summary>
    Use Asset Center in ES.<br>
</details>

해당 문제는 현 실습 환경에서 제공되지 않는 Splunk ES에서 확인할 수 있는것으로 문제풀이는 하지않겠습니다.

301	What episode of Game of Thrones is Mallory excited to watch? Answer guidance: Submit the HBO title of the episode.
말로리는 왕좌의 게임의 어떤 에피소드를 보고 싶어 할까요? 답변 안내: 에피소드의 HBO 제목을 제출하세요.  

<details>
  <summary>hint#1</summary>
    Look for video files downloaded to MACLORY-AIR13.<br>
    MACLORY-AIR13에 다운로드된 비디오 파일을 찾습니다.
</details>

host가 MACLORY-AIR13인 데이터 중에서 game of thrones, got 등의 키워드로 찾아봅시다.

```
host=MACLORY-AIR13 "*game of thrones*" OR "got"
```

- 결과  
![]({{site.url}}/assets/built/images/splunk/bots/v2/2021-10-26-15-24-33.png)

target_path필드 값은 다음과 같습니다.  
**/Users/mallorykraeusen/Downloads/GoT.S7E2.BOTS.BOTS.BOTS.mkv.torrent.**

시즌7의 2화의 제목은 Stormborn입니다.

![]({{site.url}}/assets/built/images/splunk/bots/v2/2021-10-26-15-27-50.png)

답 : Stormborn

302	What is Mallory Krauesen's phone number? Answer guidance: ddd-ddd-dddd where d=[0-9]. No country code.  
Mallory Krauesen의 전화번호는 무엇입니까? 답변 안내: ddd-ddd-dddd 여기서 d=[0-9]. 국가 코드가 없습니다.

<details>
  <summary>hint#1</summary>
    Use Identity Center in ES.  
</details>

해당 문제는 현 실습 환경에서 제공되지 않는 Splunk ES에서 확인할 수 있는것으로 문제풀이는 하지않겠습니다.

303	Enterprise Security contains a threat list notable event for MACLORY-AIR13 and suspect IP address 5.39.93.112. What is the name of the threatlist (i.e. Threat Group) that is triggering the notable?  
Enterprise Security에는 MACLORY-AIR13 및 의심되는 IP 주소 5.39.93.112에 대한 주요 이벤트 목록이 포함되어 있습니다. 주목할 만한 것을 유발하는 위협 목록(예: 위협 그룹)의 이름은 무엇입니까?

<details>
  <summary>hint#1</summary>
    Look for threat activity from Mallory's MacBook in the Incident Review dashboard.<br>
    Incident Review 대시보드에서 Mallory의 MacBook에서 위협 활동을 찾습니다.
</details>

해당 문제는 현 실습 환경에서 제공되지 않는 Splunk ES에서 확인할 수 있는것으로 문제풀이는 하지않겠습니다.

304	Considering the threatlist you found in the question above, and related data, what protocol often used for file transfer is actually responsible for the generated traffic?  
위의 질문에서 찾은 위협 목록과 관련 데이터를 고려할 때 파일 전송에 자주 사용되는 프로토콜이 실제로 생성된 트래픽을 담당합니까?

<details>
  <summary>hint#1</summary>
    Do you see MACLORY-AIR13 communicating with known Tor addresses? That's misleading.<br>
    알려진 Tor 주소와 통신하는 MACLORY-AIR13이 보입니까? 오해의 소지가 있습니다.
</details>

위 IP에서 특이한 로그가 있는지 살펴봅시다.

```
5.39.93.112
```

sourcetype은 [pan:traffic](https://docs.paloaltonetworks.com/pan-os/8-1/pan-os-admin/monitoring/use-syslog-for-monitoring/syslog-field-descriptions/traffic-log-fields) 한가지만 있고,
app field에 bittorrent를 찾을 수 있습니다.

답 : bittorrent

305	Mallory's critical PowerPoint presentation on her MacBook gets encrypted by ransomware on August 18. At what hour, minute, and second does this actually happen? Answer guidance: Provide the time in PDT. Use the 24h format HH:MM:SS, using leading zeroes if needed. Do not use Splunk's _time (index time).  
Mallory Macbook에 있는 중요한 PowerPoint파일이 8월 18일 랜섬웨어에 의해 암호화되었습니다. 몇 시, 분, 초에 발생했습니까 ? 답변 안내: PDT로 시간을 제공합니다. 필요한 경우 선행 0을 사용하여 24시간 형식 HH:MM:SS를 사용합니다. Splunk의 _time(index time)을 사용하지 마십시오.

<details>
  <summary>hint#1</summary>
    People that work on PowerPoint presentations generally save them in their Documents folder.<br>
    PowerPoint 작업을 하는 사람들은 일반적으로 문서 폴더에 프레젠테이션을 저장합니다.
</details>

<details>
  <summary>hint#2</summary>
    The time that Splunk indexed this information might not be the time the file was modified.<br>
    Splunk가 이 정보를 인덱싱한 시간은 파일이 수정된 시간이 아닐 수 있습니다.
</details>


splunk의 _time을 사용하지말라고했으니 해당 로그에 시간과 관련된 필드가 있을것입니다.

우선 탐색 시간을 2017/08/18 00 ~ 2018/08/19 00시로 설정하고, 키워드를 다음과 같이 설정하고 조사해봅니다.

```
*mallory* (*.ppt OR *.pptx)
```

![]({{site.url}}/assets/built/images/splunk/bots/v2/2021-10-26-16-48-38.png)

target_path 필드에 crypt된 파일이 보입니다. 원본 파일 경로와 이름은 /Users/mallorykraeusen/Documents/Frothly_marketing_campaign_Q317.pptx이므로, 해당 키워드로 검색해봅시다.
또, 시간을 알아봐야하니 mac time 관련 데이터를 table 명령어를 사용해 파악해봅시다.
[MAC TIME이란?](https://itwiki.kr/w/MAC_Time)

\- Mtime(modified time) : 파일을 생성한 시간, 또는 가장 최근에 파일 내용을 바꾼 시간  
\- Atime(accessed time) : 가장 최근에 파일을 읽거나(Read) 실행(Execution)시킨 시간  
\- Ctime(changed time) : 가장 최근에 파일의 소유권, 그룹, 퍼미션 등 파일의 속성(inode 정보)이 변경된 시간  

```
sourcetype=osquery_results columns.target_path="/Users/mallorykraeusen/Documents/Frothly_marketing_campaign_Q317.pptx*"
| table _time columns.target_path columns.mtime columns.atime columns.ctime columns.time unixTime
```

[PDT(Pacific Daylight Time)란?#1](https://www.timeanddate.com/time/zones/pdt)  
[PDT(Pacific Daylight Time)란?#2](https://luran.me/339)



|_time|	columns.target_path|	columns.mtime|	columns.atime|	columns.ctime|	columns.time|	unixTime|
|---|---|---|---|---|---|---|
|2017/08/18 21:50:43|	/Users/mallorykraeusen/Documents/Frothly_marketing_campaign_Q317.pptx.crypt|	1266652800|	1503093023|	1503093022|	1503093023|	1503093043|
|2017/08/18 21:50:43|	/Users/mallorykraeusen/Documents/Frothly_marketing_campaign_Q317.pptx.crypt|	1266652800|	1503093023|	1503093022|	1503093023|	1503093043|
|2017/08/18 21:50:43|	/Users/mallorykraeusen/Documents/Frothly_marketing_campaign_Q317.pptx.crypt|	1266652800|	1503093023|	1503093022|	1503093023|	1503093043|
|2017/08/18 21:50:43|	/Users/mallorykraeusen/Documents/Frothly_marketing_campaign_Q317.pptx.crypt|	1266652800|	1503093023|	1503093022|	1503093023|	1503093043|
|2017/08/18 21:50:43|	/Users/mallorykraeusen/Documents/Frothly_marketing_campaign_Q317.pptx.crypt|	1266652800|	1503093022|	1503093022|	1503093023|	1503093043|
|2017/08/18 21:50:43|	/Users/mallorykraeusen/Documents/Frothly_marketing_campaign_Q317.pptx			 |  - | - | - | 1503093023|	1503093043|

랜섬웨어로 파일이 변경되었으면 권한이 바뀌었으므로 ctime을 기준으로 보면 될것입니다.
ctime : 1503093022

[유닉스 타임변환 사이트](https://time.is/ko/Unix_time_converter)
![]({{site.url}}/assets/built/images/splunk/bots/v2/2021-10-26-17-28-03.png)

PDT는 UTC-7과 같다고 설명되어있습니다.
![PDT Time 설명]({{site.url}}/assets/built/images/splunk/bots/v2/2021-10-26-17-44-48.png)

Sat Aug 19 2017 06:50:22 UTC+0900에서 UTC-7로 환산해보면(-16시간)
Sat Aug 18 2017 14:50:22 입니다.

답 : 14:50:22

306	How many seconds elapsed between the time the ransomware executable was written to disk on MACLORY-AIR13 and the first local file encryption? Answer guidance: Use the index times (_time) instead of other timestamps in the events.  
MACLORY-AIR13의 디스크에 랜섬웨어 실행 파일이 작성된 시간과 첫 번째 로컬 파일 암호화 사이에 몇 초가 걸렸습니까? 답변 안내: 이벤트의 다른 타임스탬프 대신 인덱스 시간(_time)을 사용하세요.

<details>
  <summary>hint#1</summary>
    What time did the 'Office 2016 Patcher.app' get added to MACLORY-AIR13's filesystem?<br>
    MACLORY-AIR13의 파일 시스템에 'Office 2016 Patcher.app'이 몇시에 추가되었나요?
</details>

<details>
  <summary>hint#2</summary>
    What time was the first file with *.crypt added to MACLORY-AIR13's filesystem?<br>
    MACLORY-AIR13의 파일 시스템에 *.crypt가 추가된 첫 번째 파일은 언제였습니까?
</details>

.crypt가 처음붙은 파일과 MAC의 실행파일 확장자인 .app간 _time의 차를 구해봅시다.

```
sourcetype=osquery_results host=MACLORY-AIR13 columns.target_path=*.app
| reverse
| table _time columns.target_path
| head 1 ```로컬실행파일
| append 
    [ search sourcetype=osquery_results host=MACLORY-AIR13 columns.target_path=*.crypt
| reverse
| table _time columns.target_path
| head 1```첫 암호화된 로컬 파일]
| transaction maxevents=2
| table columns.target_path duration eventcount
```
※ [transaction](https://docs.splunk.com/Documentation/Splunk/8.2.2/SearchReference/Transaction)함수는 이벤트간 시간차이를 duration이라는 변수를 통해 계산해주는 함수입니다.  

|columns.target_path|duration|eventcount|
|---|:---:|:---:|
|/Users/mallorykraeusen/Desktop/.DS_Store.crypt<br>/Users/mallorykraeusen/Downloads/Office 2016 Patcher.app|132|2|

답 : 132

307	Kevin Lagerfield used a USB drive to move malware onto kutekitten, Mallory's personal MacBook. She ran the malware, which obfuscates itself during execution. Provide the vendor name of the USB drive Kevin likely used. Answer Guidance: Use time correlation to identify the USB drive.  
Kevin Lagerfield는 USB 드라이브를 사용하여 Mallory의 개인 MacBook인 kutekitten에 멀웨어를 옮겼습니다. 그녀는 실행 중에 스스로를 난독화하는 맬웨어를 실행했습니다. Kevin이 사용했을 가능성이 있는 USB 드라이브의 공급업체 이름을 제공합니다. 답변 지침: 시간 상관 관계를 사용하여 USB 드라이브를 식별합니다.
<details>
  <summary>hint#1</summary>
    osquery_results is a great sourcetype to review.<br>
    osquery_results에서 찾아보세요.
</details>
<details>
  <summary>hint#2</summary>
    Look for unusual files in a place that Mallory would come across them.<br>
    Mallory가 발견할 수 있는 장소에서 특이한 파일을 찾으십시오.
</details>
<details>
  <summary>hint#3</summary>
    If you can figure out what kind of malware this is, do some open source intelligence research to determine how it behaves. Find an online database of USB vendors.<br>이것이 어떤 종류의 맬웨어인지 알아낼 수 있다면 오픈 소스 인텔리전스 연구를 수행하여 작동 방식을 확인하십시오. USB 공급업체의 온라인 데이터베이스를 찾으십시오.
</details>
<details>
  <summary>hint#4</summary>
    Various sourcetypes can tell you how things look when the run. Look at 'ps' and look at 'osquery_results' from kutekitten.<br>
    다양한 소스 유형은 실행될 때 상황이 어떻게 보이는지 알려줄 수 있습니다. kutekitten의 'ps'와 'osquery_results'를 보세요.    
</details>

해당 정보는 osquery관련 sourcetype에 있을것으로 추측됩니다. [osquery](https://github.com/osquery/osquery)는 실행중인 프로세스, 네트워크, 하드웨어 이벤트 등을 포함한 OS의 정보를 쿼리형식으로 질의하여 얻은 값을 갖고 있습니다.  

MACBook의 이름인 kutekitten, 그리고 usb를 키워드로 두고, osquery_result에서 조사해봅시다.

```
sourcetype=osquery_results *kutekitten* *usb*
```

columns.vendor_id라는 필드를 보면 058f, 13fe라는 값이 있습니다.
columns.vendor_id이 있고, USB를 삽입한 데이터만 보도록 합시다.
![]({{site.url}}/assets/built/images/splunk/bots/v2/2021-10-27-13-49-54.png)


```
sourcetype=osquery_results *kutekitten* *usb* columns.vendor_id=* action=added
```

이벤트 2개가 있습니다. 각 이벤트에 대해 탐색기간을 ±60초로 설정해두고, 어떤 파일을 반입했는지 확인해봅시다.
첫번째로 vendor_id가 058f인 이벤트의 ±60초로 두고 반입된 파일의 hash값을 찾아봅시다.

```
sourcetype=osquery_results *kutekitten*
```

![]({{site.url}}/assets/built/images/splunk/bots/v2/2021-10-27-14-34-51.png)

columns.sha256의 hash값을 virustotal에서 조회해봅시다.
![sha256]({{site.url}}/assets/built/images/splunk/bots/v2/2021-10-27-14-34-11.png)
sha256 : befa9bfe488244c64db096522b4fad73fc01ea8c4cd0323f1cbdee81ba008271

MAC BackDoor 악성코드입니다.
![]({{site.url}}/assets/built/images/splunk/bots/v2/2021-10-27-14-40-12.png)

제조사 13fe의 이벤트도 추가 조사해봅니다.

columns.device의 값이 devfs인것을 보아하니, 파일이 아닌 드라이브임을 알 수 있습니다.
![]({{site.url}}/assets/built/images/splunk/bots/v2/2021-10-27-14-47-18.png)

악성코드를 반입한 USB의 제조사의 ID는 058f입니다. 구글에 해당 제조사의 ID를 검색해봅니다.

![]({{site.url}}/assets/built/images/splunk/bots/v2/2021-10-27-14-47-46.png)
vendorid 058f는 **Alcor Micro Corp.** 입니다.

답 : Alcor

308	What programming language is at least part of the malware from the question above written in?  
위의 질문에서 악성 코드의 일부인 프로그래밍 언어는 무엇입니까?

<details>
  <summary>hint#1</summary>
    Review the hints for question 307.<br>
    문제 307에 대한 힌트를 검토하세요.
</details>

문제 307번에서 발견한 악성코드의 sha256 해쉬값은 **befa9bfe488244c64db096522b4fad73fc01ea8c4cd0323f1cbdee81ba008271**입니다.
해당 hash값으로 virustotal에서  자세한 정보를 파악해봅시다.

![]({{site.url}}/assets/built/images/splunk/bots/v2/2021-10-27-15-39-44.png)
Virustotal의 Detail탭의 FileType을 보면 Perl로 작성된 언어임을 알 수 있습니다.

답 : Perl

309	The malware from the two questions above appears as a specific process name in the process table when it is running. What is it?  
위의 두 질문에 대한 맬웨어는 실행 중일 때 프로세스 테이블에 특정 프로세스 이름으로 나타납니다. 그것은 무엇입니까?

<details>
  <summary>hint#1</summary>
    Review the hints for question 307.
</details>

접근방식을 모르겠으니, 아시는분은 제보바랍니다.
답 : java

310	The malware infecting kutekitten uses dynamic DNS destinations to communicate with two C&C servers shortly after installation. What is the fully-qualified domain name (FQDN) of the first (alphabetically) of these destinations?  
kutekitten을 감염시키는 악성코드는 설치 직후 2개의 C&C 서버와 통신하기 위해 동적 DNS 대상을 사용합니다. 이러한 대상 중 첫 번째(알파벳 순)의 정규화된 도메인 이름(FQDN)은 무엇입니까?

<details>
  <summary>hint#1</summary>
    Have a look at the stream:dns sourcetype and observe queries from kutekitten.<br>
    stream:dns와 kutekitten이 요청한 쿼리를 보세요.
</details>
<details>
  <summary>hint#2</summary>
    You need a lookup. Find one, and also review this: https://www.splunk.com/blog/2015/08/04/detecting-dynamic-dns-domains-in-splunk.html<br>
    lookup이 필요합니다. https://www.splunk.com/blog/2015/08/04/detecting-dynamic-dns-domains-in-splunk.html를 참고하세요
</details>

virustotal의 Realtions 탭을 보면, **eidk.duckdns.org, eidk.hopto.org** 두개 url이 악성으로 발견되어있습니다.
![]({{site.url}}/assets/built/images/splunk/bots/v2/2021-10-27-16-55-36.png)

철자 순서에 의해 답은 eidk.duckdns.org입니다.

답 : eidk.duckdns.org

311	From the question above, what is the fully-qualified domain name (FQDN) of the second (alphabetically) contacted C&C server?  
위의 질문에서 두 번째(알파벳순)로 연결된 C&C 서버의 FQDN(정규화된 도메인 이름)은 무엇입니까?  

<details>
  <summary>hint#1</summary>
    Review the hints for question 310.
    문제 310에 대한 힌트를 검토하세요.
</details>

답은 eidk.hopto.org 입니다.

답 :  eidk.hopto.org

312	What is the average Alexa 1M rank of the domains between August 18 and August 19 that MACLORY-AIR13 tries to resolve while connected via VPN to the corporate network? Answer guidance: Round to two decimal places. Remember to include domains with no rank in your average! Answer example: 3.23 or 223234.91  
8월 18일부터 8월 19일 사이에 MACLORY-AIR13이 VPN을 통해 기업 네트워크에 연결되어 있는 동안 해결하려고 하는 도메인의 평균 Alexa 1M 순위는 얼마입니까? 답변 안내: 소수점 이하 두 자리까지 반올림합니다. 평균에 순위가 없는 도메인을 포함하는 것을 잊지 마십시오! 답변 예: 3.23 또는 223234.91

<details>
  <summary>hint#1</summary>
    You're going to need a lookup. Are there any loaded in the system that might help you?<br>
    조회가 필요합니다. 당신을 도울 수 있는 시스템에 로드된 것이 있습니까?
</details>
<details>
  <summary>hint#2</summary>
    We want the average of ranks. Not the average of hits to the domains.<br>
    우리는 순위의 평균을 원합니다. 도메인에 대한 평균 조회수가 아닙니다.
</details>
<details>
  <summary>hint#3</summary>
    https://www.splunk.com/blog/2016/03/22/splunking-1-million-urls.html
</details>



313	Two .jpg-formatted photos of Mallory exist in Kevin Lagerfield's server home directory that have eight-character file names, not counting the .jpg extension. Both photos were encrypted by the ransomware. One of the photos can be downloaded at the following link, replacing 8CHARACTERS with the eight characters from the file name. https://splunk.box.com/v/8CHARACTERS After you download the file to your computer, decrypt the file using the encryption key used by the ransomware. What is the complete line of text in the photo, including any punctuation? Answer guidance: The encryption key can be found in Splunk.  
.jpg 형식의 Mallory 사진 두 장이 Kevin Lagerfield의 서버 홈 디렉토리에 있으며 .jpg 확장자는 제외하고 파일 이름이 8자로 되어 있습니다. 두 사진 모두 랜섬웨어에 의해 암호화되었습니다. 사진 중 하나는 다음 링크에서 다운로드할 수 있으며 8CHARACTERS를 파일 이름의 8자로 대체합니다. https://splunk.box.com/v/8CHARACTERS 파일을 컴퓨터에 다운로드한 후 랜섬웨어에서 사용하는 암호화 키를 사용하여 파일을 해독합니다. 문장부호를 포함하여 사진의 전체 텍스트 줄은 무엇입니까? 답변 안내: 암호화 키는 Splunk에서 찾을 수 있습니다.

<details>
  <summary>hint#1</summary>
    Understanding from OSINT how this ransomware behaves is key to the answer.<br>
    OSINT에서 이 랜섬웨어가 어떻게 작동하는지 이해하는 것이 답의 핵심입니다.
</details>
<details>
  <summary>hint#2</summary>
    This ransomware is called 'Patcher' and it is terribly written and uses *NIX command line tools to wreak havoc.<br>
    이 랜섬웨어는 '패처'라고 불리며 끔찍하게 작성되었으며 *NIX 명령줄 도구를 사용하여 혼란을 일으키고 있습니다.
</details>
<details>
  <summary>hint#3</summary>
    Patcher uses the UNIX zip utility.<br>
    Patcher는 UNIX zip 유틸리티를 사용합니다.
</details>

