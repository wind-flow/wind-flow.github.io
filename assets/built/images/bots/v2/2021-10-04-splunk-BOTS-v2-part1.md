---
layout: post
current: post
cover:  assets/built/images/bots/v2/bots-v2.jpg
navigation: True
title: splunk-bots-v2 write up(1)
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

100	Amber Turing was hoping for Frothly to be acquired by a potential competitor which fell through, but visited their website to find contact information for their executive team. What is the website domain that she visited? Answer guidance: Do not provide the FQDN. Answer example: google.com  
Amber Turing은 Frothly가 잠재적인 경쟁업체에 인수되기를 바랐지만, 웹사이트를 방문하여 경영진의 연락처를 찾았습니다. 그녀가 방문한 웹사이트 도메인은 무엇입니까? 주의 : 답은 FQDN형태가 아닙니다. 답변 예시: google.com

<details>
  <summary>hint#1</summary>
    Look at Amber's web traffic.<br>
    Amber의 웹 트래픽을 보십시오.
</details>

<details>
  <summary>hint#2</summary>
    Find Amber's hostname and find the IP address that she was most likely using. Then look at the stream:http sourcetype.<br>
    Amber의 호스트 이름을 찾고 그녀가 사용했을 가능성이 가장 높은 IP 주소를 찾습니다. 그런 다음 stream:http 소스 유형을 보십시오.
</details>

<details>
  <summary>hint#3</summary>
    Take a look at src_ip=10.0.2.101 and the stream:http sourcetype. Look at the websites that Amber visited over the month of August.<br>
    src_ip=10.0.2.101 및 stream:http 소스 유형을 살펴보십시오. Amber가 8월 한 달 동안 방문한 웹사이트를 보십시오
</details>

Amber Turing의 IP를 파악하고, stream:http에서 해당 IP가 src인 url을 확인해보면 될것입니다.

```
Amber Turing
```

src칼럼을 보면 10.0.4.4와 10.0.2.101의 이벤트 수가 가장 많습니다.

두가지 모두 src필드로 검색해보면, 10.0.4.4는 stream:smb에서 찾을 수 있는데, amber의 이름이 filename에 포함되어있습니다.
한편, 10.0.2.101는 sourcetype pan:traffic에서 출발지가 frothly\amber.turing인 데이터를 보아, amber turing의 IP는 10.0.2.101입니다.

frothly의 경쟁회사라고 했으니, 해당 기업의 산업을 찾아봅니다.
![frothly]({{site.url}}/assets/built/images/bots/v2/2021-10-21-09-54-13.png)
frothly는 맥주제조회사임을 알 수 있습니다.

src=10.0.2.101를 두고, http로그를 조사해봅니다. 추가로, 방문한 웹사이트니 method를 GET으로 두어 탐색범위를 줄입시다.

```
src=10.0.2.101 sourcetype=stream:http http_method=GET
| stats count by site
```

|site|count|
|---|---|
|uranus.frothly.local:8014|593|
|img-s-msn-com.akamaized.net|353|
|crl.microsoft.com|86|
|clienttemplates.content.office.net|69|
|redirector.gvt1.com|39|
|www.finnegan.com|24|
|ping.chartbeat.net|18|
|www1.folha.uol.com.br|18|
|classificados1.folha.uol.com.br|13|
|static-hp-wus-s-msn-com.akamaized.net|12|
|www.berkbeer.com|12|
|www.bing.com	|12|
|ocsp.digicert.com|11|

site 중 berkbeer.com가 눈에 보입니다. forthly도 맥주회사니, berkbeer가 Ambur가 방문한 경쟁회사의 사이트는 berkbeer.com입니다.

답 : berkbeer.com

101	Amber found the executive contact information and sent him an email. What is the CEO's name? Provide the first and last name.  
Amber는 임원 연락처 정보를 찾아 이메일을 보냈습니다. CEO의 이름은 무엇입니까? 이름과 성을 제공하십시오.

<details>
  <summary>hint#1</summary>
    Look for emails to Amber Turing.<br>
    Amber Turing에게 보내는 이메일주소를 찾으세요.
</details>

<details>
  <summary>hint#2</summary>
    Find emails from aturing that were sent to the domain from question 100.<br>
    문제 100번에서 도메인으로 보낸 aturing의 이메일 찾아보세요.
</details>
<details>
  <summary>hint#3</summary>
    Look at the sourcetype=stream:smtp and filter on the sender=aturing@froth.ly and/or recipient=aturing@froth.ly. Look at the content and body of emails that have something to do with competitors. The name of the CEO should be in the email.<br>
    sourcetype=stream:smtp를 보고 sender=aturing@froth.ly 및/또는 recipient=aturing@froth.ly를 필터링합니다. 경쟁자와 관련이 있는 이메일의 내용과 본문을 살펴보십시오. CEO의 이름은 이메일에 있어야 합니다.
</details>

이메일 관련 데이터는 sourcetype stream:smtp에 있을것입니다.
송수신자의 도메인이 forthly.ly, berkbeer.com인 데이터를 찾아봅시다.

우선 amber turing의 이메일주소를 찾아봅니다.
```
sourcetype=stream:smtp amber turing
```
sender필드를 보면 Amber Turing <aturing@froth.ly>인것으로 보아 amber의 이메일주소는 
aturing@froth.ly 입니다.

receiver의 도메인주소가 @berkbeer.com를 찾고, 메일 본문에 CEO란 단어가 있을것입니다.
키워드에 CEO를 추가합시다.

```
sourcetype=stream:smtp aturing@froth.ly @berkbeer.com ceo
| reverse
```

위 쿼리로 검색하면, content필드에 아래의 내용을 볼 수 있다.  
 Hello Amber,=C2=A0=0A=0AGreat to hear from you, yes it is unfortunate th=
e way things turned=0Aout. It would be great to speak with you directly,=
 I would also like=0Ato have Bernhard on the call as I think he might ha=
ve some questions=0Afor you. =C2=A0Give me a call this afternoon if you=
 are free.=C2=A0=0A=0A**Martin Berk=0ACEO**=0A777.222.8765=0Amberk@berkbeer.=
com=0A=0A----- Original Message -----=0AFrom: "Amber Turing" <aturing@fr=
oth.ly>=0ATo:"mberk@berkbeer.com" <mberk@berkbeer.com>=0ACc:=0ASent:Fri,=
 11 Aug 2017 15:49:01 +0000=0ASubject:Amber from Froth.ly=0A=0A=09Mr. Be=
rnhard,=0A=0A=09=C2=A0=C2=A0 I was very sorry to hear about the acquisit=
ion falling through.=0AI was very excited to work with you in the future=
.. I have to admit, I=0Aam a little worried about my future here. I=E2=80=
=99d love to talk to you=0Aabout some information I have regarding my wo=
rk.=0A=0A Amber Turing=0A Principal Scientist=0A 867.322.1123=0A Froth.l=
y=0A=0A=09

smtp의 데이터는 base64로 인코딩되는 경우가 많습니다.
5번째줄을 보면 Martin Berk CEO의 내용이 있습니다.

답 : Martin Berk

102	After the initial contact with the CEO, Amber contacted another employee at this competitor. What is that employee's email address?  
CEO와 처음 연락한 후 Amber는 이 경쟁업체의 다른 직원에게 연락했습니다. 그 직원의 이메일 주소는 무엇입니까?

<details>
  <summary>hint#1</summary>
  Look at Amber's email traffic.<br>
  Amber의 이메일 트래픽을 보세요.
</details>

<details>
  <summary>hint#2</summary>
  Find the last email from the domain in question 100.<br>
  100번 문제의 도메인에서 보낸 마지막 이메일을 찾습니다.
</details>

Martin Berk의 이메일 주소는 mberk@berkbeer.com입니다.  
mberk의 이메일 대화를 파악하면 다른직원의 이메일 주소를 알 수 있을것입니다.

전 문제에서 파악한 메일의 내용을 다시 봅시다.

 Hello Amber,=C2=A0=0A=0AGreat to hear from you, yes it is unfortunate th=
e way things turned=0Aout. It would be great to speak with you directly,=
 I would also like=0Ato have Bernhard on the call as I think he might ha=
ve some questions=0Afor you. =C2=A0Give me a call this afternoon if you=
 are free.=C2=A0=0A=0AMartin Berk=0ACEO=0A777.222.8765=0Amberk@berkbeer.=
com=0A=0A----- Original Message -----=0AFrom: "Amber Turing" <aturing@fr=
oth.ly>=0ATo:"mberk@berkbeer.com" <mberk@berkbeer.com>=0ACc:=0ASent:Fri,=
 11 Aug 2017 15:49:01 +0000=0ASubject:Amber from Froth.ly=0A=0A=09**Mr. Be=
rnhard**,=0A=0A=09=C2=A0=C2=A0 I was very sorry to hear about the acquisit=
ion falling through.=0AI was very excited to work with you in the future=
.. I have to admit, I=0Aam a little worried about my future here. I=E2=80=
=99d love to talk to you=0Aabout some information I have regarding my wo=
rk.=0A=0A Amber Turing=0A Principal Scientist=0A 867.322.1123=0A Froth.l=
y=0A=0A=09

언뜻 지나가기 쉽지만 Mr. Bernhard에게 질문하라는 내용이 있습니다.

```
sourcetype=stream:smtp amber bernhard
```

위 쿼리 결과에서 메일을 읽기전에 receiver 필드에 어떤 내용이 있는지 파악해봅시다.

![receiver]({{site.url}}/assets/built/images/bots/v2/2021-10-21-15-35-13.png)

bernhard의 이메일을 찾을 수 있습니다.

답 : hbernhard@berkbeer.com

103	What is the name of the file attachment that Amber sent to a contact at the competitor?  
Amber가 경쟁업체 연락처에 보낸 첨부 파일 이름은 무엇입니까?
<details>
  <summary>hint#1</summary>
  Look for emails sent from Amber Turing.<br>
  Amber Turing이 보낸 이메일을 찾습니다.
</details>

<details>
  <summary>hint#2</summary>
  Look for aturing@froth.ly sending email to the address listed in question 102.<br>
  문제 102에 나열된 주소로 이메일을 보내는 aturing@froth.ly를 찾으십시오.
</details>

<details>
  <summary>hint#3</summary>
  Search sourcetype=stream:smtp sender=aturing@froth.ly and find the attachment she sent.<br>
  sourcetype=stream:smtp sender=aturing@froth.ly를 검색하고 그녀가 보낸 첨부 파일을 찾습니다.
</details>

sender가 aturing@froth.ly이고, receiver의 도메인이 berkbeer.com인 데이터 중 attach_file관련 필드의 값을 확인해 봅시다.

```
sourcetype=stream:smtp sender_email=aturing@froth.ly receiver_email{}=*@berkbeer.com
```
해당 결과의 attach_filename{}이라는 필드에 값이 한개만 존재하는걸 알 수 있습니다.

![attach_filename]({{site.url}}/assets/built/images/bots/v2/2021-10-21-15-55-05.png)

답 : Saccharomyces_cerevisiae_patent.docx

104	What is Amber's personal email address?  
Amber의 개인 이메일주소는 무엇입니까 ?

<details>
  <summary>hint#1</summary>
  Look for emails sent from Amber Turing.
  Amber Turing이 보낸 이메일을 찾습니다.
</details>
<details>
  <summary>hint#2</summary>
  Review the body of emails that Amber has sent.
  Amber가 보낸 이메일 본문을 검토합니다.
</details>
<details>
  <summary>hint#3</summary>
  Review the email with base64-encoded text for body (or content) and decode the base64.
  본문(또는 콘텐츠)에 대해 base64로 인코딩된 텍스트가 포함된 이메일을 검토하고 base64를 디코딩합니다.
</details>

계속해서 amber와 bern의 대화를 파악해 봅시다.

```
sourcetype=stream:smtp aturing@froth.ly hbernhard@berkbeer.com
```

둘이 나눈 마지막 content의 내용을 보면 base64코드로 보이는 내용을 발견할 수 있습니다. 이것을 decode 해보면 Amber의 개인 이메일주소를 파악할 수 있습니다.

- base64 인코딩  
VGhhbmtzIGZvciB0YWtpbmcgdGhlIHRpbWUgdG9kYXksIEFzIGRpc2N1c3NlZCBoZXJlIGlzIHRo
ZSBkb2N1bWVudCBJIHdhcyByZWZlcnJpbmcgdG8uICBQcm9iYWJseSBiZXR0ZXIgdG8gdGFrZSB0
aGlzIG9mZmxpbmUuIEVtYWlsIG1lIGZyb20gbm93IG9uIGF0IGFtYmVyc3RoZWJlc3RAeWVhc3Rp
ZWJlYXN0aWUuY29tPG1haWx0bzphbWJlcnN0aGViZXN0QHllYXN0aWViZWFzdGllLmNvbT4NCg0K
RnJvbTogaGJlcm5oYXJkQGJlcmtiZWVyLmNvbTxtYWlsdG86aGJlcm5oYXJkQGJlcmtiZWVyLmNv
bT4gW21haWx0bzpoYmVybmhhcmRAYmVya2JlZXIuY29tXQ0KU2VudDogRnJpZGF5LCBBdWd1c3Qg
MTEsIDIwMTcgOTowOCBBTQ0KVG86IEFtYmVyIFR1cmluZyA8YXR1cmluZ0Bmcm90aC5seTxtYWls
dG86YXR1cmluZ0Bmcm90aC5seT4+DQpTdWJqZWN0OiBIZWlueiBCZXJuaGFyZCBDb250YWN0IElu
Zm9ybWF0aW9uDQoNCkhlbGxvIEFtYmVyLA0KDQpHcmVhdCB0YWxraW5nIHdpdGggeW91IHRvZGF5
LCBoZXJlIGlzIG15IGNvbnRhY3QgaW5mb3JtYXRpb24uIERvIHlvdSBoYXZlIGEgcGVyc29uYWwg
ZW1haWwgSSBjYW4gcmVhY2ggeW91IGF0IGFzIHdlbGw/DQoNClRoYW5rIFlvdQ0KDQpIZWlueiBC
ZXJuaGFyZA0KaGVybmhhcmRAYmVya2JlZXIuY29tPG1haWx0bzpoZXJuaGFyZEBiZXJrYmVlci5j
b20+DQo4NjUuODg4Ljc1NjMNCg0K

- base64 디코딩  
Thanks for taking the time today, As discussed here is the document I was referring to.  Probably better to take this offline. Email me from now on at ambersthebest@yeastiebeastie.com\<mailto:ambersthebest@yeastiebeastie.com\>  

From: hbernhard@berkbeer.com<mailto:hbernhard@berkbeer.com> [mailto:hbernhard@berkbeer.com]  
Sent: Friday, August 11, 2017 9:08 AM  
To: Amber Turing <aturing@froth.ly<mailto:aturing@froth.ly>>  
Subject: Heinz Bernhard Contact Information  
  
Hello Amber,  
  
Great talking with you today, here is my contact information. Do you have a personal email I can reach you at as well?  
  
Thank You  
  
Heinz Bernhard  
hernhard@berkbeer.com<mailto:hernhard@berkbeer.com>  
865.888.7563  
  
디코딩 내용에 amber의 개인 이메일주소를 발견할 수 있습니다.

답 : ambersthebest@yeastiebeastie.com

105	What version of TOR did Amber install to obfuscate her web browsing? Answer guidance: Numeric with one or more delimiter.  
Amber는 웹 브라우징을 난독화하기 위해 어떤 버전의 TOR를 설치했습니까? 답변 안내: 하나 이상의 구분 기호가 있는 숫자.

TOR 설치관련 이벤트는 sysmon에 있을것입니다.
keyword를 amber와 tor를 두고 검색해 봅시다.
(ParentCommandLine과 Commandline에 tor가 포함될것으로 예상됩니다.)

```
sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" CommandLine=*tor* ParentCommandLine=*tor* Amber
```
```
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon' Guid='{5770385F-C22A-43E0-BF4C-06F5698FFBD9}'/><EventID>1</EventID><Version>5</Version><Level>4</Level><Task>1</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime='2017-08-24T04:20:44.276520600Z'/><EventRecordID>118559</EventRecordID><Correlation/><Execution ProcessID='900' ThreadID='1824'/><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>wrk-aturing.frothly.local</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='UtcTime'>2017-08-24 04:20:44.260</Data><Data Name='ProcessGuid'>{B2E0DF5E-9CF4-598C-0000-00103B38CC01}</Data><Data Name='ProcessId'>2252</Data><Data Name='Image'>C:\Users\amber.turing\Desktop\Tor Browser\Browser\firefox.exe</Data><Data Name='CommandLine'>"C:\Users\amber.turing\Desktop\Tor Browser\Browser\firefox.exe" </Data><Data Name='CurrentDirectory'>C:\Users\amber.turing\Desktop\Tor Browser\Browser\</Data><Data Name='User'>FROTHLY\amber.turing</Data><Data Name='LogonGuid'>{B2E0DF5E-B9C1-598B-0000-0020ED760900}</Data><Data Name='LogonId'>0x976ed</Data><Data Name='TerminalSessionId'>1</Data><Data Name='IntegrityLevel'>Medium</Data><Data Name='Hashes'>SHA1=82EEBDA7E828142E1FA55066D793D29FB81B48C5</Data><Data Name='ParentProcessGuid'>{B2E0DF5E-9CDF-598C-0000-00101AF3CB01}</Data><Data Name='ParentProcessId'>4536</Data><Data Name='ParentImage'>C:\Users\amber.turing\Downloads\torbrowser-install-7.0.4_en-US.exe</Data><Data Name='ParentCommandLine'>"C:\Users\amber.turing\Downloads\torbrowser-install-7.0.4_en-US.exe" </Data></EventData></Event>
```
tor 설치파일의 이름과 경로를 찾을 수 있었습니다.
C:\Users\amber.turing\Downloads\torbrowser-install-7.0.4_en-US.exe

답 : 7.0.4