---
layout: post
current: post
cover:  assets/built/images/bots/v1/bots-v1.jpg
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
  
시나리오는 아래와 같습니다.

Scenario 1 (APT):
The focus of this hands on lab will be an APT scenario and a ransomware scenario. You assume the persona of Alice Bluebird, the analyst who has recently been hired to protect and defend Wayne Enterprises against various forms of cyberattack.
In this scenario, reports of the below graphic come in from your user community when they visit the Wayne Enterprises website, and some of the reports reference "P01s0n1vy." In case you are unaware, P01s0n1vy is an APT group that has targeted Wayne Enterprises. Your goal, as Alice, is to investigate the defacement, with an eye towards reconstructing the attack via the Lockheed Martin Kill Chain.  

\- 시나리오#1 요약  
해킹그룹 ```P01s0n1vy```가 ```Wayne```기업를 해킹했습니다. 당신은 보안 담당자, Alice Bluebird의 입장에서 ```Lockheed Martin의 Cyberkillchain``` 모델을 이용해 침해 사고를 분석해야 합니다.

![Scenario 1]({{site.url}}/assets/built/images/bots/v1/Defacement.png)

![록히드마틴 사이버킬체인 7단계]({{site.url}}/assets/built/images/bots/v1/cyberkillchain.jpg)  
[록히드마틴 사이버킬체인 7단계]

Scenario 2 (Ransomeware):
In the second scenario, one of your users is greeted by this image on a Windows desktop that is claiming that files on the system have been encrypted and payment must be made to get the files back. It appears that a machine has been infected with Cerber ransomware at Wayne Enterprises and your goal is to investigate the ransomware with an eye towards reconstructing the attack.  

\- 시나리오#2 요약  
```Wayne```기업 직원 중 한 명이 시스템의 파일이 암호화 되었으며 파일을 복호화하려면 비용을 지불해야 하는 내용의 이미지를 보게 됩니다. 시스템이 ```Wayne```의 ```Cerber 랜섬웨어```에 감염된 것으로 보이며 귀하의 목표는 재공격을 염두에 두고 랜섬웨어를 조사하는 것입니다.

![Scenario 2]({{site.url}}/assets/built/images/bots/v1/ransomewere.png)

101	What is the likely IP address of someone from the Po1s0n1vy group scanning imreallynotbatman.com for web application vulnerabilities?  
웹 애플리케이션 취약점에 대해 imreallynotbatman.com을 스캔하는 Po1s0n1vy 그룹의 누군가의 가능한 IP 주소는 무엇입니까?
<details>
  <summary alignment="left">hint#1</summary>
Start your search with "sourcetype=stream:http" and review the rich data captured in these events.<br>
(sourcetype=stream:http로 검색을 시작하고 이러한 이벤트에서 캡처된 풍부한 데이터를 검토하십시오.)
</details>

<details>
  <summary>hint#2</summary>
You'll notice that source and destination IP addresses are stored in fields called src_ip and dest_ip respectively. Determine top-talkers for HTTP by combining : "sourcetype=stream:http | stats count by src_ip, dest_ip | sort -count"<br>
(출발지 및 대상 IP 주소가 각각 src_ip 및 dest_ip라는 필드에 저장되어 있습니다. 조합하여 가장 많은 HTTP이벤트를 조사합니다.)
</details>

원하는 데이터는 IP에 있다. 어떤 sourcetype 있을지 생각해봅시다.
```
| metadata type=sourcetypes index=botsv1
| stats values(sourcetype)
```

sourcetype은 아래와 같습니다.
![sourcetype]({{site.url}}/assets/built/images/bots/v1/2021-10-12-14-38-04.png)

scan을 수행한 컴퓨터의 ip를 찾는거니 stream:http에 우리가 원하는 데이터가 있을것입니다.
또, scan tool을 실행하면 http header의 user-agent에 scan tool에 대한 정보가 추가되므로 scan키워드를 추가해서 검색해봅니다.

```
sourcetype=stream:http imreallynotbatman.com *scan*
```
![수행결과]({{site.url}}/assets/built/images/bots/v1/2021-10-12-14-49-30.png)

src_header에 scan 정보를 볼 수 있다.
추가로, imreallynotbatman.com의 ip는 192.168.250.70라는 정보도 얻을 수 있습니다.

답 : 40.80.148.42

102 What company created the web vulnerability scanner used by Po1s0n1vy? Type the company name. (For example "Microsoft" or "Oracle")  
Po1s0n1vy가 사용하는 웹 취약점 스캐너를 만든 회사는? 회사 이름을 입력합니다. (예: "Microsoft" 또는 "Oracle")

<details>
  <summary>hint#1</summary>
  Many commercial web vulnerability scanners clearly identify themselves in the headers of the HTTP request. Inspect the HTTP source headers (src_headers) of requests from the IP identified in question 101.
  많은 상용 웹 취약점 스캐너는 HTTP 요청의 헤더에서 자신을 명확하게 식별합니다. 질문 101에서 식별된 IP의 요청에 대한 HTTP 소스 헤더(src_headers)를 검사합니다.
</details>

![수행결과]({{site.url}}/assets/built/images/bots/v1/2021-10-12-14-49-30.png)
header정보가 "Acunetix"라는 키워드가 있다. 구글링해봅시다.

![Acunetix]({{site.url}}/assets/built/images/bots/v1/2021-10-12-15-03-12.png)
구글링결과, scan tool을 제작하는 회사명이다.

답 : Acunetix

103	What content management system is imreallynotbatman.com likely using?(Please do not include punctuation such as . , ! ? in your answer. We are looking for alpha characters only.)  
imreallynotbatman.com은 어떤 콘텐츠 관리 시스템을 사용하고 있습니까?(답변에 . , ! ?와 같은 문장부호를 포함하지 마십시오. 우리는 알파 문자만 찾고 있습니다.)

<details>
  <summary>hint#1</summary>
  Look for successful (http status code of 200) GET requests from the scanning IP address (identified previously) and inspect the fields related to URL/URI for clues to the CMS in use.  
  스캐닝 IP 주소(이전에 식별)에서 성공적인(http 상태 코드 200) GET 요청을 찾고 사용 중인 CMS에 대한 단서가 있는지 URL/URI와 관련된 필드를 검사합니다.
</details>

content management system가 뭔지부터 알아봅시다.
![cms란?]({{site.url}}/assets/built/images/bots/v1/2021-10-12-15-11-21.png)
저작물 관리시스템이라함은, 파일 등을 upload하는 서버일 것입니다. 
아래 조건을 추가해 URL field를 검색해봅시다. 
1. http status code를 200이다.
2. HTTP요청은 POST일것 이다.(upload)
3. upload할떄 content-type은 ```application/x-www-form-urlencoded```일것이다.

```
sourcetype=stream:http imreallynotbatman.com status=200 http_method=POST cs_content_type=application/x-www-form-urlencoded
```

결과 중 uri_path field를 보면 joomla라는 키워드를 발견할 수 있습니다.
![uri joomla]({{site.url}}/assets/built/images/bots/v1/2021-10-12-15-18-42.png)

joomla를 구글링해봅시다.
![what is joomla?]({{site.url}}/assets/built/images/bots/v1/2021-10-12-15-20-03.png)

joomla는 CMS의 종류임을 알 수있습니다.

답 : joomla

104	What is the name of the file that defaced the imreallynotbatman.com website? Please submit only the name of the file with extension (For example "notepad.exe" or "favicon.ico")  
imreallynotbatman.com 웹사이트를 침해한 파일의 이름은 무엇입니까? 확장자가 있는 파일 이름만 제출하십시오(예: "notepad.exe" 또는 "favicon.ico").

<details>
  <summary>hint#1</summary>
  First find the IP address of the web server hosting imreallynotbatman.com. You may have found this IP during the course of answering the previous few questions.  
  먼저 imreallynotbatman.com을 호스팅하는 웹 서버의 IP 주소를 찾습니다. 이전 질문에 답하는 과정에서 이 IP를 발견했을 수 있습니다.
</details>

<details>
  <summary>hint#2</summary>
  Revealing sourcetypes include stream:http, fgt_utm, and suricata.  
  소스 유형에는 stream:http, fgt_utm 및 suricata가 포함됩니다.
</details>

<details>
  <summary>hint#3</summary>
  The key here is searching for events where the IP address of the web server is the source. Because it's a web server, we most often see it as a destination but in this case the intruder took control of the server and pulled the defacement file from an internet site.  
  여기서 핵심은 웹 서버의 IP 주소가 소스인 이벤트를 검색하는 것입니다. 웹 서버이기 때문에 우리는 목적지로 가장 많이 보지만 이 경우에는 침입자가 서버를 제어하고 인터넷 사이트에서 변조 파일을 가져왔습니다.
</details>

우선 101질문에서 보았듯이, imreallynotbatman.com의 IP는 192.168.250.70입니다. suricata에서 특이한 이벤트가 있는지 찾아봅니다.
※ suricata는 오픈소스 IDS입니다. 패턴에 의해 악성패킷을 차단하는 이벤트가 있을것으로 예상합니다.  
- [suricata란?](https://bricata.com/blog/what-is-suricata-ids/)

```
sourcetype=suricata dest=192.168.250.70 
| stats count by src
```
|src|count|
|------|---|
|192.168.2.50|211
|192.168.250.70|210|

별 특이점은 없어보입니다. 리버스 커넥션의 경우도 있을 수 있으니 해당 ip를 src로 두어 다시 검색해봅니다.  
리버스 커넥션은 inbound가 아닌 outbound로 CnC서버(악성서버)에 접속하는 기법을 말합니다.
자세한 내용은 아래사이트 참고해주세요.

- [reverse connection이란?](https://oggwa.tistory.com/62)

```
sourcetype=suricata src=192.168.250.70 
| stats count by dest_ip
| sort -count
```

|dest_ip|count|
|------|---|
|40.80.148.42|10317|
|23.22.63.114|1294|
|192.168.250.40|758|
|192.168.2.50	|214|
|192.168.250.70|210|
|108.161.187.134|12|
|192.168.250.255|3|
|224.0.0.252|3|

공인망중 접근 count가 많은것이 있습니다. \(40.80.148.42, 23.22.63.114)\
보통 웹서버는 outbound 통신이 많지 않습니다.
40.80.148.42은 101번 문제에서 풀었던 scan pc의 IP입니다.

해당 통신 중 특이한 점이 있는지 찾아봅니다.
```
sourcetype=suricata src=192.168.250.70 dest_ip=23.22.63.114
```
url field를 보니 의심스러운 url이 있습니다.
![poisonivy-is-coming-for-you-batman.jpeg]({{site.url}}/assets/built/images/bots/v1/2021-10-12-17-01-19.png)

확실하지 않으니, 192.168.250.70(imreallynotbatman.com)가 src인 이벤트가 얼마나 많은지 stream:http에서 찾아봅니다.

```
index=botsv1 src_ip=192.168.250.70 sourcetype=stream:http
```
![src결과]({{site.url}}/assets/built/images/bots/v1/2021-10-12-17-06-49.png)
suricata와 stream:http 모두 해당 uri에 접근한 이력이 있습니다. poisonivy-is-coming-for-you-batman.jpeg

답 : poisonivy-is-coming-for-you-batman.jpeg

105	This attack used dynamic DNS to resolve to the malicious IP. What fully qualified domain name (FQDN) is associated with this attack?
이 공격은 동적 DNS를 사용하여 악성 IP를 확인합니다. 이 공격과 관련된 FQDN(도메인 이름)은 무엇입니까?

<details>
  <summary>hint#1</summary>
  Consider the answer to question 104. The fully qualified domain name was recorded by Stream, Suricata, and the Fortigate firewall.  
  104번 질문에 대한 답을 생각해 보십시오. 정규화된 도메인 이름은 Stream, Suricata 및 Fortigate 방화벽에 의해 기록되었습니다.
</details>

104번에서 확인한 jepg파일을 키워드로, strean:http sourcetype에서 url 필드를 확인해보면 full domain이 나올것입니다.

![105url]({{site.url}}/assets/built/images/bots/v1/2021-10-12-17-52-17.png)

```
sourcetype=stream:http src=192.168.250.70 poisonivy-is-coming-for-you-batman.jpeg
```

답 : prankglassinebracket.jumpingcrab.com

106	What IP address has Po1s0n1vy tied to domains that are pre-staged to attack Wayne Enterprises?  
Po1s0n1vy가 Wayne Enterprises를 공격하기 위해 사전 준비된 도메인에 연결된 IP 주소는 무엇입니까?

<details>
  <summary>hint#1</summary>
  Consider the answer to question 104. The IP address was recorded by Stream, Suricata, and the Fortigate firewall. Do you dig me?
  104번 질문에 대한 답을 생각해 보십시오. IP 주소는 Stream, Suricata 및 Fortigate 방화벽에 의해 기록되었습니다.
</details>

104번 문제에서 공격자의 IP주소는 23.22.63.114 이었음을 파악했습니다.

답 : 23.22.63.114

107	Based on the data gathered from this attack and common open source intelligence sources for domain names, what is the email address that is most likely associated with Po1s0n1vy APT group?  
이 공격에서 수집한 데이터와 도메인 이름에 대한 일반적인 오픈 소스 인텔리전스 소스를 기반으로 할 때 Po1s0n1vy APT 그룹과 가장 관련이 있는 이메일 주소는 무엇입니까?

<details>
  <summary>hint#1</summary>
  Malicious IP addresses, like the one in the last question are examples of attacker infrastructure. Infrastructure is often reused by the same group. Use a service like www.robtex.com to determine other domains that are or have been associated with this attacker infrastructure (IP address).  

  마지막 질문과 같은 악성 IP 주소는 공격자 인프라의 예시입니다. 인프라는 동일한 그룹에서 재사용되는 경우가 많습니다. www.robtex.com과 같은 서비스를 사용하여 이 공격자 인프라(IP 주소)와 관련되어 있거나 연결된 다른 도메인을 확인합니다.
</details>

<details>
  <summary>hint#2</summary>
  Use the whois lookup on domaintools.com to iterate through domains associated with this IP and visually search for suspicious email addresses. Your knowledge of Batman will help you here!

  domaintools.com에서 whois 조회를 사용하여 이 IP와 연결된 도메인을 반복하고 의심스러운 이메일 주소를 시각적으로 검색합니다.   
</details>

이 문제는 OSINT(공개된 출처에서 얻은 정보)를 사용해야합니다. 현재는 OSINT의 해당정보가 변경되어 과거 자료를 인용해서 해결하겠습니다.
- [OSINT란?](https://ko.wikipedia.org/wiki/%EC%98%A4%EC%8B%A0%ED%8A%B8)  
- [splunk OSINT 관련 포스팅](https://www.splunk.com/en_us/blog/tips-and-tricks/work-flow-ing-your-osint.html)

robtex.com는 IP, Domain을 통해서 해당 사이트의 정보에 대해 알 수 있습니다.

robtex에 prankglassinebracket.jumpingcrab.com 검색하면 아래와 같이 조회됩니다.  
![robtex]({{site.url}}/assets/built/images/bots/v1/OSINT-robtex-domain.png)

robtex에서 특이한 정보를 찾지 못했으니 virustotal에 검색해봅시다.

domain정보에 email 정보를 발견할 수 있습니다.  
![virustotal#1]({{site.url}}/assets/built/images/bots/v1/OSINT-virustotal-ip.png)  
![virustotal#2]({{site.url}}/assets/built/images/bots/v1/OSINT-virustotal-domain.png)  

답 : lillian.rose@po1s0n1vy.com

108	What IP address is likely attempting a brute force password attack against imreallynotbatman.com?  
imreallynotbatman.com에 대해 무차별 암호 대입 공격을 시도할 가능성이 있는 IP 주소는 무엇입니까?

<details>
  <summary>hint#1</summary>
  Login attempts will use the HTTP POST method, and they will include some obvious fields in the form_data field of stream:http events.
  로그인 시도는 HTTP POST 메서드를 사용하며 여기에는 stream:http 이벤트의 form_data 필드에 몇 가지 명백한 필드가 포함됩니다.
</details>

- [brute force 공격이란?](https://ko.wikipedia.org/wiki/%EB%AC%B4%EC%B0%A8%EB%B3%84_%EB%8C%80%EC%9E%85_%EA%B3%B5%EA%B2%A9)  

login 관련 데이터는 stream:http에 있을 것입니다. 아래 기준에 맞춰 쿼리를 작성해보겠습니다.
1. method는 post일것.
2. login 데이터는 form_data 태그에 있을 것.
3. password, passwd, admin등의 키워드가 있을것.
4. brute force를 시행했다면, 통신 수가 많을 것.

```
sourcetype=stream:http http_method=POST form_data=*passwd* OR form_data=*password* OR form_data=*admin* dest=192.168.250.70
| stats count by src
```
- 쿼리 결과

|dest_ip|count|
|------|---|
|23.22.63.114|412|
|40.80.148.42|8|

src가 23.22.63.114인 form_data의 결과를 보면 
```username=admin&task=login&return=aW5kZXgucGhw&option=com_login&passwd=7777777&1af64a5fa91b91c7107ac2b8e2d4d28a=1```로, 전형적인 brute force attack의 형태이다.

답 : 23.22.63.114

109	What is the name of the executable uploaded by Po1s0n1vy? Please include file extension. (For example, "notepad.exe" or "favicon.ico")

<details>
  <summary>hint#1</summary>
  File uploads to web forms use the HTTP POST method.
  파일 업로드는 HTTP POST 방법을 사용합니다.
</details>
<details>
  <summary>hint#2</summary>
  The question mentions and executable. Search for common executable filename extensions on Windows systems.
  Windows 시스템에서 실행 파일 이름 확장자를 검색합니다.
</details>

1. window의 excuteable file이니 .exe가 포함될것.
2. file upload시 http method는 post입니다.

```
sourcetype=stream:http http_method=POST dest=192.168.250.70 *.exe
```

part_filename이라는 필드에 3791.exe라는 이름의 파일이 보입니다.
![part_filename]({{site.url}}/assets/built/images/bots/v1/2021-10-13-16-16-27.png)

해당파일을 전송한 ip를 확인해보니, 101번 문제해서 scan했던 IP와 같으므로 악성파일임을 확신할 수 있습니다.
![]({{site.url}}/assets/built/images/bots/v1/2021-10-13-16-21-24.png)

답 : 3791.exe

110	What is the MD5 hash of the executable uploaded?

<details>
  <summary>hint#1</summary>
  It will be difficult to calulate a hash based on the Splunk event you used to answer 109. Instead Search for the file name in a different data source to find evidence of execution, including file hash values.  
  109번에서 사용한 Splunk 이벤트를 기반으로 해시를 계산하는 것은 어려울 것입니다. 대신 다른 데이터 소스에서 파일 이름을 검색하여 파일 해시 값을 포함하여 실행 증거를 찾으십시오.
</details>
<details>
  <summary>hint#2</summary>
  This is an ideal use case for Microsoft Sysmon data. Determine the sourcetype for Sysmon events and search them for the executable.  
  이것은 이상적인 Microsoft Sysmon 데이터 usecase 입니다. Sysmon 이벤트의 소스 유형을 결정하고 실행 파일을 검색합니다.
</details>

해답은 window 이벤트 로그인 sysmon에서 찾을 수 있을 것입니다.
[syslog란?](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)

sourcetype Sysmon에서 3791.exe를 키워드로 이벤트를 검색합니다.
![sourcetype]({{site.url}}/assets/built/images/bots/v1/2021-10-12-14-38-04.png)
```

```
111	GCPD reported that common TTPs (Tactics, Techniques, Procedures) for the Po1s0n1vy APT group, if initial compromise fails, is to send a spear phishing email with custom malware attached to their intended target. This malware is usually connected to Po1s0n1vys initial attack infrastructure. Using research techniques, provide the SHA256 hash of this malware.

<details>
  <summary>hint#1</summary>
  You need to pivot outside of Splunk to answer this question. Use the IP address discovered earlier to search for malware that has been associated with it in the past.
  이 질문에 답하려면 Splunk 외부로 피벗해야 합니다. 이전에 검색된 IP 주소를 사용하여 과거에 연결된 맬웨어를 검색합니다.
</details>
<details>
  <summary>hint#2</summary>
  Experienced analysts know to use sites like www.threatminer.org to search for malware associated with the malicious IP address, but if all alse fails, Google it!  
  전문분석가는 www.threatminer.org와 같은 사이트를 사용하여 악성 IP 주소와 관련된 맬웨어를 검색하지만, 발견 실패시 Google에서 검색하십시오!
</details>

112	What special hex code is associated with the customized malware discussed in question 111? (Hint: It's not in Splunk)

<details>
  <summary>hint#1</summary>
  Do some further research on the hash discovered in the last question. Virustotal.com is a good starting place.    
  마지막 문제에서 발견된 해시에 대해 좀 더 조사하십시오. Virustotal.com에서 검색해봅니다.
</details>
<details>
  <summary>hint#2</summary>
  malwr.com might lead you astray.  
  malwr.com은 잘못된 방향입니다.
</details>

<details>
  <summary>hint#3</summary>
  The hex codes we are after here will be formatted like this: 49 66 20 79 6f 75 20 64 65 63 6f 64 65 20 74 68 65 20 68 69 6e 74 2c 20 79 6f 75 20 64 6f 6e 27 74 20 6e 65 65 64 20 61 20 68 69 6e 74 21. Submit the hex codes, but decode them on the web for fun!  
  16진수 코드는 49 66 20 79 6f 75 20 64 65 63 6f 64 65 20 74 68 65 20 68 69 6e 74 2c 20 79 6f 645 64 20 61 20 68 69 6e 74 21. 16진수 코드를 제출하되 웹에서 디코딩하십시오!
</details>

113	One of Po1s0n1vy's staged domains has some disjointed "unique" whois information. Concatenate the two codes together and submit as a single answer.

<details>
  <summary>hint#1</summary>
  Use a service like www.robtex.com to determine other domains that are or have been associated with the attacker infrastructure (IP address).    
</details>

<details>
  <summary>hint#2</summary>
  Use a high quality whois site like www.domaintools.com to perform whois lookups against these domains until you see a hex code where you were expecting text. Warning not all whois sites show you all fields!  
</details>

114	What was the first brute force password used?

<details>
  <summary>hint#1</summary>
  Login attempts will use the HTTP POST method, and they will include some obvious fields that you can search for in the form_data field of stream:http events.  
  로그인 시도는 HTTP POST 메서드를 사용하며 여기에는 stream:http 이벤트의 form_data 필드에서 검색할 수 있는 몇 가지 명백한 필드가 포함됩니다.
</details>
<details>
  <summary>hint#2</summary>
  By default, Splunk will put the most recent events at the top of the list. You can use the "reverse" SPL command to show you least recent first.  
  Splunk는 가장 최근 이벤트를 목록 맨 위에 놓습니다. "reverse" SPL 명령을 사용하여 가장 최근의 것을 먼저 표시할 수 있습니다.
</details>

108번에서 발견한 정보를 토대로 brute force attack를 발췌해봅시다.
형식은 passwd=xxx기준이니, 정규표현식을 사용합니다.

```
sourcetype=stream:http http_method=POST src=23.22.63.114 dest=192.168.250.70
| rex field=form_data "passwd=(?<brutePassword>\w+)"
| table _time brutePassword
| sort _time
```

- 결과
![passwdfield]({{site.url}}/assets/built/images/bots/v1/2021-10-13-17-35-23.png)

제일 먼저 나오는 패스워드는 12345678입니다.

답 : 12345678

115	One of the passwords in the brute force attack is James Brodsky's favorite Coldplay song. Hint: we are looking for a six character word on this one. Which is it?  
brute force attack의 암호 중 하나는 James Brodsky가 가장 좋아하는 Coldplay 노래입니다. 힌트: 이 단어에서 6자 단어를 찾고 있습니다. 어떤것 인가?
<details>
  <summary>hint#1</summary>
  If you have not done so already, try to extract the attempted password into a new field using the "rex" SPL command and a regular expression. Having the password attempt in its own field will serve you well for the next several questions!  
  아직 수행하지 않은 경우 "rex" SPL 명령과 정규식을 사용하여 시도한 암호를 새 필드에 추출해 보십시오. 자체 필드에 비밀번호를 입력하면 다음 몇 가지 질문에 도움이 됩니다!
</details>
<details>
  <summary>hint#2</summary>
  It's not hard to get a list of songs by the artist. Once you have that,use the "len()" function of the "eval" SPL command. For Splunk style points, use a lookup table to match the password attempts with songs.
  아티스트의 노래 목록을 얻는 것은 어렵지 않습니다. 일단 가지고 있으면 "eval" SPL 명령의 "len()" 함수를 사용하십시오. Splunk 스타일의 경우 조회 테이블을 사용하여 노래와 비밀번호를 일치시킵니다.  
</details>

114번에서 사용한 쿼리를 사용하겠습니다.
그리고, 조건을 걸어 6자리 패스워드를 발췌하겠습니다.

```
sourcetype=stream:http http_method=POST src=23.22.63.114 dest=192.168.250.70
| rex field=form_data "passwd=(?<brutePassword>\w+)"
| where len(brutePassword)=6
```

overview에서 소개한 쿼리를 사용할 차례입니다. csv파일중 cp.csv 파일이 있습니다.
```
| rest /servicesNS/-/-/data/lookup-table-files
```
![csv파일 조회]({{site.url}}/assets/built/images/bots/overview/csvFileSearch.jpg)

```
sourcetype=stream:http http_method=POST src=23.22.63.114 dest=192.168.250.70
| rex field=form_data "passwd=(?<brutePassword>\w+)" ```brutePassword변수에 패스워드 발췌 표현식```
| where len(brutePassword)=6```패스워드 중 6자리글자인것만 발췌```
| table brutePassword 
| join type=inner brutePassword ```cold play 노래제목 파일과 join```
    [ | inputlookup coldplay.csv 
    | rename song as brutePassword 
    | fields brutePassword ]
```

- 결과    

|brutePassword|
|:---:|
|yellow|

답 : yellow

116	What was the correct password for admin access to the content management system running "imreallynotbatman.com"?  
"imreallynotbatman.com"을 실행하는 콘텐츠 관리 시스템에 대한 관리자 액세스의 올바른 비밀번호는 무엇입니까?
<details>
  <summary>hint#1</summary>
  From the previous questions, you should know how to extract the password attempts.  You should also know what IP is submitting passwords.  Are any other IP addresses submitting passwords?
  전 질문에서 비밀번호 시도를 추출하는 방법을 알아야 합니다. 또한 어떤 IP가 로그인 시도했는지 알아야 합니다. 로그인을 시도하는 다른 IP 주소가 있습니까?  
</details>

탐색 전략은 아래와 같습니다.
1. brute force는 같은 패스워드는 한번만 시도한다.
2. 올바른 패스워드를 찾았다면 같은 패스워드 사용이 2번이상 있을것이다.

```
sourcetype=stream:http dest=192.168.250.70
| rex field=form_data "passwd=(?<brutePassword>\w+)"
| stats count by brutePassword
| sort -count
```

- 결과 

|brutePassword|count|
|---|---|
|batman|2|
|000000|1|
|1111|1|


|brutePassword|count|values(src)|
|---|---|---|
|batman|2|23.22.63.114<br>40.80.148.42|
|000000|1|23.22.63.114|
|1111|1|23.22.63.114|

40.80.148.42(scan ip)로 로그인했음을 알 수 있습니다.

답 : batman

117	What was the average password length used in the password brute forcing attempt? (Round to closest whole integer. For example "5" not "5.23213")
brute force attack 시도에 사용된 평균 암호 길이는 얼마입니까? (가장 가까운 정수로 반올림합니다. 예를 들어 "5.23213"이 아닌 "5")

<details>
  <summary>hint#1</summary>
  Calculate the length of every password attempt and store the result in a new field. Then calulate the average of that new field with a stats command. Use eval to average, or just visually inspect.  
  모든 암호 시도의 길이를 계산하고 결과를 새 필드에 저장합니다. 그런 다음 stats 명령으로 새 필드의 평균을 계산합니다. 평균을 내기 위해 eval을 사용하거나 그냥 육안으로 검사하십시오.
</details>
<details>
  <summary>hint#2</summary>
  Then calulate the average of that new length field with a stats command, and finally use eval to round, or just manually round.  
  그 후 stats 명령으로 새 길이 필드의 평균을 계산하고 마지막으로 eval을 사용하여 반올림하거나 수동으로 반올림합니다.
</details>

```
sourcetype=stream:http dest=192.168.250.70
| rex field=form_data "passwd=(?<brutePassword>\w+)"
| eval lenPwd = len(brutePassword)
| stats avg(lenPwd) as avglenPwd
| eval answer=round(avglenPwd,0)
```


|avglenPwd|answer|
|---|---|
|6.174334140435835|6|

답 : 6

118	How many seconds elapsed between the time the brute force password scan identified the correct password and the compromised login? Round to 2 decimal places.  
brute force attack시 올바른 암호를 식별한 시간과 성공한 로그인 사이에 몇 초가 경과했습니까? 소수점 이하 2자리까지 반올림합니다.

<details>
  <summary>hint#1</summary>
  You'll note from previous answers that one of the passwords was attempted twice. You need to calculate the duration of time between those two attempts.  
  이전 답변에서 비밀번호 중 하나가 두 번 시도되었음을 알 수 있습니다. 이 두 시도 사이의 시간을 계산해야 합니다.
</details>
<details>
  <summary>hint#2</summary>
  Need more help? Write a search that returns only the two events in questions, then use  either "| delta _time" or "| transaction \<extracted-pword-attempt\>" SPL commands.  
  도움이 더 필요하세요? 질문에서 두 개의 이벤트만 반환하는 검색을 작성한 다음 "| delta _time" 또는 "| transaction \<extracted-pword-attempt\>" SPL 명령을 사용하십시오.  
</details>  

위에서 올바른 암호는 batman이었으니, 암호가 batman인 이벤트의 시간차를 구해봅시다.  
  
```
sourcetype=stream:http dest=192.168.250.70
| rex field=form_data "passwd=(?<brutePassword>\w+)"
| search brutePassword=batman
| table _time brutePassword
```

|_time|brutePassword|
|---|---|
|2016/08/10 21:46:33.689|batman|
|2016/08/10 21:48:05.858|batman|

차이는 92.169인데, 2번째자리에서 반올림하면 92.17이다.

답 : 92.17

※ 풀이2
transaction이라는 명령어가 있다.
[splunk transaction명령어](https://docs.splunk.com/Documentation/Splunk/8.2.2/SearchReference/Transaction)

```
sourcetype=stream:http  
| rex field=form_data "passwd=(?<brutePassword>\w+)" 
| search brutePassword=batman
| transaction brutePassword 
| eval duration=round(duration, 2)
| table duration
```

|duration|
|---|
|92.169084|

119	How many unique passwords were attempted in the brute force attempt?  
brute force attack에서 사용한 패스워드는 몇가지입니까?  

<details>
  <summary>hint#1</summary>
  Be sure you are extracting the password attempts correctly, then use a stats function to count unique (not total) attempts.
  비밀번호 시도를 올바르게 추출했는지 확인한 다음 통계 기능을 사용하여 고유한(총 시도가 아닌) 시도를 계산하십시오.
</details>

중복값을 제거하는 dedup명령어를 사용하여 총 이벤트 수를 파악한다.
```
sourcetype=stream:http  
| rex field=form_data "passwd=(?<brutePassword>\w+)" 
| dedup brutePassword
```

![password수]({{site.url}}/assets/built/images/bots/overview/2021-10-14-16-18-05.png)

답 : 412

200	What was the most likely IP address of we8105desk on 24AUG2016?

<details>
  <summary>hint#1</summary>
  
</details>

201	Amongst the Suricata signatures that detected the Cerber malware, which one alerted the fewest number of times? Submit ONLY the signature ID value as the answer. (No punctuation, just 7 integers.)

<details>
  <summary>hint#1</summary>
  
</details>

202	What fully qualified domain name (FQDN) does the Cerber ransomware attempt to direct the user to at the end of its encryption phase?

<details>
  <summary>hint#1</summary>
  
</details>

203	What was the first suspicious domain visited by we8105desk on 24AUG2016?

<details>
  <summary>hint#1</summary>
  
</details>

204	During the initial Cerber infection a VB script is run. The entire script from this execution, pre-pended by the name of the launching .exe, can be found in a field in Splunk. What is the length in characters of the value of this field?

<details>
  <summary>hint#1</summary>
  
</details>

205	What is the name of the USB key inserted by Bob Smith?

<details>
  <summary>hint#1</summary>
  
</details>

206	Bob Smith's workstation (we8105desk) was connected to a file server during the ransomware outbreak. What is the IP address of the file server?

<details>
  <summary>hint#1</summary>
  
</details>

207	How many distinct PDFs did the ransomware encrypt on the remote file server?

<details>
  <summary>hint#1</summary>
  
</details>

208	The VBscript found in question 204 launches 121214.tmp. What is the ParentProcessId of this initial launch?

<details>
  <summary>hint#1</summary>
  
</details>

209	The Cerber ransomware encrypts files located in Bob Smith's Windows profile. How many .txt files does it encrypt?

<details>
  <summary>hint#1</summary>
  
</details>

210	The malware downloads a file that contains the Cerber ransomware cryptor code. What is the name of that file?

<details>
  <summary>hint#1</summary>
  
</details>

211	Now that you know the name of the ransomware's encryptor file, what obfuscation technique does it likely use?

<details>
  <summary>hint#1</summary>
  
</details>
