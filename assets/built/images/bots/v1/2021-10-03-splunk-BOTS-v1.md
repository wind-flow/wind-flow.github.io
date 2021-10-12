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
![cms란?]({{site.url}}/assets/built/images/bots/v12021-10-12-15-11-21.png)
저작물 관리시스템이라함은, 파일 등을 upload하는 서버일 것입니다. 
아래 조건을 추가해 URL field를 검색해봅시다. 
1. http status code를 200이다.
2. HTTP요청은 POST일것 이다.(upload)
3. upload할떄 content-type은 ```application/x-www-form-urlencoded```일것이다.

```
sourcetype=stream:http imreallynotbatman.com status=200 http_method=POST cs_content_type=application/x-www-form-urlencoded
```

결과 중 uri_path field를 보면 joomla라는 키워드를 발견할 수 있습니다.
![uri joomla]({{site.url}}/assets/built/images/bots/2021-10-12-15-18-42.png)

joomla를 구글링해봅시다.
![what is joomla?]({{site.url}}/assets/built/images/bots/2021-10-12-15-20-03.png)

joomla는 CMS의 종류임을 알 수있습니다.

답 : joomla

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