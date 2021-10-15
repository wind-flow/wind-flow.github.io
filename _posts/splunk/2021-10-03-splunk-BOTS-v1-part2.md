---
layout: post
current: post
cover:  assets/built/images/bots/v1/bots-v1.jpg
navigation: True
title: splunk-bots-v1 write up - part2
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

200	What was the most likely IP address of we8105desk on 24AUG2016?  
2016년 8월 24일 we8105desk의 가장 가능성이 높은 IP 주소는 무엇입니까?
<details>
  <summary>hint#1</summary>
  Keep it simple and just search for the hostname provided in the question.  Try using the stats command to get a count of events by source ip address to point you in the right direction.<br>
  
  간단하게 유지하고 질문에 제공된 호스트 이름을 검색하십시오. stats 명령을 사용하여 소스 IP 주소별로 이벤트 수를 가져와 올바른 방향으로 안내해 보세요.
</details>

201	Amongst the Suricata signatures that detected the Cerber malware, which one alerted the fewest number of times? Submit ONLY the signature ID value as the answer. (No punctuation, just 7 integers.)  
Cerber 악성코드를 탐지한 Suricata 시그니처 중 가장 적게 경고한 것은? 서명 ID 값만 답변으로 제출하십시오. (구두점은 없고 7개의 정수만 있습니다.)
<details>
  <summary>hint#1</summary>
  Keep it simple and start your search by looking at only the sourcetype associated with Suricata and maybe even the name of the malware in question.  The field containing the signature ID should be obvious.  Use stats to create a count by the field containing the signature ID.<br>
  
  단순하게 유지하고 Suricata와 연결된 소스 유형만 보고 심지어 문제의 맬웨어 이름까지 살펴봄으로써 검색을 시작하십시오. 서명 ID가 포함된 필드는 명확해야 합니다. 통계를 사용하여 서명 ID가 포함된 필드로 개수를 만듭니다.
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
