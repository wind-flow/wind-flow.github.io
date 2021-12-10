---
layout: post
current: post
cover:  assets/built/images/splunk/bots/v3/bots-v3.jpg
navigation: True
title: splunk-bots-v3 write up(3)
date: '2021-10-05 20:04:36 +0900'
tags: [splunk]
class: post-template
subclass: 'post tag-splunk'
author: wind-flow
---
{% include bots-table-of-contents.html %}

- secnario #1  
Note: All the information you need to answer each question is present within the question itself. You just need to figure out how to create the proper splunk search query that will get you the information you want.  
각 질문에 답하는 데 필요한 모든 정보는 질문 자체에 있습니다. 원하는 정보를 얻을 수 있는 적절한 splunk 검색 쿼리를 생성하는 방법을 알아내기만 하면 됩니다.

BOTS-V3

index=botsv3의 sourcetype은 아래와 같습니다.

```
| metadata type=sourcetypes index=botsv3
| stats values(sourcetype)
```
- sourcetype 목록  

|values(sourcetype)|
|---|
|PerfmonMk:Process|
|Script:GetEndpointInfo|
|Script:InstalledApps|
|Script:ListeningPorts|
|Unix:ListeningPorts|
|Unix:SSHDConfig|
|Unix:Service|
|Unix:Update|
|Unix:Uptime|
|Unix:UserAccounts|
|Unix:Version|
|WinHostMon|
|access_combined|
|alternatives|
|amazon-ssm-agent|
|amazon-ssm-agent-too_small|
|apache_error|
|aws:cloudtrail|
|aws:cloudwatch|
|aws:cloudwatch:guardduty|
|aws:cloudwatchlogs|
|aws:cloudwatchlogs:vpcflow|
|aws:config:rule|
|aws:description|
|aws:elb:accesslogs|
|aws:rds:audit|
|aws:rds:error|
|aws:s3:accesslogs|
|bandwidth|
|bash_history|
|bootstrap|
|cisco:asa|
|cloud-init|
|cloud-init-output|
|code42:api|
|code42:computer|
|code42:org|
|code42:security|
|code42:user|
|config_file|
|cpu|
|cron-too_small|
|df|
|dmesg|
|dpkg|
|error-too_small|
|errors|
|errors-too_small|
|ess_content_importer|
|hardware|
|history-2|
|interfaces|
|iostat|
|lastlog|
|linux_audit|
|linux_secure|
|localhost-5|
|lsof|
|maillog-too_small|
|ms:aad:audit|
|ms:aad:signin|
|ms:o365:management|
|ms:o365:reporting:messagetrace|
|netstat|
|o365:management:activity|
|openPorts|
|osquery:info|
|osquery:results|
|osquery:warning|
|out-3|
|package|
|protocol|
|ps|
|stream:arp|
|stream:dhcp|
|stream:dns|
|stream:http|
|stream:icmp|
|stream:igmp|
|stream:ip|
|stream:mysql|
|stream:smb|
|stream:smtp|
|stream:tcp|
|stream:udp|
|symantec:ep:agent:file|
|symantec:ep:agt_system:file|
|symantec:ep:behavior:file|
|symantec:ep:packet:file|
|symantec:ep:risk:file|
|symantec:ep:scm_system:file|
|symantec:ep:security:file|
|symantec:ep:traffic:file|
|syslog|
|time|
|top|
|usersWithLoginPrivs|
|vmstat|
|who|
|wineventlog|
|xmlwineventlog|
|yum-too_small|

300	What is the full user agent string that uploaded the malicious link file to OneDrive?  
OneDrive에 악성 링크 파일을 업로드한 전체 사용자 에이전트 문자열은 무엇입니까?
<details>
  <summary>hint#1</summary>
    Use ms:o365:management as the sourcetype for OneDrive activity.<br>
    OneDrive 활동의 원본 유형으로 ms:o365:management를 사용합니다.
</details>
<details>
  <summary>hint#2</summary>
    A link (or .lnk) file is a shortcut file. Look for link files that are associated with OneDrive.<br>
    링크(또는 .lnk) 파일은 바로 가기 파일입니다. OneDrive와 연결된 링크 파일을 찾습니다.
</details>
<details>
  <summary>hint#3</summary>
    Filter your search to just upload activity.<br>
    활동을 업로드하기 위해 검색을 필터링하십시오.
</details>

OneDrive를 검색하니 sourcetype이 ms:o365:management, o365:management:activity 두가지가 나옵니다.
두가지 sourcetype의 필드를 조사해보니 Operation의 필드에 FileUploaded라는 값이 있습니다.
이 sourcetype에 UserAgent 필드가 있으므로 해당 값이 답일것입니다.

```
OneDrive .lnk Operation=FileUploaded
| table UserAgent
```

답 : Mozilla/5.0 (X11; U; Linux i686; ko-KP; rv: 19.1br) Gecko/20130508 Fedora/1.9.1-2.5.rs3.0 NaenaraBrowser/3.5b4

301	What external client IP address is able to initiate successful logins to Frothly using an expired user account?  
만료된 사용자 계정을 사용하여 Frothly에 성공적으로 로그인할 수 있는 외부 클라이언트 IP 주소는 무엇입니까?
<details>
  <summary>hint#1</summary>
    Use ms:aad:signin as the sourcetype for Azure Active Directory sign-in activity.<br>
    Azure Active Directory 로그인 활동의 소스 유형으로 ms:aad:signin을 사용합니다.
</details>

로그인관련 이벤트는 AD에있을것입니다. sourcetype에 **ms:aad:signin**란 sourcetype이 있습니다.
expired 키워드로 조사해봅니다.

```
sourcetype=ms:aad:signin expired
```

ID는 Kevin Lagerfield, ip는 199.66.91.253, expired된 비밀번호로 로그인을 시도했습니다.
해당 정보로 다시 검색해봅니다.

```
sourcetype=ms:aad:signin "Kevin Lagerfield" 199.66.91.253
```

해당 계정으로 로그인을 성공한 이벤트를 발견할 수 있습니다.

답 : 199.66.91.253

302	According to Symantec's website, what is the discovery date of the malware identified in the macro-enabled file? Answer guidance: Provide the US date format MM/DD/YY. (Example: January 1, 2019 should be provided as 01/01/19)  
시만텍 웹사이트에 따르면 매크로 실행 파일에서 식별된 악성코드의 발견 날짜는 언제입니까? 답변 안내: 미국 날짜 형식 MM/DD/YY를 제공하십시오. (예시: 2019년 1월 1일은 01/01/19로 제공되어야 함)
<details>
  <summary>hint#1</summary>
    Use ms:aad:signin as the sourcetype for Azure Active Directory sign-in activity.
    Azure Active Directory 로그인 활동의 소스 유형으로 ms:aad:signin을 사용합니다.
</details>
<details>
  <summary>hint#2</summary>
    Use WinEventLog:Application as the sourcetype to identify the security risk found.<br>
    WinEventLog:Application을 소스 유형으로 사용하여 발견된 보안 위험을 식별합니다.        
</details>
<details>
  <summary>hint#3</summary>
    Google search for that risk and the term Symantec together.<br>
    Google에서 해당 위험과 Symantec이라는 용어를 함께 검색합니다.
</details>

조사 방향을 잡기힘드니 **macro**로 검색해봅니다.
```
*macro*
```

그럼 19개의 이벤트가 발생하는데, stream:smtp로그가 눈에 띕니다.
![]({{site.url}}/assets/built/images/splunk/bots/v3/2021-11-01-05-33-01.png)
첨부파일 **Malware Alert Text.txt**의 base64 인코딩값을 발견할 수 있습니다. 디코딩해봅시다.

```
Malware was detected in one or more attachments included with this email message. 
Action: All attachments have been removed.
Frothly-Brewery-Financial-Planning-FY2019-Draft.xlsm	 W97M.Empstage
```

추후 마저 풀겠음 

303	What is the password for the user that was successfully created by the user "root" on the on-premises Linux system?  
온프레미스 Linux 시스템에서 사용자 "루트"가 성공적으로 생성한 사용자의 비밀번호는 무엇입니까?
<details>
  <summary>hint#1</summary>
    Use osquery:results as the sourcetype.<br>
    sourcetype osquery:results에서 조사하세요.
</details>
<details>
  <summary>hint#2</summary>
    Osquery is logging command executions on the Linux host hoth.<br>
    Osquery는 Linux 호스트 hoth에서 명령 실행을 기록하고 있습니다.
</details>

linux에서 사용자 추가명령어는 useradd 혹은 adduser입니다.

```
sourcetype=osquery:results *useradd* OR *adduser*
```
이벤트2개가 뜹니다.

cmdline: "useradd" "-ou" "tomcat7" "-p" "ilovedavidverve" "0" "-g" "0" "-M" "-N" "-r" "-s" "/bin/bash"
cmdline: "useradd" "-ou" "tomcat7" "-p" "davidverve.com" "0" "-g" "0" "-M" "-N" "-r" "-s" "/bin/bash"

이중, 실행한 uid가 0인 이벤트의 비밀번호값은 ilovedavidverve입니다.

답 : ilovedavidverve

304	What is the name of the user that was created after the endpoint was compromised?  
엔드포인트가 손상된 후 생성된 사용자의 이름은 무엇입니까?
<details>
  <summary>hint#1</summary>
    Use WinEventLog:Security as the sourcetype.<br>
    WinEventLog:Security를 ​​소스 유형으로 사용하십시오.    
</details>

엔드포인트라고 했으니, 윈도우 시스템일 것입니다. 이벤트로그에서 계정생성 이벤트를 찾아봅시다.
구글에 검색하니 계정생성 윈도우이벤트로그 ID는 4720입니다.

![]({{site.url}}/assets/built/images/splunk/bots/v3/2021-11-01-06-10-48.png)

```
sourcetype=WinEventLog EventCode=4720
```
한개의 이벤트가 나옵니다. 
Account Name:		svcvnc

답 : svcvnc

305	What is the process ID of the process listening on a "leet" port?  
"leet" 포트에서 수신 대기하는 프로세스의 프로세스 ID는 무엇입니까?
<details>
  <summary>hint#1</summary>
    Use osquery:results as the sourcetype.<br>
    osquery:results를 소스 유형으로 사용하십시오.
</details>
<details>
  <summary>hint#2</summary>
    Osquery is logging open ports found on the Linux host hoth.<br>
    Osquery는 Linux 호스트 hoth에서 발견된 열린 포트를 기록하고 있습니다.
</details>

[leet](https://en.wikipedia.org/wiki/Leet)는 1337포트를 사용하는 서비스입니다. PID는 sourcetype ps에서 확인할 수 있을것입니다.

```
1337 sourcetype=ps
```
- 결과
```
root             14356     0      0.0      00:00:00     0.1       1732       6492   ?        S         31:58  netcat              -v_-l_-p_1337_-e_/bin/bash
```
pid는 14356임을 알 수 있습니다.

답 : 14356

306	A search query originating from an external IP address of Frothly's mail server yields some interesting search terms. What is the search string?
Frothly 메일 서버의 외부 IP 주소에서 시작되는 검색 쿼리는 몇 가지 흥미로운 검색어를 생성합니다. 검색 문자열은 무엇입니까?
<details>
  <summary>hint#1</summary>
    Use o365:management:activity as the sourcetype.
    sourcetype o365:management:activity에서 조사하십시오.
</details>

ms office를 사용하는것을 알고있으니, Outlook 혹은 Exchange를 사용할 것입니다. o365관련 sourcetype에서 키워드 query를 조사해봅니다.

```
sourcetype=*o365* (Exchange OR Outlook) *query*
```

아래와 같은 로그를 발견할 수 있습니다.

ClientIP: 104.207.83.63:21974
user: fyodor@froth.ly
Workload: Exchange
UserKey: 1003BFFDA2E71FF9
UserType: 2
Name: SearchQuery
Value: cromdale OR beer OR financial OR secret 

답 : cromdale OR beer OR financial OR secret 

307	What is the MD5 value of the file downloaded to Fyodor's endpoint system and used to scan Frothly's network?  
Fyodor의 엔드포인트 시스템에 다운로드되어 Frothly의 네트워크를 스캔하는 데 사용되는 파일의 MD5 값은 무엇입니까?
<details>
  <summary>hint#1</summary>
    
</details>
실행파일의 hash값은 sysmon로그에 있습니다.
sourcetype으로 제공되지않고, source로 제공합니다.
파일이 실행됐다면 process creation이벤트가 발생했을것입니다.(EventID=1)
어떤 파일이 실행됐는지 파악할 수 있도록 Image필드의 값을 봅시다.

```
host=FYODOR-L source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1 
| stats count by Image
```
Images 중 "C:\\Windows\\Temp\\hdoor.exe"라는 특이한 실행파일이 보입니다.
CommandLine을 보면 "C:\windows\temp\hdoor.exe" -hbs 192.168.9.1-192.168.9.50 /b /m /n 식으로 네트워크 대역관련 인자가 보입니다.

답 : 586EF56F4D8963DD546163AC31C865D7

308	Based on the information gathered for question 304, what groups was this user assigned to after the endpoint was compromised? Answer guidance: Comma separated without spaces, in alphabetical order.  
문제 304에 대해 수집된 정보에 따르면 엔드포인트가 손상된 후 이 사용자는 어떤 그룹에 할당되었습니까? 답변 안내: 알파벳 순서로 공백 없이 쉼표로 구분됩니다.
<details>
  <summary>hint#1</summary>
    
</details>

계정명 svcvnc의 그룹을 알아봅시다.


[sysmon Group할당](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4732)eventID는 4732입니다.

```
svcvnc EventCode=4732
```
이벤트 2개가 나옵니다.

답 : Administrators,Users

309	At some point during the attack, a user's domain account is disabled. What is the email address of the user whose account gets disabled and what is the email address of the user who disabled their account? Answer guidance: Comma separated without spaces, in alphabetical order. (Example: jdoe@mycompany.com,tmiller@mycompany.com)  
공격 중간에 어느 시점에서 사용자의 도메인 계정이 비활성화됩니다. 계정이 비활성화된 사용자의 이메일 주소는 무엇이며 계정을 비활성화한 사용자의 이메일 주소는 무엇입니까? 답변 안내: 알파벳 순서로 공백 없이 쉼표로 구분됩니다. (예: jdoe@mycompany.com,tmiller@mycompany.com)
<details>
  <summary>hint#1</summary>
    
</details>

[sysmon account disable](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4725)eventID는 4725입니다.

```
EventCode=4725
```

아무이벤트도 나오지 않습니다.

AD에서 찾아봅시다.

```
sourcetype=ms:aad:* *user* OR *account* OR *disable*
```

activity라는 필드에 **Disable account**가 보입니다.

```
sourcetype=ms:aad:* activity="Disable account"
```

![]({{site.url}}/assets/built/images/splunk/bots/v3/2021-11-01-12-25-55.png)
actor부분에 **fyodor@froth.ly**라는 이메일계정을 발견할 수 있습니다.
![]({{site.url}}/assets/built/images/splunk/bots/v3/2021-11-01-12-27-35.png)
target을 보면 **bgist@froth.ly**라는 이메일계정또한 발견할 수 있습니다.

답 : bgist@froth.ly,fyodor@froth.ly

310	Another set of phishing emails were sent to Frothly employees after the adversary gained a foothold on a Frothly computer. This malicious content was detected and left behind a digital artifact. What is the name of this file? Answer guidance: Include the file extension. (Example: badfile.docx)  
공격자가 Frothly 컴퓨터에 발판을 마련한 후 또 다른 피싱 이메일 세트가 Frothly 직원에게 전송되었습니다. 이 악성 콘텐츠는 감지되어 디지털 아티팩트를 남겼습니다. 이 파일의 이름은 무엇입니까? 답변 지침: 파일 확장자를 포함합니다. (예: badfile.docx)
<details>
  <summary>hint#1</summary>
    
</details>

문제 302번에서 발견한 **Frothly-Brewery-Financial-Planning-FY2019-Draft.xlsm**파일이 생각납니다. 
![]({{site.url}}/assets/built/images/splunk/bots/v3/2021-11-01-13-15-28.png)
해당 파일명으로 검색해보면 auto-sacning되어 지워졌음을 확인할 수 있습니다.

답 : Frothly-Brewery-Financial-Planning-FY2019-Draft.xlsm

311	Based on the answer to question 310, what is the name of the executable that was embedded in the malware? Answer guidance: Include the file extension. (Example: explorer.exe)  
310번 문제에 대한 답변에 따르면 악성코드에 포함된 실행 파일의 이름은 무엇입니까? 답변 지침: 파일 확장자를 포함합니다. (예: explorer.exe)
<details>
  <summary>hint#1</summary>
    
</details>

바로 다음이벤트의 Image에 exe파일이 있습니다.

![]({{site.url}}/assets/built/images/splunk/bots/v3/2021-11-01-13-22-46.png)

답 : HxTsr.exe

312	How many unique IP addresses "used" the malicious link file that was sent?  
전송된 악성 링크 파일을 "사용"한 고유 IP 주소는 몇 개입니까?
<details>
  <summary>hint#1</summary>
    
</details>

300번문제에서 파악한 악성 링크파일의 이름은 **BRUCE BIRTHDAY HAPPY HOUR PICS.lnk**입니다.

```
"BRUCE BIRTHDAY HAPPY HOUR PICS.lnk"
```

67개의 이벤트가 있습니다.
그중 operation field값 중 **AnonymousLinkUsed**이 눈에 띕니다.

![](2021-11-01-13-29-24.png)

```
"BRUCE BIRTHDAY HAPPY HOUR PICS.lnk"  Operation=AnonymousLinkUsed
| stats dc(ClientIP)
```

답 : 7

313문제도 없네요

314	What port number did the adversary use to download their attack tools?  
공격자가 공격 도구를 다운로드하는 데 사용한 포트 번호는 무엇입니까?
<details>
  <summary>hint#1</summary>
    
</details>

stream:tcp에서 조사해봅니다.
well-known포트가 아닌 포트 중 한번만 다운로드 한 이벤트를 찾아봅시다.

```
sourcetype=stream:tcp
| stats count by dest_port
```
45.77.53.176:3333과 192.168.8.103:50504가 count 1입니다.
외부망 IP인 45.77.53.176이 의심스럽습니다.
stream:http에서 확인해봅시다.

**uri_path: /images/logos.png**를 발견할 수 있습니다.

답 : 3333

315	During the attack, two files are remotely streamed to the /tmp directory of the on-premises Linux server by the adversary. What are the names of these files? Answer guidance: Comma separated without spaces, in alphabetical order, include the file extension where applicable.  
공격하는 동안 공격자는 온프레미스 Linux 서버의 /tmp 디렉터리에 두 개의 파일을 원격으로 스트리밍합니다. 이 파일의 이름은 무엇입니까? 답변 안내: 알파벳 순서로 공백 없이 쉼표로 구분하고 해당되는 경우 파일 확장자를 포함합니다.
<details>
  <summary>hint#1</summary>
    
</details>

file upload 관련 로그는 osquery에 있을것입니다. create, upload관련 행위를 하는 데이터를 찾아봅시다.
```
sourcetype=osquery:results */tmp*.* "columns.action"=CREATED
```
create한 user 중 **tomcat8**을 발견할 수 있습니다. tomcat7이 악성행위하는 계정을 생성했으니 해당 계정도 의심스럽습니다.

```
sourcetype=osquery:results */tmp*.* "columns.action"=CREATED "decorations.username"=tomcat8
| table columns.target_path
```


|columns.target_path|
|---|
|/tmp/ccgZ61x9.o|
|/tmp/cclBJ1WV.s|
|/tmp/colonel.c|
|/tmp/definitelydontinvestigatethisfile.sh|

실행파일은 colonel.c와 definitelydontinvestigatethisfile.sh입니다.

316	Based on the information gathered for question 314, what file can be inferred to contain the attack tools? Answer guidance: Include the file extension.  
314번 문제에 대해 수집된 정보를 바탕으로 공격 도구가 포함된 것으로 유추할 수 있는 파일은 무엇입니까? 답변 지침: 파일 확장자를 포함합니다.
<details>
  <summary>hint#1</summary>
    
</details>

답 : logos.png

317	What is the first executable uploaded to the domain admin account's compromised endpoint system? Answer guidance: Include the file extension.  
도메인 관리자 계정의 손상된 엔드포인트 시스템에 업로드된 첫 번째 실행 파일은 무엇입니까? 답변 지침: 파일 확장자를 포함합니다.
<details>
  <summary>hint#1</summary>
    
</details>

domain admin의 GUI는 (**S-1-5-21*-512**)[https://docs.microsoft.com/en-US/windows/security/identity-protection/access-control/security-identifiers]과 같습니다.
이 키워드로 검색해도 아무것도 나오지않습니다.

sysmon에서 .exe확장자 파일을 검색해봅니다. 악성코드는 보통 tmp, temp파일에 업로드하니 경로조건도 추가해봅니다.

```
*.exe source="WinEventLog:Microsoft-Windows-Sysmon/Operational" Image IN(*tmp*, *temp*)
| stats count by Image
```


|Image|count|
|---|---|
|C:\Users\ALBUNG~1\AppData\Local\Temp\632F4847-CD24-4609-823F-C2C020FD03EB\DismHost.exe	|2|
|C:\Users\BRUCEG~1\AppData\Local\Temp\GUM4F89.tmp\DropboxUpdate.exe	|9|
|C:\Users\BruceGist\AppData\Local\Packages\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\TempState\Downloads\DropboxInstaller.exe	|6|
|C:\Users\FYODOR~1\AppData\Local\Temp\3F5D15FE-AD68-4E1F-B3C4-90E199AF3640\DismHost.exe	|2|
|C:\Users\PeatCerf\AppData\Local\Temp\9027560D-FED5-45FC-A0CC-89A7591BC00E\DismHost.exe	|2|
|C:\Windows\Temp\hdoor.exe	|20|
|C:\Windows\Temp\unziped\lsof-master\iexeplorer.exe	|51|

**hdoor.exe**이 굉장히 의심스럽습니다.

```
*.exe source="WinEventLog:Microsoft-Windows-Sysmon/Operational" Image IN(*tmp*, *temp*)
| dedup Image
| table _time Image Computer User SourceIp DestinationIp
| reverse
```

|_time|Image|Computer|User|SourceIp|DestinationIp|
|---|---|---|---|---|---|
|2018/08/20 09:16:50|C:\Users\ALBUNG~1\AppData\Local\Temp\632F4847-CD24-4609-823F-C2C020FD03EB\DismHost.exe|	ABUNGST-L.froth.ly|
|2018/08/20 10:33:27|C:\Users\BRUCEG~1\AppData\Local\Temp\GUM4F89.tmp\DropboxUpdate.exe|                      BGIST-L.froth.ly|
|2018/08/20 10:33:27|C:\Users\BruceGist\AppData\Local\Packages\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\TempState\Downloads\DropboxInstaller.exe|BGIST-L.froth.ly|
|2018/08/20 10:44:05|C:\Windows\Temp\hdoor.exe|FYODOR-L.froth.ly|AzureAD\FyodorMalteskesko|192.168.8.103|192.168.9.50|
|2018/08/20 11:34:02|C:\Windows\Temp\unziped\lsof-master\iexeplorer.exe|FYODOR-L.froth.ly	|AzureAD\FyodorMalteskesko|192.168.8.103|192.168.9.30|
|2018/08/20 11:34:33|C:\Users\FYODOR~1\AppData\Local\Temp\3F5D15FE-AD68-4E1F-B3C4-90E199AF3640\DismHost.exe	|FYODOR-L.froth.ly|
|2018/08/20 15:00:41|C:\Users\PeatCerf\AppData\Local\Temp\9027560D-FED5-45FC-A0CC-89A7591BC00E\DismHost.exe	|PCERF-L.froth.ly|

가장 먼저 업로드된 파일은 hdoor.exe입니다.

답 : hdoor.exe