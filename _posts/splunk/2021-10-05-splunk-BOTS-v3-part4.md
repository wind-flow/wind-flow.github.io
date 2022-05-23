---
cover: assets/built/images/splunk/bots/v3/bots-v3.jpg
title: splunk-bots-v3 write up(4) - END
date: "2021-10-05 20:04:36+0900"
author: wind-flow
categories:
  - splunk
tags: [splunk]
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

| values(sourcetype)             |
| ------------------------------ |
| PerfmonMk:Process              |
| Script:GetEndpointInfo         |
| Script:InstalledApps           |
| Script:ListeningPorts          |
| Unix:ListeningPorts            |
| Unix:SSHDConfig                |
| Unix:Service                   |
| Unix:Update                    |
| Unix:Uptime                    |
| Unix:UserAccounts              |
| Unix:Version                   |
| WinHostMon                     |
| access_combined                |
| alternatives                   |
| amazon-ssm-agent               |
| amazon-ssm-agent-too_small     |
| apache_error                   |
| aws:cloudtrail                 |
| aws:cloudwatch                 |
| aws:cloudwatch:guardduty       |
| aws:cloudwatchlogs             |
| aws:cloudwatchlogs:vpcflow     |
| aws:config:rule                |
| aws:description                |
| aws:elb:accesslogs             |
| aws:rds:audit                  |
| aws:rds:error                  |
| aws:s3:accesslogs              |
| bandwidth                      |
| bash_history                   |
| bootstrap                      |
| cisco:asa                      |
| cloud-init                     |
| cloud-init-output              |
| code42:api                     |
| code42:computer                |
| code42:org                     |
| code42:security                |
| code42:user                    |
| config_file                    |
| cpu                            |
| cron-too_small                 |
| df                             |
| dmesg                          |
| dpkg                           |
| error-too_small                |
| errors                         |
| errors-too_small               |
| ess_content_importer           |
| hardware                       |
| history-2                      |
| interfaces                     |
| iostat                         |
| lastlog                        |
| linux_audit                    |
| linux_secure                   |
| localhost-5                    |
| lsof                           |
| maillog-too_small              |
| ms:aad:audit                   |
| ms:aad:signin                  |
| ms:o365:management             |
| ms:o365:reporting:messagetrace |
| netstat                        |
| o365:management:activity       |
| openPorts                      |
| osquery:info                   |
| osquery:results                |
| osquery:warning                |
| out-3                          |
| package                        |
| protocol                       |
| ps                             |
| stream:arp                     |
| stream:dhcp                    |
| stream:dns                     |
| stream:http                    |
| stream:icmp                    |
| stream:igmp                    |
| stream:ip                      |
| stream:mysql                   |
| stream:smb                     |
| stream:smtp                    |
| stream:tcp                     |
| stream:udp                     |
| symantec:ep:agent:file         |
| symantec:ep:agt_system:file    |
| symantec:ep:behavior:file      |
| symantec:ep:packet:file        |
| symantec:ep:risk:file          |
| symantec:ep:scm_system:file    |
| symantec:ep:security:file      |
| symantec:ep:traffic:file       |
| syslog                         |
| time                           |
| top                            |
| usersWithLoginPrivs            |
| vmstat                         |
| who                            |
| wineventlog                    |
| xmlwineventlog                 |
| yum-too_small                  |

318 From what country is a small brute force or password spray attack occurring against the Frothly web servers?  
Frothly 웹 서버에 대해 소규모 무차별 대입 공격 또는 암호 스프레이 공격이 어느 국가에서 발생합니까?

<details>
  <summary>hint#1</summary>
    Use linux_secure as the sourcetype.
    sourcetype linux_secure에서 조사하세요.
</details>

힌트에서 sourcetype linux_secure에 답이있다고 알려줍니다.
[linux_secure](https://splunkbase.splunk.com/app/3476/)

vendor_action필드에 **Invalid user**란 값이있으니 조건을 추가해봅니다.

```
sourcetype=linux_secure vendor_action="Invalid user"
```

해당 로그에서 발견한 IP는 **5.101.40.81**입니다.

whois에 검색해봅시다.
![]({{site.url}}/assets/built/images/splunk/bots/v3/2021-11-01-15-28-35.png)

해당 IP국가는 러시아입니다.

답 : RUSSIA

319 The adversary created a BCC rule to forward Frothly's email to his personal account. What is the value of the "Name" parameter set to?  
공격자는 Frothly의 이메일을 자신의 개인 계정으로 전달하는 BCC 규칙을 만들었습니다. "Name" 매개변수의 값은 무엇으로 설정되어 있습니까?

<details>
  <summary>hint#1</summary>
    Use ms:o365:management as the sourcetype.
    sourcetype ms:o365:management에서 조사하세요.
</details>

[BCC룰이란?](https://bluemail.help/ko/myself-bcc-automatically/)
BCC는 숨은참조입니다. 숨은참조 룰을 찾아봅시다.

```
sourcetype=ms:o365:management *Frothly* *Name* (*bcc* OR *Rule* OR *Blind*Carbon*Copy*)
```

![]({{site.url}}/assets/built/images/splunk/bots/v3/2021-11-01-16-01-27.png)

공격자의 메일주소 hyunki1984@naver.com로 BlindCopyTo를 보내는 **New-TransportRule**룰을 생기는 이벤트입니다.

답 : SOX

320 What is the password for the user that was created on the compromised endpoint?  
손상된 엔드포인트에서 생성된 사용자의 비밀번호는 무엇입니까?

<details>
  <summary>hint#1</summary>
    Use WinEventLog:Security as the sourcetype.
    sourcetype WinEventLog:Security에서 조사하세요.
</details>

svcvnc를 키워드로 검색하면 아래와 같은 이벤트를 발견할 수 있습니다.

Process Command Line: C:\Windows\system32\net1 user /add svcvnc Password123!

답 : Password123!

321 The Taedonggang adversary sent Grace Hoppy an email bragging about the successful exfiltration of customer data. How many Frothly customer emails were exposed or revealed?  
대동강은 Grace Hoppy에게 성공적인 고객 데이터 유출에 대해 자랑하는 이메일을 보냈습니다. 얼마나 많은 Frothly 고객 이메일이 노출되거나 공개되었습니까?

<details>
  <summary>hint#1</summary>
    Use stream:smtp as the sourcetype.
    sourcetype stream:smtp에서 조사하세요.
</details>

Grace Hoppy의 이메일주소는 **ghoppy@froth.ly**입니다.
smtp에서 수신자 ghoppy@froth.ly인 이벤트를 찾아봅시다.

```
sourcetype=stream:smtp receiver_email{}=ghoppy@froth.ly
```

sender_email이 **hyunki1984@naver.com**인 이벤트가 1개있습니다.
base64인코딩된 데이터를 디코딩해봅시다.

```
R3JhY2llLAoKICAgICAgIFdlIGJyb3VnaHQgeW91ciBkYXRhIGFuZCBpbXBvcnRlZCBpdDogaHR0
cHM6Ly9wYXN0ZWJpbi5jb20vc2RCVWt3c0UgQWxzbywgeW91IHNob3VsZCBub3QgYmUgdG9vIGhh
cmQgQnJ1Y2UuIEhlIGdvb2QgbWFuIAogCiAKIAogCg==
(Decoding)→
Gracie,
We brought your data and imported it: https://pastebin.com/sdBUkwsE Also, you should not be too hard Bruce. He good man
```

해당 url로 가보면 총 8명입니다.
![]({{site.url}}/assets/built/images/splunk/bots/v3/2021-11-01-16-17-11.png)

답 : 8

322 What is the path of the URL being accessed by the command and control server? Answer guidance: Provide the full path. (Example: The full path for the URL https://imgur.com/a/mAqgt4S/lasd3.jpg is /a/mAqgt4S/lasd3.jpg)
명령 및 제어 서버가 액세스하는 URL의 경로는 무엇입니까? 답변 안내: 전체 경로를 제공하세요. (예: https://imgur.com/a/mAqgt4S/lasd3.jpg URL의 전체 경로는 /a/mAqgt4S/lasd3.jpg입니다.)

<details>
  <summary>hint#1</summary>
    Start with XmlWinEventLog:Microsoft-Windows-Sysmon/Operational as the sourcetype, or review the PowerShell logging on various Frothly laptops.
    XmlWinEventLog:Microsoft-Windows-Sysmon/Operational을 소스 유형으로 시작하거나 다양한 Frothly 랩톱에서 PowerShell 로깅을 검토합니다.
</details>

323 At least two Frothly endpoints contact the adversary's command and control infrastructure. What are their short hostnames? Answer guidance: Comma separated without spaces, in alphabetical order.  
최소 2개의 Frothly 엔드포인트가 적의 명령 및 제어 인프라에 접속합니다. 짧은 호스트 이름은 무엇입니까? 답변 안내: 알파벳 순서로 공백 없이 쉼표로 구분됩니다.

<details>
  <summary>hint#1</summary>
    
</details>

324 Who is Al Bungstein's cell phone provider/carrier? Answer guidance: Two words.  
324 Al Bungstein의 휴대전화 제공업체/이동통신사는 누구인가요? 답변 안내: 두 단어.

<details>
  <summary>hint#1</summary>
    How can you find out what external IP address Al Bungstein is using?<br>
    Al Bungstein이 사용하는 외부 IP 주소를 어떻게 알 수 있습니까?
</details>
<details>
  <summary>hint#2</summary>
    OSINT is your friend here. Pivot off of Al's external IP.<br>
    OSINT는 여기 당신의 친구입니다. Al의 외부 IP를 피벗합니다.
</details>
<details>
  <summary>hint#3</summary>
    There is a single sourcetype in Splunk that also contains this information. It is a scripted input running on Al's machine.<br>
    Splunk에는 이 정보도 포함하는 단일 소스 유형이 있습니다. Al의 시스템에서 실행되는 스크립트 입력입니다.
</details>

Al Bungstein의 이메일은 **abungstein@froth.ly**입니다.
ip : 174.215.1.81

해당 ip를 [whois](https://domain.whois.co.kr/whois/search.php)에 조회해보면

![]({{site.url}}/assets/built/images/splunk/bots/v3/2021-11-01-18-03-14.png)

답 : Verizon Wireless

325 Microsoft cloud services often have a delay or lag between "index time" and "event creation time". For the entire day, what is the max lag, in minutes, for the sourcetype: ms:aad:signin? Answer guidance: Round to the nearest minute without the unit of measure.  
Microsoft 클라우드 서비스는 종종 "인덱스 시간"과 "이벤트 생성 시간" 사이에 지연 또는 지연이 있습니다. 전체일 중 ms:aad:signin의 최대 지연 시간(분)은 얼마입니까? 답변 안내: 측정 단위 없이 가장 가까운 분으로 반올림합니다.

<details>
  <summary>hint#1</summary>

</details>
```
sourcetype=ms:aad:signin  
| eval indextime=strftime(_indextime,"%Y-%m-%d %H:%M:%S") 
| eval time=strftime(_time,"%Y-%m-%d %H:%M:%S") 
| eval indextime_epoch=strptime(indextime,"%Y-%m-%d %H:%M:%S")
| eval time_epoch=strptime(time, "%Y-%m-%d %H:%M:%S")
| table time, indextime, indextime_epoch, time_epoch
| eval delta=indextime_epoch-time_epoch
| stats max(delta) as max_lag
| eval minutes=max_lag / 60
```
326	According to Mallory's advertising research, how is beer meant to be enjoyed? Answer guidance: One word.  
Mallory의 광고 연구에 따르면 맥주는 어떻게 즐길 수 있습니까? 답변 안내: 한 마디.
<details>
  <summary>hint#1</summary>
    
</details>

327도 문제 없습니다.

328 What text is displayed on line 2 of the file used to escalate tomcat8's permissions to root? Answer guidance: Provide contents of the entire line.  
tomcat8의 권한을 루트로 에스컬레이션하는 데 사용되는 파일의 2행에 어떤 텍스트가 표시됩니까? 답변 안내: 전체 라인의 내용을 제공합니다.

<details>
  <summary>hint#1</summary>
    Start with any sourcetype that provides detailed process execution data, or one that provides clear-text details of information posted to the Linux host hoth.<br>
    자세한 프로세스 실행 데이터를 제공하는 소스 유형이나 Linux 호스트 hoth에 게시된 정보의 일반 텍스트 세부 정보를 제공하는 소스 유형으로 시작하십시오.
</details>
<details>
  <summary>hint#2</summary>
    You are looking for a long string of base64 information.
    긴 base64 정보 문자열을 찾고 있습니다.
</details>

osquery에 실행관련 이벤트가 있을것입니다. 어떤 계정이 어떤 명령을 실행했는지 조사해봅니다.

```
sourcetype=osquery:results tomcat8 columns.cmdline=*
| table _time decorations.username columns.cmdline
| reverse
```

중간에 **"chmod" "+x" "colonelnew"**, **"./colonelnew"**의 이벤트를 발견할 수 있습니다.
**colonelnew**은 315번문제에서 발견한 파일과 비슷합니다. sourcetype sysmon에서 cat colonel.c의 로그가 있었습니다.

```
*colonel* source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
```

중간 **C:\windows\temp\unziped\lsof-master\iexeplorer.exe" http://192.168.9.30:8080/frothlyinventory/showcase.action "echo Ly.... &gt;&gt; /tmp/colonel**과 같은 명령어가 보입니다.
해당 base64를 /tmp/colonel파일로 옮기는것처럼 보입니다. 해당 데이터를 base64로 디코딩해봅니다.

시작 : LyoKICogVWJ1bnR1IDE2
끝 : JldHVybiAwOwp9 &gt;&gt

![]({{site.url}}/assets/built/images/splunk/bots/v3/2021-11-01-22-06-41.png)

답 : \* Ubuntu 16.04.4 kernel priv esc

329 One of the files uploaded by Taedonggang contains a word that is a much larger in font size than any other in the file. What is that word?
대동강이 업로드한 파일 중 하나에는 파일의 다른 어떤 것보다 훨씬 큰 글자 크기의 단어가 포함되어 있습니다. 그 단어는 무엇입니까?

<details>
  <summary>hint#1</summary>
    Figure out what files were uploaded, and pivot off of interesting file names found. The WinEventLog:Security sourcetype is helpful, as is the osquery:results sourcetype.<br>
    어떤 파일이 업로드되었는지 파악하고 발견된 흥미로운 파일 이름을 중심으로 중심을 잡습니다. WinEventLog:Security 소스 유형은 osquery:results 소스 유형과 마찬가지로 유용합니다.
</details>
<details>
  <summary>hint#2</summary>
    You are looking for a long string of base64 information.<br>
    긴 base64 정보 문자열을 찾고 있습니다.
</details>
<details>
  <summary>hint#3</summary>
    You will need to find a site to decode the base64 to a viewable image. CyberChef is a good one!
    base64를 볼 수 있는 이미지로 디코딩하려면 사이트를 찾아야 합니다. CyberChef는 좋은 사람입니다!
</details>

지금까지 문제에서 대동강그룹이 업로드한 파일은 colonel, Frothly_GABF_Deck-2018-MK.pptx, 1534778082419.png, definitelydontinvestigatethisfile.sh로 파악했습니다.
각 검색하여 base64 디코딩해봅시다.
**definitelydontinvestigatethisfile.sh**를 검색해보면
sysmon에 아래 base64 코드들이 있습니다.
시작 : /9j/4AAQSkZJRgABAQAAAQABAAD/
끝 : BvdGF0byBwaG9uZQo=

해당 데이터를 디코드해보면 아래와 같습니다.
![]({{site.url}}/assets/built/images/splunk/bots/v3/2021-11-01-22-21-07.png)

답 : splunk

330 What Frothly VPN user generated the most traffic? Answer guidance: Provide the VPN user name.  
어떤 Frothly VPN 사용자가 가장 많은 트래픽을 생성했습니까? 답변 안내: VPN 사용자 이름을 제공합니다.

<details>
  <summary>hint#1</summary>
    Start with cisco:asa as the sourcetype.
    sourcetype cisco:asa에서 조사하십시오.
</details>

```
sourcetype=cisco:asa eventtype=cisco_vpn
| stats count by Cisco_ASA_user
| sort -count
```

| Cisco_ASA_user | count |
| -------------- | ----- |
| mkraeusen      | 38    |
| bstoll         | 36    |
| bgist          | 19    |
| fyodor         | 14    |
| pcerf          | 13    |
| ghoppy         | 5     |
| btun           | 3     |
| abungstein     | 2     |

답 : mkraeusen

331 Using Splunk commands only, what is the upper fence (UF) value of the interquartile range (IQR) of the count of event code 4688 by Windows hosts over the entire day? Use a 1.5 multiplier. Answer guidance: UF = Q3 + 1.5 x IQR  
Splunk 명령만 사용하는 경우 하루 종일 Windows 호스트의 이벤트 코드 4688 수에 대한 사분위수 범위(IQR)의 상한(UF) 값은 얼마입니까? 1.5 배율을 사용하십시오. 답변 안내: UF = Q3 + 1.5 x IQR

<details>
  <summary>hint#1</summary>
    Start with WinEventLog:Security as the sourcetype.<br>
    sourcetype WinEventLog:Security를 조사하십시오.
</details>
<details>
  <summary>hint#2</summary>
    Splunk commands such as eventstats, perc25() and perc75() would be helpful here.<br>
    여기에서 eventstats, perc25() 및 perc75()와 같은 Splunk 명령이 도움이 될 것입니다.
</details>
<details>
  <summary>hint#3</summary>
    If you have never used the interquartile range (IQR) to identify outliers, take a look at the documentation https://docs.splunk.com/Documentation/Splunk/latest/Search/Findingandremovingoutliers#Use_the_interquartile_range_.28IQR.29_to_identify_outliers<br>
    사분위수 범위(IQR)를 사용하여 이상값을 식별한 적이 없는 경우 https://docs.splunk.com/Documentation/Splunk/latest/Search/Findingandremovingoutliers#Use_the_interquartile_range_.28IQR.29_to_identify_outliers 문서를 참조하십시오.
</details>

[eventcode4688](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4688)
새 process creation 이벤트 코드입니다.

```
sourcetype=wineventlog EventCode=4688
| eventstats perc25(count) as p25, perc75(count) as p75
| eval IQR=p75-p25
| eval UF=p75+1.5*IQR
```

답 : 1368

332 What is the CVE of the vulnerability that escalated permissions on Linux host hoth? Answer guidance: Submit in normal CVE format. (Example: cve-2018-9805)
Linux 호스트 hoth에서 권한을 에스컬레이션한 취약점의 CVE는 무엇입니까? 답변 안내: 일반 CVE 형식으로 제출하십시오. (예: cve-2018-9805)

<details>
  <summary>hint#1</summary>
    Start with any sourcetype that provides detailed process execution data, or one that provides clear-text details of information posted to the Linux host hoth.<br>
    자세한 프로세스 실행 데이터를 제공하는 소스 유형이나 Linux 호스트 hoth에 게시된 정보의 일반 텍스트 세부 정보를 제공하는 소스 유형으로 시작하십시오.
</details>
<details>
  <summary>hint#2</summary>
    You are looking for a long string of base64 information.
    긴 base64 정보 문자열을 찾고 있습니다.
</details>
<details>
  <summary>hint#3</summary>
    Google search.
    구글링 하세요.
</details>

328번문제에서 발견한 "\* Ubuntu 16.04.4 kernel priv esc"를 구글링해봅시다.

[CVE-2017-16995](https://www.exploit-db.com/exploits/44298)

답 : CVE-2017-16995

333 What is the CVE of the vulnerability that was exploited to run commands on Linux host hoth? Answer guidance: Submit in normal CVE format. (Example: cve-2018-9805)  
Linux 호스트 hoth에서 명령을 실행하기 위해 악용된 취약점의 CVE는 무엇입니까? 답변 안내: 일반 CVE 형식으로 제출하십시오. (예: cve-2018-9805)

<details>
  <summary>hint#1</summary>
    
</details>
