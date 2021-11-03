---
layout: post
current: post
cover:  assets/built/images/bots/v3/bots-v3.jpg
navigation: True
title: splunk-bots-v3 write up(2)
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

218	What IAM user access key generates the most distinct errors when attempting to access IAM resources?  
IAM 리소스에 액세스하려고 할 때 가장 뚜렷한 오류를 생성하는 IAM 사용자 액세스 키는 무엇입니까?
<details>
  <summary>hint#1</summary>
    Use aws:cloudtrail as the sourcetype.<br>
    sourcetype aws:cloudtrail에서 조사하세요.
</details>
<details>
  <summary>hint#2</summary>
    Make sure to include all the error codes, such as AccessDenied and NoSuchEntityException.<br>
    AccessDenied 및 NoSuchEntityException과 같은 모든 오류 코드를 포함해야 합니다.
</details>

액세스 오류관련 로그는 cloudtrail에 있을것입니다. aws 공식문서에서 찾아봅니다.

**오류 코드 및 메시지 로그의 예**[AWS cloudtrail 문서](https://docs.aws.amazon.com/ko_kr/awscloudtrail/latest/userguide/cloudtrail-log-file-examples.html)
errorCode 및 errorMessage 요소에 이 오류를 표시합니다.

```
sourcetype=aws:cloudtrail errorCode=*access*
| dedup errorCode errorMessage
| table errorCode errorMessage
```

errorcode필드에서 **AccessDenied**값을 발견할 수 있습니다. 이 키워드를 중심으로 검색해봅니다.

```
sourcetype=aws:cloudtrail errorCode=AccessDenied
```
6개의 이벤트가 있고, userIdentity.accessKeyId필드 **AKIAJOGCDXJ5NW5PXUPA**와 **ASIAZB6TMXZ7LL6JBJQA**를 발견할 수 있습니다.

key가 AKIAJOGCDXJ5NW5PXUPA인 이벤트의 errorMessage를 보면 __User: arn:aws:iam::622676721278:user/web_admin is not authorized to perform: iam:GetUser on resource: user web_admin__ 이므로, IAM리스소에 접속하는 이벤트의 액세스키는 AKIAJOGCDXJ5NW5PXUPA입니다.
(ASIAZB6TMXZ7LL6JBJQA는 bucketlist에 접속하는 이벤트입니다)

답 : AKIAJOGCDXJ5NW5PXUPA

219	Bud accidentally commits AWS access keys to an external code repository. Shortly after, he receives a notification from AWS that the account had been compromised. What is the support case ID that Amazon opens on his behalf?  
Bud가 실수로 AWS 액세스 키를 외부 코드 리포지토리에 커밋합니다. 얼마 후 그는 AWS로부터 계정이 손상되었다는 알림을 받습니다. Amazon이 그의 행동으로 여는 case ID는 무엇입니까?

<details>
  <summary>hint#1</summary>
    Use stream:smtp as the sourcetype.<br>
    sourcetype stream:smtp에서 조사하십시오.
</details>

```
aws support case
```
위와 같이 검색하면 sourcetype stream:smtp의 subject필드에 support case ID정보를 발견할 수 있습니다.
**subject: Amazon Web Services: New Support case: 5244329601**

답 : 5244329601

220	AWS access keys consist of two parts: an access key ID (e.g., AKIAIOSFODNN7EXAMPLE) and a secret access key (e.g., wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY). What is the secret access key of the key that was leaked to the external code repository?  
AWS 액세스 키는 액세스 키 ID(예: AKIAIOSFODNN7EXAMPLE)와 보안 액세스 키(예: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY)의 두 부분으로 구성됩니다. 외부 코드 저장소로 유출된 키의 비밀 접근 키는 무엇입니까?
<details>
  <summary>hint#1</summary>
    Use stream:smtp as the sourcetype.<br>
    sourcetype stream:smtp에서 조사하십시오.
</details>

219문제에서 발견한 email의 content내용을 보면 아래와 같습니다.
```
Your security is important to us. We have become aware that the AWS Access Key AKIAJOGCDXJ5NW5PXUPA (belonging to IAM user "web_admin") along with the corresponding Secret Key is publicly available online at https://github.com/FrothlyBeers/BrewingIOT/blob/e4a98cc997de12bb7a59f18aea207a28bcec566c/MyDocuments/aws_credentials.bak.
```
해당 github page로 가면 secret key를 발견할 수 있습니다.  
https://github.com/FrothlyBeers/BrewingIOT/blob/e4a98cc997de12bb7a59f18aea207a28bcec566c/MyDocuments/aws_credentials.bak

답 : Bx8/gTsYC98T0oWiFhpmdROqhELPtXJSR9vFPNGk

221	Using the leaked key, the adversary makes an unauthorized attempt to create a key for a specific resource. What is the name of that resource? Answer guidance: One word.
유출된 키를 사용하여 공격자는 승인되지 않은 특정 리소스에 대한 키 생성을 시도합니다. 그 자원의 이름은 무엇입니까? 답변 안내: 한 단어.
<details>
  <summary>hint#1</summary>
    Use aws:cloudtrail as the sourcetype.<br>
    sourcetype aws:cloudtrail에서 조사하십시오.
</details>

계정생성관련 이벤트는 cloudtrail에 있으므로, 위에서 파악한 키를 키워드로 **키 생성**같은 이벤트를 찾아봅니다.
```
sourcetype=aws:cloudtrail *AKIAJOGCDXJ5NW5PXUPA*
| table eventName
```

|eventName|
|---|
|UpdateAccessKey|
|GetUser|
|DescribeAccountAttributes|
|ListAccessKeys|
|GetSessionToken|
|CreateAccessKey|
|DeleteAccessKey|
|CreateUser|
|ListAccessKeys|
|GetCallerIdentity|

eventName이 CreateAccessKey인 이벤트를 살펴봅시다.

```
sourcetype=aws:cloudtrail *AKIAJOGCDXJ5NW5PXUPA* eventName=CreateAccessKey
```
error message 필드를 보면 __User: arn:aws:iam::622676721278:user/web_admin is not authorized to perform: iam:CreateAccessKey on resource: user nullweb_admin__
자원이름은 nullweb_admin입니다.

답 : nullweb_admin

222	Using the leaked key, the adversary makes an unauthorized attempt to describe an account. What is the full user agent string of the application that originated the request?  
유출된 키를 사용하여 공격자는 계정을 알아내기 위해 무단으로 시도합니다. 요청을 시작한 애플리케이션의 전체 사용자 에이전트 문자열은 무엇입니까?
<details>
  <summary>hint#1</summary>
    Use aws:cloudtrail as the sourcetype.<br>
    sourcetype aws:cloudtrail에서 조사하십시오.
</details>

전문제와 동일한 조건에서, eventName이 GetUser인 이벤트의 useragent를 파악해봅시다.
```
sourcetype=aws:cloudtrail *AKIAJOGCDXJ5NW5PXUPA* eventName=GetUser
| table userAgent
```

|userAgent|
|---|
|ElasticWolf/5.1.6|

답 : ElasticWolf/5.1.6

223	The adversary attempts to launch an Ubuntu cloud image as the compromised IAM user. What is the codename for that operating system version in the first attempt? Answer guidance: Two words.  
공격자는 손상된 IAM 사용자로 Ubuntu 클라우드 이미지를 시작하려고 시도합니다. 첫 번째 시도에서 해당 운영 체제 버전의 코드명은 무엇입니까? 답변 안내: 두 단어.
<details>
  <summary>hint#1</summary>
    Use aws:cloudtrail as the sourcetype.<br>
    sourcetype aws:cloudtrail에서 조사하십시오.
</details>

```
sourcetype=aws:cloudtrail errorCode="Client.UnauthorizedOperation" eventName=RunInstances
| sort _time
```
requestParameters.instancesSet.items{}.imageId필드의 값이 ami-41e0b93b 임을 알 수 있습니다.
구글에 **ami-41e0b93b ubuntu**로 검색해봅니다.
![]({{site.url}}/assets/built/images/bots/v3/2021-10-31-00-24-26.png)

Xenial이란 이름이 있는데 두단어가 아닙니다.
**ubuntu Xenial**로 검색해봅니다. 

![]({{site.url}}/assets/built/images/bots/v3/2021-10-31-00-25-21.png)

두 단어 이름은 **Xenial Xerus**입니다.

답 : Xenial Xerus

224	Frothly uses Amazon Route 53 for their DNS web service. What is the average length of the distinct third-level subdomains in the queries to brewertalk.com? Answer guidance: Round to two decimal places. (Example: The third-level subdomain for my.example.company.com is example.)  
Frothly는 DNS 웹 서비스에 Amazon Route 53을 사용합니다. brewertalk.com에 대한 쿼리에서 고유한 세 번째 수준 하위 도메인의 평균 길이는 얼마입니까? 답변 안내: 소수점 이하 두 자리까지 반올림합니다. (예: my.example.company.com의 세 번째 수준 하위 도메인은 example입니다.)
<details>
  <summary>hint#1</summary>
    Use aws:cloudwatchlogs as the sourcetype for DNS queries.<br>
    aws:cloudwatchlogs를 DNS 쿼리의 소스 유형으로 사용합니다.
</details>
<details>
  <summary>hint#2</summary>
    Look at the documentation for URL Toolbox (on Splunkbase) to help you parse out the subdomain substring. Use the Splunk len command to help you calculate the length or review the blog entries in https://www.splunk.com/blog/2017/07/06/hunting-with-splunk-the-basics.html. This will teach you how to split domains with URL Toolbox.<br>
    하위 도메인 하위 문자열을 구문 분석하는 데 도움이 되는 URL 도구 상자(Splunkbase의) 설명서를 참조하십시오. Splunk len 명령을 사용하여 길이를 계산하거나 https://www.splunk.com/blog/2017/07/06/hunting-with-splunk-the-basics.html의 블로그 항목을 검토할 수 있습니다. 이것은 URL Toolbox를 사용하여 도메인을 분할하는 방법을 알려줍니다.
</details>
<details>
  <summary>hint#3</summary>
    Make sure to include only the distinct third-level subdomain values.<br>
    고유한 세 번째 수준 하위 도메인 값만 포함해야 합니다.
</details>  

aws:cloudwatchlogs에 DNS관련 데이터가 있습니다. brewertalk.com가 있는 이벤트를 발췌해봅시다.

```
sourcetype=aws:cloudwatchlogs brewertalk.com
```

1.0 2018-08-20T15:08:11Z Z149R7NEBZTKPN hitech1.brewertalk.com A NXDOMAIN UDP NRT20 13.125.50.235 -
와 같은 이벤트가 10만개가 넘습니다.

정규표현식을 사용해 subdomain을 발췌하고, 값들의 평균을 구한 후 반올립합니다.

```
sourcetype=aws:cloudwatchlogs brewertalk.com
| rex field=_raw "Z149R7NEBZTKPN\s(?<query>[^\s]+)" 
| rex field=query "\.?(?<subdomain>[^\.]+).brewertalk.com" 
| dedup subdomain
| table subdomain
| eval lenSubdomain = len(subdomain)
| stats avg(lenSubdomain) as answer
| eval answer=round(answer,2)
```

답 : 8.10

225	Using the payload data found in the memcached attack, what is the name of the .jpeg file that is used by Taedonggang to deface other brewery websites? Answer guidance: Include the file extension.  
memcached 공격에서 발견된 페이로드 데이터를 사용하여 대동강이 다른 양조장 웹사이트를 훼손하는 데 사용하는 .jpeg 파일의 이름은 무엇입니까? 답변 지침: 파일 확장자를 포함합니다.
<details>
  <summary>hint#1</summary>
    Use stream:udp as the sourcetype to find the injected string and separate out the payload.<br>
    sourcetype stream:udp에서 주입된 문자열을 찾고 페이로드를 분리합니다.
</details>
<details>
  <summary>hint#2</summary>
    Google search for the two strings with special characters.<br>
    Google은 특수 문자가 있는 두 문자열을 검색합니다.
</details>
<details>
  <summary>hint#3</summary>
    Looking at one of the websites from the Google results, inspect the source code and identify the name of the image file.<br>
    Google 결과에서 웹사이트 중 하나를 보고 소스 코드를 검사하고 이미지 파일의 이름을 식별합니다.
</details>

memcached attack(https://www.cloudflare.com/ko-kr/learning/ddos/memcached-ddos-attack/)관련 내용을 참고바랍니다.

udp 11211포트를 사용한 DDoS공격입니다.
공격을 찾아봅시다.

```
source="stream:udp" dest_port=11211
```

공격자 : 13.125.33.130


답 : index1.jpeg