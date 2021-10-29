---
layout: post
current: post
cover:  assets/built/images/bots/v3/bots-v3.jpg
navigation: True
title: splunk-bots-v3 write up(1)
date: '2021-10-05 20:04:36 +0530'
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

200	List out the IAM users that accessed an AWS service (successfully or unsuccessfully) in Frothly's AWS environment? Answer guidance: Comma separated without spaces, in alphabetical order. (Example: ajackson,mjones,tmiller)  
Frothly의 AWS 환경에서 AWS 서비스(성공 또는 실패)에 액세스한 IAM 사용자를 나열합니까? 답변 안내: 알파벳 순서로 공백 없이 쉼표로 구분됩니다. (예: ajackson,mjones,tmiller)
<details>
  <summary>hint#1</summary>
    Use aws:cloudtrail as the sourcetype.<br>
    sourcetype aws:cloudtrail에서 찾으세요
</details>
<details>
  <summary>hint#2</summary>
    Look at the values within the user_type field.
    user_type의 값을 보세요.
</details>

```
sourcetype=*aws:* *IAM*
```

user_agent field를 보면 IAMUser란 값이 보입니다.

![IAMUser]({{site.url}}/assets/built/images/bots/v3/2021-10-28-16-20-41.png)

user라는 필드가 눈에 띄니 보도록 합시다.

```
sourcetype=*aws* *IAM* user_type=IAMUser
| dedup user
| table user
| sort -user
```


|user|
|---|
|bstoll|
|btun|
|splunk_access|
|web_admin|

답 : bstoll,btun,splunk_access,web_admin

201	What field would you use to alert that AWS API activity have occurred without MFA (multi-factor authentication)? Answer guidance: Provide the full JSON path. (Example: iceCream.flavors.traditional)  
MFA(다중 요소 인증) 없이 AWS API 활동이 발생했음을 알리기 위해 어떤 필드를 사용하시겠습니까? 답변 안내: 전체 JSON 경로를 제공하세요. (예: iceCream.flavors.traditional)

<details>
  <summary>hint#1</summary>
    Use aws:cloudtrail as the sourcetype.<br>
    sourcetype aws:cloudtrail를 살펴보세요.
</details>
<details>
  <summary>hint#2</summary>
    Check out the AWS docs: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudwatch-alarms-for-cloudtrail-additional-examples.html#cloudwatch-alarms-for-cloudtrail-no-mfa-example <br>
    AWS 공식문서를 참고하세요. https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudwatch-alarms-for-cloudtrail-additional-examples.html#cloudwatch-alarms-for-cloudtrail-no-mfa-example
</details>
<details>
  <summary>hint#3</summary>
    Make sure you are not including console login activity.<br>
    콘솔 로그인 활동을 포함하지 않았는지 확인하십시오.
</details>

CloudTrail은 AWS 환경에서 수행 된 모든 작업의 로그입니다.

clouldtrail에서 MFA 관련 로그를 찾아봅시다.
```
sourcetype=aws:cloudtrail *MFA*
```

쿼리 결과를 보면 mfamfaAuthenticated라는 필드를 볼 수 있습니다.

![MFA]({{site.url}}/assets/built/images/bots/v3/2021-10-28-17-05-12.png)
![]({{site.url}}/assets/built/images/bots/v3/2021-10-28-17-09-40.png)

AWS 공식문서에 해당 필드가 MFA 사용여부를 확인하는 필드임을 확인할 수 있습니다.
![]({{site.url}}/assets/built/images/bots/v3/2021-10-28-17-10-16.png)

답 : userIdentity.sessionContext.attributes.mfaAuthenticated

202	What is the processor number used on the web servers? Answer guidance: Include any special characters/punctuation. (Example: The processor number for Intel Core i7-8650U is i7-8650U.)  
웹 서버에서 사용되는 프로세서 번호는 무엇입니까? 답변 안내: 특수 문자/문장부호를 포함하십시오. (예: Intel Core i7-8650U의 프로세서 번호는 i7-8650U입니다.)

<details>
  <summary>hint#1</summary>
    Use hardware as the sourcetype for hardware information such as CPU statistics, hard drives, network interface cards, memory, and more.<br>
    CPU 통계, 하드 드라이브, 네트워크 인터페이스 카드, 메모리 등과 같은 하드웨어 정보의 소스 유형으로 하드웨어를 사용합니다.
</details>

CPU 이름에 intel 혹은 amd가 포함되어있을테니 해당 키워드로 검색해봅니다.

```
intel OR amd
| stats count by sourcetype
```

|sourcetype|count|
|---|---|
|WinHostMon|	1916|
|aws:elb:accesslogs|	430|
|stream:http|	368|
|access_combined|	366|
|stream:mysql|	172|
|aws:rds:audit|	93|
|ms:o365:management|	63|
|wineventlog|	29|
|o365:management:activity|	18|
|syslog|	8|
|dmesg|	6|
|osquery:results|	4|
|aws:cloudwatchlogs|	3|
|hardware|	3|
|stream:udp|	2|
|stream:smtp|	1|

WinHostMon이 유력하지만, **hardware**라는 sourcetype이 눈에 띕니다.
해당 sourcetype으로 검색해봅니다.

```
intel OR amd sourcetype=hardware
```
CPU_TYPE필드 값은 다음과 같습니다. Intel(R) Xeon(R) CPU **E5-2676** v3 @ 2.40GHz

답 : E5-2676

203	Bud accidentally makes an S3 bucket publicly accessible. What is the event ID of the API call that enabled public access? Answer guidance: Include any special characters/punctuation.  
Bud가 실수로 S3 버킷에 공개적으로 액세스할 수 있도록 합니다. 공개 액세스를 활성화한 API 호출의 이벤트 ID는 무엇입니까? 답변 안내: 특수 문자/문장부호를 포함하십시오.
<details>
  <summary>hint#1</summary>
    Use aws:cloudtrail as the sourcetype.
    sourcetype aws:cloudtrail을 보세요.
</details>

설정관련 로그는 cloudtrail에 있을것입니다. s3를 키워드로 검색해봅니다.
```
sourcetype=aws:cloudtrail s3
```

field중에 eventName이 있습니다. 어떤 eventName이 있는지 봅시다.

```
sourcetype=aws:cloudtrail s3
| dedup eventName
| table eventName
```
설정하는 이벤트(Set이 포함된 이벤트이름 등)가 있을것입니다.

- 결과

|eventName|
|---|
|DescribeConfigRuleEvaluationStatus|
|DescribeConfigRules|
|GetBucketLocation|
|GetBucketCors|
|GetBucketTagging|
|GetBucketLifecycle|
|GetBucketLogging|
|ListBuckets|
|GetBucketEncryption|
|GetBucketVersioning|
|GetBucketPolicy|
|GetBucketAcl|
|GetComplianceDetailsByConfigRule|
|PutEvaluations|
|GetBucketRequestPayment|
|GetBucketReplication|
|GetBucketWebsite|
|GetBucketNotification|
|PutBucketAcl|
|DescribeLoadBalancerAttributes|

중간에 PutBucketAcl이란 이벤트 이름이 보입니다.
해당키워드로 검색해봅니다.

Grantee.URL을 보면 AllUsers란 게있습니다.
![Grantee.URL]({{site.url}}/assets/built/images/bots/v3/2021-10-28-22-46-22.png)

```
sourcetype="aws:cloudtrail" eventName="PutBucketAcl"
| table _time eventID requestParameters.AccessControlPolicy.AccessControlList.Grant{}.Grantee.URI requestParameters.AccessControlPolicy.AccessControlList.Grant{}.Permission
```

|_time|eventID|requestParameters.AccessControlPolicy.AccessControlList.Grant{}.Grantee.URI|requestParameters.AccessControlPolicy.AccessControlList.Grant{}.Permission|
|---|---|---|---|
|2018/08/20 13:57:54|9a33d8df-1e16-4d58-b36d-8e80ce68f8a3|http://acs.amazonaws.com/groups/s3/LogDelivery<br>http://acs.amazonaws.com/groups/s3/ogDelivery<br>http://acs.amazonaws.com/groups/s3/LogDelivery|FULL_CONTROL<br>WRITE<br>READ_ACP<br>READ<br>FULL_CONTROL|
|2018/08/20 13:01:46|ab45689d-69cd-41e7-8705-5350402cf7ac|http://acs.amazonaws.com/groups/s3/LogDelivery<br>http://acs.amazonaws.com/groups/s3/LogDelivery<br>http://cs.amazonaws.com/groups/s3/LogDelivery<br>http://acs.amazonaws.com/groups/global/AllUsers<br>http://acs.amazonaws.com/groups/global/AllUsers|FULL_CONTROL<br>WRITE<br>READ_ACP<br>READ<br>FULL_CONTROL<br>READ<br>WRITE|

AllUsers에 대한 READ, WRITE 권한이 2018/08/20 13:57:54에 빠졌습니다.

S3 Bucket이 모든사용자에게 공개된 시간은 2018/08/20 13:01:46 ~ 2018/08/20 13:57:54 입니다.
공개정책을 넣은 eventID는 **ab45689d-69cd-41e7-8705-5350402cf7ac**입니다.

답 : ab45689d-69cd-41e7-8705-5350402cf7ac

204	What is the name of the S3 bucket that was made publicly accessible?  
공개적으로 액세스할 수 있게 된 S3 버킷의 이름은 무엇입니까?
<details>
  <summary>hint#1</summary>
    Use aws:cloudtrail as the sourcetype.<br>
    sourcetype aws:cloudtrail에서 찾으세요.
</details>

https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_Trail.html
![s3bucketname]({{site.url}}/assets/built/images/bots/v3/2021-10-29-13-05-45.png)

splunk 로그에서는 S3BucketName이 아닌, bucketName 입니다.
203번문제에서 발생한 bucketName은 **frothlywebcode** 입니다.
![bucketName]({{site.url}}/assets/built/images/bots/v3/2021-10-29-13-13-35.png)

205	What is the name of the text file that was successfully uploaded into the S3 bucket while it was publicly accessible? Answer guidance: Provide just the file name and extension, not the full path. (Example: filename.docx instead of /mylogs/web/filename.docx)  
공개적으로 액세스할 수 있는 동안 S3 버킷에 성공적으로 업로드된 텍스트 파일의 이름은 무엇입니까? 답변 안내: 전체 경로가 아닌 파일 이름과 확장자만 제공하세요. (예: /mylogs/web/filename.docx 대신 filename.docx)
<details>
  <summary>hint#1</summary>
    Use aws:s3:accesslogs as the sourcetype.
</details>

sourctype중 **aws:s3:accesslogs**가 있습니다. 여기서 frothlywebcode로 업로드 된 텍스트 파일을 찾아봅시다.
검색범위를 줄이기 위해 aws:s3:accesslogs의 필드를 보니 요청 성공여부를 나타내는 http_status, 수행 함수를 뜻하는 opertaion필드가 있습니다.

http_status=200, REST.**PUT**.OBJECT 조건을 추가로 넣어 검색해봅니다.

```
sourcetype=aws:s3:accesslogs frothlywebcode http_status=200 operation="REST.PUT.OBJECT" .txt
```

![텍스트 파일]({{site.url}}/assets/built/images/bots/v3/2021-10-29-13-52-12.png)
**OPEN_BUCKET_PLEASE_FIX.txt**라는 이름의 텍스트 파일을 발견할 수 있습니다.

답 : OPEN_BUCKET_PLEASE_FIX.txt

206	What is the size (in megabytes) of the .tar.gz file that was successfully uploaded into the S3 bucket while it was publicly accessible? Answer guidance: Round to two decimal places without the unit of measure. Use 1024 for the byte conversion. Use a period (not a comma) as the radix character.  
공개적으로 액세스할 수 있는 동안 S3 버킷에 성공적으로 업로드된 .tar.gz 파일의 크기(MB)는 얼마입니까? 답변 안내: 측정 단위 없이 소수점 이하 두 자리까지 반올림합니다. 바이트 변환에 1024를 사용합니다. 기수 문자로 마침표(쉼표 아님)를 사용합니다.
<details>
  <summary>hint#1</summary>
    Use aws:s3:accesslogs as the sourcetype.<br>
    sourcetype aws:s3:accesslogs에서 찾으세요.
</details>
<details>
  <summary>hint#1</summary>
    Take a closer look at who made (or requested) the upload.
    누가 업로드를 했는지(또는 요청했는지) 자세히 살펴보세요.
</details>

공개된 시간은 2018/08/20 13:01:46 ~ 2018/08/20 13:57:54이므로, 해당 시간안에 .tar.gz 확장자의 파일이 업로드된 이벤트를 탐색해봅시다.

![]({{site.url}}/assets/built/images/bots/v3/2021-10-29-14-54-36.png)

```
sourcetype=aws:s3:accesslogs frothlywebcode http_status=200 operation="REST.PUT.OBJECT" .tar.gz
```

object_size 필드가 눈에 띕니다.
![object_size]({{site.url}}/assets/built/images/bots/v3/2021-10-29-14-55-18.png)
해당 값을 MiB(1024)로 변환해봅시다.

※ MiB (메비바이트 : mebibyte) :  
메비바이트는 1,024키비바이트, 220(10242 = 1,048,576)바이트를 뜻하는 정보의 단위이다.  

![데이터 변환]({{site.url}}/assets/built/images/bots/v3/2021-10-29-14-55-47.png)

답 : 2.93

*207 문제는 없습니다.*

208	A Frothly endpoint exhibits signs of coin mining activity. What is the name of the first process to reach 100 percent CPU processor utilization time from this activity on this endpoint? Answer guidance: Include any special characters/punctuation.  
Frothly 엔드포인트는 코인 채굴 활동의 징후를 보입니다. 이 끝점에서 이 활동에서 100% CPU 프로세서 사용 시간에 도달한 첫 번째 프로세스의 이름은 무엇입니까? 답변 안내: 특수 문자/문장부호를 포함하십시오.
<details>
  <summary>hint#1</summary>
    Use perfmonmk:process as the sourcetype.<br>
    sourcetype perfmonmk:process에서 조사하세요.
</details>
<details>
  <summary>hint#2</summary>
    Which browser was in use when this endpoint visited the coin mining site(s)?<br>
    이 엔드포인트가 코인 마이닝 사이트를 방문했을 때 어떤 브라우저가 사용 중이었습니까?
</details>

cpu를 포함한 process의 자원 사용률은 **PerfmonMk:Process**에서 찾을 수 있을것입니다. 자세한 사항은 splunk 홈페이지에서 확인 가능합니다.
[PerfmonMk:Process in splunk](https://docs.splunk.com/Documentation/WindowsAddOn/8.1.2/User/SourcetypesandCIMdatamodelinfo)

```
sourcetype=perfmonmk:process
```

해당 sourcetype에 **process_cpu_used_percent**와 **process_name**이라는 필드가 눈에 띕니다.
process_cpu_used_percent=100을 추가하고, process_name을 보도록합니다.

```
sourcetype=perfmonmk:process process_cpu_used_percent=100 process_name=*
| sort -_time
```


|_time|	process_name|	process_cpu_used_percent|
|---|---|---
|2018/08/20 09:36:26|	MicrosoftEdgeCP#2|	100|
|2018/08/20 13:37:50|	chrome#5|	100|
|2018/08/20 13:38:20|	chrome#5|	100|
....

제일먼저 cpu가 100%인 프로세스는 MicrosoftEdgeCP#2입니다. 하지만 답은 **chrome#5**입니다.
근거를 찾지 못하였으니 아시는 분은 댓글로 제보 바랍니다.

답 : chrome#5

209	When a Frothly web server EC2 instance is launched via auto scaling, it performs automated configuration tasks after the instance starts. How many packages and dependent packages are installed by the cloud initialization script? Answer guidance: Provide the number of installed packages then number of dependent packages, comma separated without spaces.  
Frothly 웹 서버 EC2 인스턴스가 Auto Scaling을 통해 시작되면 인스턴스가 시작된 후 자동화된 구성 작업을 수행합니다. 클라우드 초기화 스크립트에 의해 설치되는 패키지 및 종속 패키지는 몇 개입니까? 답변 안내: 설치된 패키지 수와 종속 패키지 수를 공백 없이 쉼표로 구분하여 제공하십시오.
<details>
  <summary>hint#1</summary>
    Use cloud-init-output as the sourcetype.
    sourcetype cloud-init-output를 조사해보세요.
</details>
<details>
  <summary>hint#1</summary>
    Check out the AWS docs: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/user-data.html#user-data-cloud-init
    AWS 공식문서를 참고하세요 : https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/user-data.html#user-data-cloud-init
</details>

문제에서 auto scaling을 수행하면 인스턴스가 시작된 후 자동화 작업을 시작한다는 설명이 있습니다.
인스턴스 시작관련 로그는 [clould-init](https://zetawiki.com/wiki/Cloud-init)에 있습니다.

could-init과 관련된 sourcetype은 cloud-init과 cloud-init-output이 있습니다.  
두 sourcetype 모두 조사해보도록 합시다.
packages와 dependent를 키워드로 두고 검색해봅니다.

```
sourcetype=cloud-init* *packages* *dependent*
```

![쿼리수행결과]({{site.url}}/assets/built/images/bots/v3/2021-10-29-16-28-10.png)

로그를 확인하면 **Install  7 Packages (+13 Dependent packages)** 7개의 패키지와, 13개의 의존 패키지가 설치된 사실을 파악할 수 있습니다.

답 : 7,13

210	What is the short hostname of the only Frothly endpoint to actually mine Monero cryptocurrency? (Example: ahamilton instead of ahamilton.mycompany.com)  
실제로 Monero 암호화폐를 채굴하는 유일한 Frothly 엔드포인트의 짧은 호스트 이름은 무엇입니까? (예: ahamilton.mycompany.com 대신 ahamilton)
<details>
  <summary>hint#1</summary>
    What is the most common browser-based cryptominer?<br>
    가장 일반적인 브라우저 기반 크립토마이너는 무엇입니까?
</details>
<details>
  <summary>hint#2</summary>
    Can you find DNS traffic with evidence of a common browser-based cryptomining technology?<br>
    일반적인 브라우저 기반 크립토마이닝 기술의 증거로 DNS 트래픽을 찾을 수 있습니까?
</details>
<details>
  <summary>hint#3</summary>
    Is there a laptop that communicates successfully to coinhive servers?<br>
    coinhive 서버와 성공적으로 통신하는 노트북이 있습니까?
</details>

```

```

211	How many cryptocurrency mining destinations are visited by Frothly endpoints?
<details>
  <summary>hint#1</summary>
    Use stream:dns as the sourcetype.
</details>

212	Using Splunk's event order functions, what is the first seen signature ID of the coin miner threat according to Frothly's Symantec Endpoint Protection (SEP) data?
<details>
  <summary>hint#1</summary>
    
</details>

213	According to Symantec's website, what is the severity of this specific coin miner threat?
<details>
  <summary>hint#1</summary>
    
</details>

214	What is the short hostname of the only Frothly endpoint to show evidence of defeating the cryptocurrency threat? (Example: ahamilton instead of ahamilton.mycompany.com)
<details>
  <summary>hint#1</summary>
    
</details>

215	What is the FQDN of the endpoint that is running a different Windows operating system edition than the others?
<details>
  <summary>hint#1</summary>
    
</details>

216	According to the Cisco NVM flow logs, for how many seconds does the endpoint generate Monero cryptocurrency? Answer guidance: Round to the nearest second without the unit of measure.
<details>
  <summary>hint#1</summary>
    
</details>

217	What kind of Splunk visualization was in the first file attachment that Bud emails to Frothly employees to illustrate the coin miner issue? Answer guidance: Two words. (Example: choropleth map)
<details>
  <summary>hint#1</summary>
    
</details>

218	What IAM user access key generates the most distinct errors when attempting to access IAM resources?
<details>
  <summary>hint#1</summary>
    
</details>

219	Bud accidentally commits AWS access keys to an external code repository. Shortly after, he receives a notification from AWS that the account had been compromised. What is the support case ID that Amazon opens on his behalf?
<details>
  <summary>hint#1</summary>
    
</details>

220	AWS access keys consist of two parts: an access key ID (e.g., AKIAIOSFODNN7EXAMPLE) and a secret access key (e.g., wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY). What is the secret access key of the key that was leaked to the external code repository?
<details>
  <summary>hint#1</summary>
    
</details>

221	Using the leaked key, the adversary makes an unauthorized attempt to create a key for a specific resource. What is the name of that resource? Answer guidance: One word.
<details>
  <summary>hint#1</summary>
    
</details>

222	Using the leaked key, the adversary makes an unauthorized attempt to describe an account. What is the full user agent string of the application that originated the request?
<details>
  <summary>hint#1</summary>
    
</details>

223	The adversary attempts to launch an Ubuntu cloud image as the compromised IAM user. What is the codename for that operating system version in the first attempt? Answer guidance: Two words.
<details>
  <summary>hint#1</summary>
    
</details>

224	Frothly uses Amazon Route 53 for their DNS web service. What is the average length of the distinct third-level subdomains in the queries to brewertalk.com? Answer guidance: Round to two decimal places. (Example: The third-level subdomain for my.example.company.com is example.)
<details>
  <summary>hint#1</summary>
    
</details>

225	Using the payload data found in the memcached attack, what is the name of the .jpeg file that is used by Taedonggang to deface other brewery websites? Answer guidance: Include the file extension.
<details>
  <summary>hint#1</summary>
    
</details>

300	What is the full user agent string that uploaded the malicious link file to OneDrive?
<details>
  <summary>hint#1</summary>
    
</details>

301	What external client IP address is able to initiate successful logins to Frothly using an expired user account?
<details>
  <summary>hint#1</summary>
    
</details>

302	According to Symantec's website, what is the discovery date of the malware identified in the macro-enabled file? Answer guidance: Provide the US date format MM/DD/YY. (Example: January 1, 2019 should be provided as 01/01/19)
<details>
  <summary>hint#1</summary>
    
</details>

303	What is the password for the user that was successfully created by the user "root" on the on-premises Linux system?
<details>
  <summary>hint#1</summary>
    
</details>

304	What is the name of the user that was created after the endpoint was compromised?
<details>
  <summary>hint#1</summary>
    
</details>

305	What is the process ID of the process listening on a "leet" port?
<details>
  <summary>hint#1</summary>
    
</details>

306	A search query originating from an external IP address of Frothly's mail server yields some interesting search terms. What is the search string?
<details>
  <summary>hint#1</summary>
    
</details>

307	What is the MD5 value of the file downloaded to Fyodor's endpoint system and used to scan Frothly's network?
<details>
  <summary>hint#1</summary>
    
</details>

308	Based on the information gathered for question 304, what groups was this user assigned to after the endpoint was compromised? Answer guidance: Comma separated without spaces, in alphabetical order.
<details>
  <summary>hint#1</summary>
    
</details>

309	At some point during the attack, a user's domain account is disabled. What is the email address of the user whose account gets disabled and what is the email address of the user who disabled their account? Answer guidance: Comma separated without spaces, in alphabetical order. (Example: jdoe@mycompany.com,tmiller@mycompany.com)
<details>
  <summary>hint#1</summary>
    
</details>

310	Another set of phishing emails were sent to Frothly employees after the adversary gained a foothold on a Frothly computer. This malicious content was detected and left behind a digital artifact. What is the name of this file? Answer guidance: Include the file extension. (Example: badfile.docx)
<details>
  <summary>hint#1</summary>
    
</details>

311	Based on the answer to question 310, what is the name of the executable that was embedded in the malware? Answer guidance: Include the file extension. (Example: explorer.exe)
<details>
  <summary>hint#1</summary>
    
</details>

312	How many unique IP addresses "used" the malicious link file that was sent?  
<details>
  <summary>hint#1</summary>
    
</details>

313문제도 없네요

314	What port number did the adversary use to download their attack tools?
<details>
  <summary>hint#1</summary>
    
</details>

315	During the attack, two files are remotely streamed to the /tmp directory of the on-premises Linux server by the adversary. What are the names of these files? Answer guidance: Comma separated without spaces, in alphabetical order, include the file extension where applicable.
<details>
  <summary>hint#1</summary>
    
</details>

316	Based on the information gathered for question 314, what file can be inferred to contain the attack tools? Answer guidance: Include the file extension.
<details>
  <summary>hint#1</summary>
    
</details>

317	What is the first executable uploaded to the domain admin account's compromised endpoint system? Answer guidance: Include the file extension.
<details>
  <summary>hint#1</summary>
    
</details>

318	From what country is a small brute force or password spray attack occurring against the Frothly web servers?
<details>
  <summary>hint#1</summary>
    
</details>

319	The adversary created a BCC rule to forward Frothly's email to his personal account. What is the value of the "Name" parameter set to?
<details>
  <summary>hint#1</summary>
    
</details>

320	What is the password for the user that was created on the compromised endpoint?
<details>
  <summary>hint#1</summary>
    
</details>

321	The Taedonggang adversary sent Grace Hoppy an email bragging about the successful exfiltration of customer data. How many Frothly customer emails were exposed or revealed?
<details>
  <summary>hint#1</summary>
    
</details>

322	What is the path of the URL being accessed by the command and control server? Answer guidance: Provide the full path. (Example: The full path for the URL https://imgur.com/a/mAqgt4S/lasd3.jpg is /a/mAqgt4S/lasd3.jpg)
<details>
  <summary>hint#1</summary>
    
</details>

323	At least two Frothly endpoints contact the adversary's command and control infrastructure. What are their short hostnames? Answer guidance: Comma separated without spaces, in alphabetical order.
<details>
  <summary>hint#1</summary>
    
</details>

324	Who is Al Bungstein's cell phone provider/carrier? Answer guidance: Two words.
<details>
  <summary>hint#1</summary>
    
</details>

325	Microsoft cloud services often have a delay or lag between "index time" and "event creation time". For the entire day, what is the max lag, in minutes, for the sourcetype: ms:aad:signin? Answer guidance: Round to the nearest minute without the unit of measure.
<details>
  <summary>hint#1</summary>
    
</details>

326	According to Mallory's advertising research, how is beer meant to be enjoyed? Answer guidance: One word.
<details>
  <summary>hint#1</summary>
    
</details>

327도 문제 없습니다.

328	What text is displayed on line 2 of the file used to escalate tomcat8's permissions to root? Answer guidance: Provide contents of the entire line.
<details>
  <summary>hint#1</summary>
    
</details>

329	One of the files uploaded by Taedonggang contains a word that is a much larger in font size than any other in the file. What is that word?
<details>
  <summary>hint#1</summary>
    
</details>

330	What Frothly VPN user generated the most traffic? Answer guidance: Provide the VPN user name.
<details>
  <summary>hint#1</summary>
    
</details>

331	Using Splunk commands only, what is the upper fence (UF) value of the interquartile range (IQR) of the count of event code 4688 by Windows hosts over the entire day? Use a 1.5 multiplier. Answer guidance: UF = Q3 + 1.5 x IQR
<details>
  <summary>hint#1</summary>
    
</details>

332	What is the CVE of the vulnerability that escalated permissions on Linux host hoth? Answer guidance: Submit in normal CVE format. (Example: cve-2018-9805)
<details>
  <summary>hint#1</summary>
    
</details>

333	What is the CVE of the vulnerability that was exploited to run commands on Linux host hoth? Answer guidance: Submit in normal CVE format. (Example: cve-2018-9805)
<details>
  <summary>hint#1</summary>
    
</details>