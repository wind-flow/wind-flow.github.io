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
2016년 8월 24일 we8105desk의 가장 가능성이 높아 보이는 IP 주소는 무엇입니까?
<details>
  <summary>hint#1</summary>
  Keep it simple and just search for the hostname provided in the question.  Try using the stats command to get a count of events by source ip address to point you in the right direction.<br>
  
  간단하게 유지하고 질문에 제공된 호스트 이름을 검색하십시오. stats 명령을 사용하여 소스 IP 주소별로 이벤트 수를 가져와 올바른 방향으로 조사해 보세요.
</details>

hostname이 we8105desk 키워드로 어떤 sourcetype에 가장 많이 있을지 조사해본다.

```
we8105desk 
| stats count by sourcetype
```

|sourcetype|count|
|---|---|
|XmlWinEventLog:Microsoft-Windows-Sysmon/Operational|130354|
|wineventlog|49006|
|stream:smb	|1529|
|stream:ldap	|74|
|nessus:scan	|24|
|stream:dns	|20|
|WinRegistry	|3|
|suricata	  |2|

여러 sourcetype에서 해당 호스트의 있을것으로 예상되지만, 그중 원격 접속인 smb sourcetype에 IP관련 필드가 있을것 같다.

```
we8105desk   sourcetype="stream:smb"
```

IP를 파악하기위해 smb에 눈여겨볼만한 field는 src_ip, dest_ip, path를 확인해보면 된다.

```
we8105desk sourcetype="stream:smb"
| dedup src_ip dest_ip path
| table src_ip dest_ip path
```


|src_ip|dest_ip|path|
|---|---|---|
|192.168.2.50	|192.168.250.100|	\\WE8105DESK\IPC$
|192.168.2.50	|192.168.250.100|	\\WE8105DESK\C$
|192.168.2.50	|192.168.250.100|	\\WE8105DESK\c$
|192.168.2.50 |	192.168.250.100|	\\WE8105DESK\ROOT
|192.168.2.50	|192.168.250.100|	\\WE8105DESK\D$
|192.168.2.50	|192.168.250.100|	\\WE8105DESK\WINNT$
|192.168.2.50	|192.168.250.100|	\\WE8105DESK\ADMIN$
|192.168.2.50	|192.168.250.100|	\\WE8105DESK\LOGS$
|192.168.2.50	|192.168.250.100|	\\WE8105DESK\ARCSERVE$
|192.168.250.100|	192.168.2.50|	\\WE8105DESK\IPC$

path의 host가 모두 WE8105DESK니, 해당 PC의 IP는 192.168.250.100일 가능성이 제일 높다.

답 : 192.168.250.100

201	Amongst the Suricata signatures that detected the Cerber malware, which one alerted the fewest number of times? Submit ONLY the signature ID value as the answer. (No punctuation, just 7 integers.)  
Cerber 악성코드를 탐지한 Suricata 시그니처 중 가장 적게 경고한 것은? 서명 ID 값만 답변으로 제출하십시오. (구두점은 없고 7개의 정수만 있습니다.)

<details>
  <summary>hint#1</summary>
  Keep it simple and start your search by looking at only the sourcetype associated with Suricata and maybe even the name of the malware in question.  The field containing the signature ID should be obvious.  Use stats to create a count by the field containing the signature ID.<br>

  단순하게 유지하고 Suricata와 연결된 소스 유형만 보고 심지어 문제의 맬웨어 이름까지 살펴봄으로써 검색을 시작하십시오. 서명 ID가 포함된 필드는 명확해야 합니다. 통계를 사용하여 서명 ID가 포함된 필드로 개수를 만듭니다.
</details>

suricata에서 cerber(케르베르스) 관련 이벤트가 있는지 검색해봅시다.
```
sourcetype=suricata *cerber*
```

alert.signature_id라는 필드가 눈에 띕니다
![alert.signature_id]({{site.url}}/assets/built/images/bots/v1/2021-10-15-16-55-44.png)

가장 적은 signature id는 2816763 입니다.

답 : 2816763

202	What fully qualified domain name (FQDN) does the Cerber ransomware attempt to direct the user to at the end of its encryption phase?  
Cerber 랜섬웨어는 암호화 단계가 끝나면 어떤 FQDN(정규화된 도메인 이름)을 사용자에게 지시합니까?

<details>
  <summary>hint#1</summary>
  Search stream:dns data for A queries coming from the infected workstation IP on the date in question.  Try and narrow your search period.<br>
  해당 날짜에 감염된 워크스테이션 IP에서 오는 A 쿼리에 대한 검색 stream:dns 데이터. 검색 기간을 좁혀 보십시오.
</details>

<details>
  <summary>hint#2</summary>
  Perform a shannon entropy analysis on the query{} field using URL toolbox by adding this to the end of the search: |`ut_shannon(query{})` | stats count by ut_shannon, query{} | sort -ut_shannon<br>
  
  다음을 검색 끝에 추가하여 URL 도구 상자를 사용하여 쿼리 필드에서 shannon 엔트로피 분석을 수행합니다. |`ut_shannon(query{})` | stats count by ut_shannon, query{} | sort -ut_shannon
</details>

8/24일에 WE8105DESK(192.168.250.100)가 cerber 랜섬웨어에 걸렸으므로, 이 호스트가 DNS서버에 질의했을것 입니다.

url 질의 DNS 쿼리 타입은 A타입입니다.  
- [DNS 쿼리 타입](https://ko.wikipedia.org/wiki/DNS_%EB%A0%88%EC%BD%94%EB%93%9C_%ED%83%80%EC%9E%85_%EB%AA%A9%EB%A1%9D)

(검색 기간8/24일로 설정)
```
sourcetype=stream:DNS src=192.168.250.100 record_type=A
| dedup query
| table query
```

- 결과  

|query|
|---|
|crl.microsoft.com<br>crl.microsoft.com|
|wpad<br>wpad|
|we9041srv.waynecorpinc.local<br>we9041srv.waynecorpinc.local|
|isatap<br>isatap|
|isatap.waynecorpinc.local<br>isatap.waynecorpinc.local|
|www.microsoft.com<br>www.microsoft.com|
|wpad.waynecorpinc.local<br>wpad.waynecorpinc.local|
|cerberhhyed5frqa.xmfir0.win<br>cerberhhyed5frqa.xmfir0.win|
|www.bing.com<br>www.bing.com|
|go.microsoft.com<br>go.microsoft.com|
|shell.windows.com<br>shell.windows.com|
|activation.sls.microsoft.com<br>activation.sls.microsoft.com|
|ipinfo.io<br>ipinfo.io|
|solidaritedeproximite.org<br>solidaritedeproximite.org|
|dns.msftncsi.com<br>dns.msftncsi.com|

위 검색결과 중 cerber키워드가 들어간 cerberhhyed5frqa.xmfir0.win가 답입니다.

답 : cerberhhyed5frqa.xmfir0.win

203	What was the first suspicious domain visited by we8105desk on 24AUG2016?  
2016년 8월 24일 we8105desk가 처음으로 방문한 의심스러운 도메인은 무엇입니까?

<details>
  <summary>hint#1</summary>
  Search stream:dns data for A queries coming from the infected workstation IP on the date in question.<br>
  query Type이 A인 stream:dns를 조사하여 해당 날짜에 감염된 워크스테이션 IP를 분석해보세요.
</details>
<details>
  <summary>hint#2</summary>
  Use the "| reverse" SPL command to show oldest events first.<br>
  "| reverse" SPL 명령을 사용하여 가장 오래된 이벤트를 먼저 표시합니다.
</details>
<details>
  <summary>hint#3</summary>
  Eliminate domain lookups that you can explain, question the first one you cannot.<br>
  설명할 수 있는 도메인 조회를 제거하고 첫 번째 질문에 질문하십시오.
</details>
<details>
  <summary>hint#4</summary>
  Go and git some IOCs on Cerber.  Then compare to the DNS Data<br>
  Cerber에 가서 IOC를 가져오세요. 그런 다음 DNS 데이터와 비교하십시오.
</details>

we8105desk src ip(192.168.250.100)를 조건을 추가한 stream:http sourcetype에 url관련 정보가 있을 것입니다.

```
src=192.168.250.100 sourcetype="stream:http"
| sort _time
| dedup _time url
| table _time url
```

- 결과  

|_time|url|
|---|---|
|2016/08/24 16:34:27.004|http://crl.microsoft.com/pki/crl/products/microsoftrootcert.crl|
|2016/08/24 16:34:31.660|	http://crl.microsoft.com/pki/crl/products/|MicCodSigPCA_08-31-2010.crl|
|2016/08/24 16:34:36.317|	http://crl.microsoft.com/pki/crl/products/CodeSigPCA.crl|
2016/08/24 16:34:40.943|	http://crl.microsoft.com/pki/crl/products/CodeSignPCA2.crl|
2016/08/24 16:34:45.589|	http://crl.microsoft.com/pki/crl/products/WinPCA.crl|
2016/08/24 16:34:50.301|	http://www.microsoft.com/pki/CRL/products/Microsoft%20Windows%20Hardware%20Compatibility%20PCA(1).crl|
2016/08/24 16:48:13.285|	http://solidaritedeproximite.org/mhtr.jpg|
2016/08/24 16:48:14.620|	http://92.222.104.182/mhtr.jpg|
2016/08/24 16:49:24.504|	http://ipinfo.io/json|
2016/08/24 16:53:21.344|	http://go.microsoft.com/fwlink/|
2016/08/24 16:53:26.936|	http://go.microsoft.com/fwlink/|

URL중 microsoft, ipinfo는 유명한 URL이지만 solidaritedeproximite.org는 알려지지 않은 URL이므로 의심 할 수 있습니다.

답 : solidaritedeproximite.org

204	During the initial Cerber infection a VB script is run. The entire script from this execution, pre-pended by the name of the launching .exe, can be found in a field in Splunk. What is the length in characters of the value of this field?  
초기 Cerber 감염 동안 VB 스크립트가 실행됩니다. 시작하는 .exe의 이름이 앞에 추가된 이 실행의 전체 스크립트는 Splunk의 필드에서 찾을 수 있습니다. 이 필드 값의 문자 길이는 얼마입니까?
<details>
  <summary>hint#1</summary>
  Keep it simple.  Start by looking at sysmon data for the infected device on the date in question.  Calculate the length of the command line using the "len()" function of the "eval" SPL command, and give your eyes a break by using the splunk table command. <br>
  간단하게 생각하세요. 해당 날짜에 감염된 장치에 대한 sysmon 데이터를 확인하여 시작합니다. "eval" SPL 명령의 "len()" 함수를 사용하여 명령줄의 길이를 계산하고 splunk table 명령을 사용하여 시각화 합니다.
</details>

205	What is the name of the USB key inserted by Bob Smith?  
Bob Smith가 삽입한 USB 키의 이름은 무엇입니까?
<details>
  <summary>hint#1</summary>
  Tough question.  Perhaps you should give http://answers.splunk.com a try.<br>
  어려운 문제입니다. http://answer.splunk.com을 사용해 보십시오.
</details>
USB의 이름은 friendlyname 컬럼에 저장되어있습니다. 해당값은 registry에 저장되어있으므로 sourcetype은 WinRegistry 입니다.

[FriendlyName이란?](https://en.wiktionary.org/wiki/friendly_name)

```
friendlyname
```
- 결과  
```
08/24/2016 10:42:17.287  
event_status="(0)The operation completed successfully."  
pid=708  
process_image="c:\Windows\System32\svchost.exe"  
registry_type="SetValue"  
key_path="HKLM\system\controlset001\enum\wpdbusenumroot\umb\2&37c186b&0&storage#volume#_??_usbstor#disk&ven_generic&prod_flash_disk&rev_8.07#7d961196&0#\friendlyname"  
data_type="REG_SZ"  
data="MIRANDA_PRI"  
host=we8105desk source=WinRegistry sourcetype=WinRegistry
```

registry의 data값이 MIRANDA_PRI임을 알수 있습니다.

답 : MIRANDA_PRI

206	Bob Smith's workstation (we8105desk) was connected to a file server during the ransomware outbreak. What is the IP address of the file server?  
Bob Smith의 워크스테이션(we8105desk)은 랜섬웨어가 발생하는 동안 파일 서버에 연결되었습니다. 파일 서버의 IP 주소는 무엇입니까?

<details>
  <summary>hint#1</summary>
  Search for SMB (Windows file sharing protocol) traffic from the infected device on the date in question. The "stats" SPL command can be used to count the most common destination IP for the SMB protocol.  
  해당 날짜에 감염된 장치에서 SMB(Windows 파일 공유 프로토콜) 트래픽을 검색합니다. "stats" SPL 명령은 SMB 프로토콜에 대한 가장 일반적인 대상 IP를 계산하는 데 사용할 수 있습니다.
</details>

이 질문은 207, 209를 풀면 더 쉽게 알 수 있습니다.
207번 질문에서 원격 파일 서버의 pdf가 암호화되었다고 했으니, 검색해보면
hostname은 we9041srv.waynecorpinc.local, IP는 192.168.250.20인것을 알 수 있습니다.

답 : 192.168.250.20

207	How many distinct PDFs did the ransomware encrypt on the remote file server?  
랜섬웨어는 원격 파일 서버에서 얼마나 많은 개별 PDF를 암호화했습니까?

<details>
  <summary>hint#1</summary>
  Don't use SMB this time - it's a trap!  Windows event logs are the way to go for this one.  Focus on the event types that deal with windows shares and narrow the search by looking for distinct filenames for the extension in question.<br>
  이번에는 SMB를 사용하지 마십시오. 함정입니다! Windows 이벤트 로그는 이를 위한 방법입니다. Windows 공유를 처리하는 이벤트 유형에 집중하고 해당 확장에 대한 고유한 파일 이름을 찾아 검색 범위를 좁힙니다.
</details>

pdf 확장자를 검색해봅니다.

```
.pdf
```
![pdf확장자]({{site.url}}/assets/built/images/bots/v1/2021-10-18-17-48-58.png)

파일이 암호화되었다면 eventlog에 파일생성, 파일 변경 등의 로그가 있을것입니다.

sourcetype=wineventlog

we9041srv.waynecorpinc.local

208	The VBscript found in question 204 launches 121214.tmp. What is the ParentProcessId of this initial launch?  
문제 204에서 찾은 VBscript는 121214.tmp를 시작합니다. 이 초기 실행의 ParentProcessId는 무엇입니까?

<details>
  <summary>hint#1</summary>
  Embrace your sysmon data.  Search for a command issued by the infected device on the date in question referencing the filename in question, and use the process_id, ParentProcessId, CommandLine,  and ParentCommandLine, to track down the parent process id of them all.<br> 
  sysmon 데이터를 수용하십시오. 해당 파일 이름을 참조하여 해당 날짜에 감염된 장치에서 실행된 명령을 검색하고 process_id, ParentProcessId, CommandLine 및 ParentCommandLine을 사용하여 모두의 상위 프로세스 ID를 추적합니다.
</details>

parentprocessid는 sysmon에서 찾을 수 있습니다.

```
sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" 121214.tmp
| where isnotnull(parent_process_id)
| table _time parent_process_id ParentCommandLine process_id CommandLine 
| sort _time
```

|_time|parent_process_id|ParentCommandLine|process_id|CommandLine|
|---|---|---|---|---|
|2016/08/24 16:48:21|	1476|	"C:\Windows\System32\cmd.exe" /C START "" "C:\Users\bob.smith.WAYNECORPINC\AppData\Roaming\121214.tmp"	|2948|	"C:\Users\bob.smith.WAYNECORPINC\AppData\Roaming\121214.tmp"|
|2016/08/24 16:48:21|	3968|	"C:\Windows\System32\WScript.exe" "C:\Users\bob.smith.WAYNECORPINC\AppData\Roaming\20429.vbs"	|1476|	"C:\Windows\System32\cmd.exe" /C START "" "C:\Users\bob.smith.WAYNECORPINC\AppData\Roaming\121214.tmp"
|2016/08/24 16:48:29|	2948|	"C:\Users\bob.smith.WAYNECORPINC\AppData\Roaming\121214.tmp"|	3828|	"C:\Users\bob.smith.WAYNECORPINC\AppData\Roaming\121214.tmp"|
|2016/08/24 16:48:41|	1280|	/d /c taskkill /t /f /im "121214.tmp" &gt; NUL &amp; ping -n 1 127.0.0.1 &gt; NUL &amp; del "C:\Users\bob.smith.WAYNECORPINC\AppData\Roaming\121214.tmp" &gt; NUL	|1684|	taskkill  /t /f /im "121214.tmp"|
|2016/08/24 16:48:41|	3828|	"C:\Users\bob.smith.WAYNECORPINC\AppData\Roaming\121214.tmp"|	1280|	/d /c taskkill /t /f /im "121214.tmp" &gt; NUL &amp; ping -n 1 127.0.0.1 &gt; NUL &amp; del "C:\Users\bob.smith.WAYNECORPINC\AppData\Roaming\121214.tmp" &gt; NUL
|2016/08/24 16:48:41|	3828|	"C:\Users\bob.smith.WAYNECORPINC\AppData\Roaming\121214.tmp"|	3836	"C:\Users\bob.smith.WAYNECORPINC\AppData\Roaming\{35ACA89F-933F-6A5D-2776-A3589FB99832}\osk.exe"
|2016/08/24 16:48:42|	1280|	/d /c taskkill /t /f /im "121214.tmp" &gt; NUL &amp; ping -n 1 127.0.0.1 &gt; NUL &amp; del "C:\Users\bob.smith.WAYNECORPINC\AppData\Roaming\121214.tmp" &gt; NUL	|556|	ping  -n 1 127.0.0.1|

209	The Cerber ransomware encrypts files located in Bob Smith's Windows profile. How many .txt files does it encrypt?  
Cerber 랜섬웨어는 Bob Smith의 Windows 프로필에 있는 파일을 암호화합니다. 얼마나 많은 .txt 파일을 암호화합니까?

<details>
  <summary>hint#1</summary>
  Sysmon to the rescue again.  Focus on the infected machine as well as the user profile while searching for the filename extension in question.
  Sysmon에서 다시 찾읍시다. 문제의 파일 이름 확장자를 검색하는 동안 감염된 시스템과 사용자 프로필에 집중하십시오.
</details>
<details>
  <summary>hint#2</summary>
  In Sysmon events, EventCode=2 indicates file creation time has changed. Watch out for duplicates!<br>
  Sysmon 이벤트에서 EventCode=2는 파일 생성 시간이 변경되었음을 나타냅니다. 중복에 주의하세요!
</details>

```
.txt host=we8105desk
```

210	The malware downloads a file that contains the Cerber ransomware cryptor code. What is the name of that file?

<details>
  <summary>hint#1</summary>
  When looking for potentially malicious file, start your search with the Suricata data.  Narrow your search by focusing on the infected device. Remember malware does not always have to begin as an executable file.  
</details>

211	Now that you know the name of the ransomware's encryptor file, what obfuscation technique does it likely use?

<details>
  <summary>hint#1</summary>
  The enrcyptor file was an image!  
</details>
