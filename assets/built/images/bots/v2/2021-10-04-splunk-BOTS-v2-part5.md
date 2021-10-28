---
layout: post
current: post
cover:  assets/built/images/bots/v2/bots-v2.jpg
navigation: True
title: splunk-bots-v2 write up(5) - END
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

500	Individual clicks made by a user when interacting with a website are associated with each other using session identifiers. You can find session identifiers in the stream:http sourcetype. The Frothly store website session identifier is found in one of the stream:http fields and does not change throughout the user session. What session identifier is assigned to dberry398@mail.com when visiting the Frothly store for the very first time? Answer guidance: Provide the value of the field, not the field name.  
웹 사이트와 상호 작용할 때 사용자가 만든 개별 클릭은 세션 식별자를 사용하여 서로 연결됩니다. stream:http sourcetype에서 세션 식별자를 찾을 수 있습니다. Frothly 상점 웹사이트 세션 식별자는 stream:http 필드 중 하나에서 찾을 수 있으며 사용자 세션 전체에서 변경되지 않습니다. Frothly 스토어를 처음 방문할 때 dberry398@mail.com에 할당된 세션 식별자는 무엇입니까? 답변 안내: 필드 이름이 아닌 필드 값을 제공하십시오.

<details>
  <summary>hint#1</summary>
    Find the source IP address that our user of interest is using, then broaden your search such that you can view all events specific to the user's src ip address.<br>
    관심 사용자가 사용하고 있는 소스 IP 주소를 찾은 다음 사용자의 src IP 주소와 관련된 모든 이벤트를 볼 수 있도록 검색을 확장하십시오.
</details>
<details>
  <summary>hint#2</summary>
    HTTP cookies often contain information specific to a user session, including session identifiers.<br>
    HTTP 쿠키는 종종 세션 식별자를 포함하여 사용자 세션에 특정한 정보를 포함합니다.
</details>
<details>
  <summary>hint#3</summary>
    After you get the events specific to the user's src ip address, you can append a '| reverse |table cookie' to get a better view of the cookies that the user clicked.<br>
    사용자의 src IP 주소와 관련된 이벤트를 얻은 후 '|reverse |table cookie'를 사용하여 사용자가 클릭한 쿠키를 더 잘 볼 수 있습니다.
</details>

보통 seesion정보는 cookie필드에 있으므로, decode해서 해당 값을 봅시다.

```
sourcetype=stream:http dberry398@mail.com
| eval decoded=urldecode(cookie)
| table decoded
```


|decoded|
|---|
|store=default; mage-translation-storage={}; mage-translation-file-version={}; form_key=lwh9Ql7oUbnJUqxR; PHPSESSID=o6fc5a2rdoufmb8en8bqvfbav2; mage-cache-storage={}; mage-cache-storage-section-invalidation={}; recently_viewed_product={}; recently_viewed_product_previous={}; recently_compared_product={}; recently_compared_product_previous={}; product_data_storage={}; section_data_ids={"cart":1502757091,"customer":null,"messages":null,"compare-products":null,"product_data_storage":null}; private_content_version=837d56d7fe0264712bb5f12adacd2dc5; mage-messages=[{"type":"success","text":"Thank you for registering with Main Website Store."}]; X-Magento-Vary=20b556236a9f73d55ee9ffb5a21ffc45a5f6d878|
|store=default; mage-translation-storage={}; mage-translation-file-version={}; PHPSESSID=mlhg4l49hi8hn93b2abtr75j42; form_key=lwh9Ql7oUbnJUqxR; mage-cache-storage={}; mage-cache-storage-section-invalidation={}; recently_viewed_product={}; recently_viewed_product_previous={}; recently_compared_product={}; recently_compared_product_previous={}; product_data_storage={}; mage-cache-sessid=true; mage-messages=; private_content_version=becda8344cf560edfa267a78a663f962; X-Magento-Vary=9bf9a599123e6402b85cde67144717a08b817412; section_data_ids={"cart":1502756249,"customer":1502756125,"compare-products":1502756125,"product_data_storage":1502756125,"last-ordered-items":1502756125,"directory-data":1502756126,"review":1502756125,"wishlist":1502756125,"recently_viewed_product":1502756125,"recently_compared_product":1502756125,"paypal-billing-agreement":1502756125}|

두개 이벤트 중 값이 같고, session값으로 보이는 항목은 **form_key**입니다.

답 : lwh9Ql7oUbnJUqxR

501	How many unique user ids are associated with a grand total order of $1000 or more?  
총 주문 금액이 $1000 이상인 고유 사용자 ID는 몇 개입니까?

<details>
  <summary>hint#1</summary>
    When a user fills out a web form passing information such as username, password, credit card numbers, etc., it's passed via a standard http field (form_data) which is captured by stream:http. Extract the username from that field and store it in a new field.<br>
    사용자가 사용자 이름, 암호, 신용 카드 번호 등과 같은 정보를 전달하는 웹 양식을 작성하면 stream:http에 의해 캡처되는 표준 http 필드(form_data)를 통해 전달됩니다. 해당 필드에서 사용자 이름을 추출하고 새 필드에 저장합니다.
</details>
<details>
  <summary>hint#2</summary>
    You're going to need to look deeper into the packet at a field called dest_content to extract the grand order total. Look for the following string and use it in a regular expression to capture the value: 'grand_total'.<br>
    총 주문량을 추출하려면 dest_content라는 필드에서 패킷을 더 깊이 조사해야 합니다. 다음 문자열을 찾아 정규식에서 사용하여 값을 캡처합니다. 'grand_total'.
</details>
<details>
  <summary>hint#3</summary>
    The 'stats' command is useful for helping you to link several pieces of context together that occur within a single clickstream.<br>
    'stats' 명령은 단일 클릭스트림 내에서 발생하는 여러 컨텍스트를 함께 연결하는 데 유용합니다.
</details>

주문금액을 묻는걸 보아하니 웹관련 이벤트인 stream:http에서 해당데이터를 찾을 수 있을것으로 생각됩니다.
```
sourcetype=stream:http dberry398@mail.com
| rex field=dest_content "\"USD\",\"grand_total\":\"(?<gtotal>\w+).\S+\"," 
| where gtotal >= 1000
| rex field=cookie "; form_key=(?<sess_id>\w+); PHPSESSID=" 
```

502	Which user, identified by their email address, edited their profile before placing an order over $1000 in the same clickstream? Answer guidance: Provide the user ID, not other values found from the profile edit, such as name.  
이메일 주소로 식별되는 어떤 사용자가 동일한 클릭스트림에서 $1000 이상 주문하기 전에 프로필을 수정했습니까? 답변 안내: 이름과 같이 프로필 편집에서 찾은 다른 값이 아닌 사용자 ID를 제공합니다.
<details>
  <summary>hint#1</summary>

</details>

503	What street address was used most often as the shipping address across multiple accounts, when the billing address does not match the shipping address? Answer example: 123 Sesame St

<details>
  <summary>hint#1</summary>

</details>

504	What is the domain name used in email addresses by someone creating multiple accounts on the Frothly store website (http://store.froth.ly) that appear to have machine-generated usernames?

<details>
  <summary>hint#1</summary>

</details>

505	Which user ID experienced the most logins to their account from different IP address and user agent combinations? Answer guidance: The user ID is an email address.

<details>
  <summary>hint#1</summary>

</details>

506	What is the most popular coupon code being used successfully on the site?

<details>
  <summary>hint#1</summary>

</details>

507	Several user accounts sharing a common password is usually a precursor to undesirable scenario orchestrated by a fraudster. Which password is being seen most often across users logging into http://store.froth.ly.

<details>
  <summary>hint#1</summary>

</details>

508	Which HTML page was most clicked by users before landing on http://store.froth.ly/magento2/checkout/ on August 19th? Answer guidance: Use earliest=1503126000 and latest=1503212400 to identify August 19th. Answer example: http://store.froth.ly/magento2/bigbrew.html

<details>
  <summary>hint#1</summary>

</details>

509	Which HTTP user agent is associated with a fraudster who appears to be gaming the site by unsuccessfully testing multiple coupon codes?

<details>
  <summary>hint#1</summary>

</details>