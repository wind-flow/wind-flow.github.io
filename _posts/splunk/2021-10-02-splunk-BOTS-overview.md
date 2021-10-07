---
layout: post
current: post
cover:  assets/built/images/bots-v1.jpg
navigation: True
title: splunk-bots 개론
date: '2021-10-02 20:04:36 +0530'
tags: [splunk]
class: post-template
subclass: 'post tag-splunk'
author: wind-flow
---

## Splunk SOC 대회인 BOSS OF THE SOC(BOTS)

{% include bots-table-of-contents.html %}

# BOTS란 ?

Boss of the SOC (BOTS) 대회는 Splunk를 활용, 제한 시간 동안 해커들의 침입으로 발생한 보안 사고를 해결하는 보안 전문가들의 대회입니다. 매일 발생하는 실제 보안 사고 시나리오를 바탕으로 Splunk의 모든 보안 솔루션(Splunk User Behavior analytics, Splunk Enterprise Security, Splunk Phantom)을 활용하여 보안 사고에 방어해야 합니다.

[BOTS 대회 안내](https://events.splunk.com/Splunk-Korea-2020-BOTS-Day)

대회 출전에 앞서 필요한 데이터 발췌에 유용한 검색 기법을 소개하고자 합니다.
# Sourcetype 한눈에 보기
```
| metadata type=sourcetypes index=botsv1
| stats values(sourcetype)
```

![sourcetype 검색 쿼리]({{site.url}}/assets/built/images/bots/overview/sourcetypequery.jpg)

metadata 명령어에 대해선 [이 링크](https://docs.splunk.com/Documentation/SplunkCloud/latest/SearchReference/metadata)를 참고하세요

# Field와 Vaule 한눈에 보기

1. 설정 클릭 후 고급검색을 누릅니다.
![고급검색]({{site.url}}/assets/built/images/bots/overview/fieldbrief.jpg)

2. 검색 매크로 옆 ```+새로 추가```를 누릅니다.
![매크로 추가#1]({{site.url}}/assets/built/images/bots/overview/createMacro-1.jpg)

3. 아래 쿼리를 fieldbrief란 이름의 매크로로 저장합니다.
```
| fieldsummary
| search values!="[]"
| fields field values
| rex field=values max_match=0 "\{\"value\":\"(?<extract_values>[^\"]+)\""
| fields field extract_values
| eval extract_values=mvdedup(extract_values)
```

![매크로 추가#2]({{site.url}}/assets/built/images/bots/overview/createMacro-2.jpg)

4. 조회할 sourcetype을 기재 후 `fieldsbreif`를 추가하면 아래와 같이 field와 값들을 한눈에 볼 수 있습니다.
![매크로 추가#2]({{site.url}}/assets/built/images/bots/overview/macroResult.jpg)

# LookUp file 조회

splunk에 어떤 데이터들이 import되었는지 조회할 수 있는 쿼리입니다.

```
| rest /servicesNS/-/-/data/lookup-table-files
```

V1의 115번 문제를 풀때 Coldplay의 노래제목 데이터가 필요합니다.
115	One of the passwords in the brute force attack is James Brodsky's favorite Coldplay song. Hint: we are looking for a six character word on this one. Which is it?  
coldplay 노래 데이터를 lookup파일 형태로 제공하고 있는지 위 쿼리로 조회를 해볼 수 있습니다.

![csv파일 조회]({{site.url}}/assets/built/images/bots/overview/csvFileSearch..jpg)
