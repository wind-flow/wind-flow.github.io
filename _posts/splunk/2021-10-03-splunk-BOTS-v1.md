---
layout: post
current: post
cover:  assets/built/images/splunk-logo.png
navigation: True
title: splunk-bots-v1 write up
date: '2021-10-03 20:04:36 +0530'
tags: [splunk]
class: post-template
subclass: 'post tag-splunk'
author: wind-flow
---

## Splunk SOC 대회인 BOTS 풀이를 작성
{% include bots-table-of-contents.html %}

![록히드마틴 사이버킬체인 7단계]({{site.baseurl}}/cyberkillchain.jpg)
```
index=botsv1 imreallynotbatman.com sourcetype=stream:http http_method=POST
```
