## Splunk SOC 대회인 BOTS 풀이를 작성

![록히드마틴 사이버킬체인 7단계]({{site.baseurl}}/cyberkillchain.jpg)

```
index=botsv1 imreallynotbatman.com sourcetype=stream:http http_method=POST
```