---
layout: post
current: post
cover:  assets/built/images/blockchain/NFT/NFT.jpg
navigation: True
title: [Hackerrank - paris]
date: 2021-11-04 09:22:00+0900
tags: [blockchain, NFT]
class: post-template
subclass: 'post tag-splunk'
author: wind-flow
---

[문제링크](https://www.hackerrank.com/challenges/pairs/problem)
설명 : 주어진 배열의 원소들의 차 중 타겟넘버(k)를 만들 수 있는 순서 쌍의 갯수를 구하는 문제입니다.

풀이 전략 : 배열의 각 원소에 k를 더해 결과값이 arr에 있는지 확인해봅니다.

# 전략 1
``` python
def pairs(k, arr):
    cnt = 0

    targetNumList = set([item + k for item in set(arr)])

    for i in arr:
        if i in targetNumList:
            cnt += 1
    
    return cnt
```
   

# 개선된 코드
``` python
def pairs(k, arr):
    return len(set(arr) & set([item + k for item in set(arr)]))
```