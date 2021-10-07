---
layout: post
current: post
cover:  assets/built/images/bots-v2.jpg
navigation: True
title: splunk-bots-v2 write up
date: '2021-10-04 20:04:36 +0530'
tags: [splunk]
class: post-template
subclass: 'post tag-splunk'
author: wind-flow
---
{% include bots-table-of-contents.html %}

100	Amber Turing was hoping for Frothly to be acquired by a potential competitor which fell through, but visited their website to find contact information for their executive team. What is the website domain that she visited? Answer guidance: Do not provide the FQDN. Answer example: google.com

101	Amber found the executive contact information and sent him an email. What is the CEO's name? Provide the first and last name.

102	After the initial contact with the CEO, Amber contacted another employee at this competitor. What is that employee's email address?

103	What is the name of the file attachment that Amber sent to a contact at the competitor?

104	What is Amber's personal email address?

105	What version of TOR did Amber install to obfuscate her web browsing? Answer guidance: Numeric with one or more delimiter.

200	What is the public IPv4 address of the server running www.brewertalk.com?

201	Provide the IP address of the system used to run a web vulnerability scan against www.brewertalk.com.

202	The IP address from question 201 is also being used by a likely different piece of software to attack a URI path. What is the URI path? Answer guidance: Include the leading forward slash in your answer. Do not include the query string or other parts of the URI. Answer example: /phpinfo.php

203	What SQL function is being abused on the uri path from question 202?

204	What is Frank Ester's password salt value on www.brewertalk.com?

205	What is user btun's password on brewertalk.com?

206	What are the characters displayed by the XSS probe? Answer guidance: Submit answer in native language or character set.

207	What was the value of the cookie that Kevin's browser transmitted to the malicious URL as part of a XSS attack? Answer guidance: All digits. Not the cookie name or symbols like an equal sign.

208	The brewertalk.com web site employed Cross Site Request Forgery (CSRF) techniques. What was the value of the anti-CSRF token that was stolen from Kevin Lagerfield's computer and used to help create an unauthorized admin user on brewertalk.com?

209	What brewertalk.com username was maliciously created by a spearphishing attack?

300	According to Frothly's records, what is the likely MAC address of Mallory's corporate MacBook? Answer guidance: Her corporate MacBook has the hostname MACLORY-AIR13.

301	What episode of Game of Thrones is Mallory excited to watch? Answer guidance: Submit the HBO title of the episode.

302	What is Mallory Krauesen's phone number? Answer guidance: ddd-ddd-dddd where d=[0-9]. No country code.

303	Enterprise Security contains a threat list notable event for MACLORY-AIR13 and suspect IP address 5.39.93.112. What is the name of the threatlist (i.e. Threat Group) that is triggering the notable?

304	Considering the threatlist you found in the question above, and related data, what protocol often used for file transfer is actually responsible for the generated traffic?

305	Mallory's critical PowerPoint presentation on her MacBook gets encrypted by ransomware on August 18. At what hour, minute, and second does this actually happen? Answer guidance: Provide the time in PDT. Use the 24h format HH:MM:SS, using leading zeroes if needed. Do not use Splunk's _time (index time).

~~~
PDT(Pacific Daylight Time)
출처 : https://luran.me/339
~~~

306	How many seconds elapsed between the time the ransomware executable was written to disk on MACLORY-AIR13 and the first local file encryption? Answer guidance: Use the index times (_time) instead of other timestamps in the events.

307	Kevin Lagerfield used a USB drive to move malware onto kutekitten, Mallory's personal MacBook. She ran the malware, which obfuscates itself during execution. Provide the vendor name of the USB drive Kevin likely used. Answer Guidance: Use time correlation to identify the USB drive.

308	What programming language is at least part of the malware from the question above written in?

309	The malware from the two questions above appears as a specific process name in the process table when it is running. What is it?

310	The malware infecting kutekitten uses dynamic DNS destinations to communicate with two C&C servers shortly after installation. What is the fully-qualified domain name (FQDN) of the first (alphabetically) of these destinations?

311	From the question above, what is the fully-qualified domain name (FQDN) of the second (alphabetically) contacted C&C server?

312	What is the average Alexa 1M rank of the domains between August 18 and August 19 that MACLORY-AIR13 tries to resolve while connected via VPN to the corporate network? Answer guidance: Round to two decimal places. Remember to include domains with no rank in your average! Answer example: 3.23 or 223234.91

313	Two .jpg-formatted photos of Mallory exist in Kevin Lagerfield's server home directory that have eight-character file names, not counting the .jpg extension. Both photos were encrypted by the ransomware. One of the photos can be downloaded at the following link, replacing 8CHARACTERS with the eight characters from the file name. https://splunk.box.com/v/8CHARACTERS After you download the file to your computer, decrypt the file using the encryption key used by the ransomware. What is the complete line of text in the photo, including any punctuation? Answer guidance: The encryption key can be found in Splunk.

400	A Federal law enforcement agency reports that Taedonggang often spearphishes its victims with zip files that have to be opened with a password. What is the name of the attachment sent to Frothly by a malicious Taedonggang actor?

401	The Taedonggang APT group encrypts most of their traffic with SSL. What is the "SSL Issuer" that they use for the majority of their traffic? Answer guidance: Copy the field exactly, including spaces.

402	Threat indicators for a specific file triggered notable events on two distinct workstations. What IP address did both workstations have a connection with?

403	Based on the IP address found in question 402, what domain of interest is associated with that IP address?

404	What unusual file (for an American company) does winsys32.dll cause to be downloaded into the Frothly environment?

405	What is the first and last name of the poor innocent sap who was implicated in the metadata of the file that executed PowerShell Empire on the first victim's workstation? Answer example: John Smith

406	What is the average Shannon entropy score of the subdomain containing UDP-exfiltrated data? Answer guidance: Cut off, not rounded, to the first decimal place. Answer examples: 3.2 or 223234.9

407	To maintain persistence in the Frothly network, Taedonggang APT configured several Scheduled Tasks to beacon back to their C2 server. What single webpage is most contacted by these Scheduled Tasks? Answer guidance: Remove the path and type a single value with an extension. Answer example: index.php or images.html

408	The APT group Taedonggang is always building more infrastructure to attack future victims. Provide the IPV4 IP address of a Taedonggang controlled server that has a completely different first octet to other Taedonggang controlled infrastructure. Answer guidance: 4.4.4.4 has a different first octet than 8.4.4.4

409	The Taedonggang group had several issues exfiltrating data. Determine how many bytes were successfully transferred in their final, mostly successful attempt to exfiltrate files via a method using TCP, using only the data available in Splunk logs. Use 1024 for byte conversion.

500	Individual clicks made by a user when interacting with a website are associated with each other using session identifiers. You can find session identifiers in the stream:http sourcetype. The Frothly store website session identifier is found in one of the stream:http fields and does not change throughout the user session. What session identifier is assigned to dberry398@mail.com when visiting the Frothly store for the very first time? Answer guidance: Provide the value of the field, not the field name.

501	How many unique user ids are associated with a grand total order of $1000 or more?

502	Which user, identified by their email address, edited their profile before placing an order over $1000 in the same clickstream? Answer guidance: Provide the user ID, not other values found from the profile edit, such as name.

503	What street address was used most often as the shipping address across multiple accounts, when the billing address does not match the shipping address? Answer example: 123 Sesame St

504	What is the domain name used in email addresses by someone creating multiple accounts on the Frothly store website (http://store.froth.ly) that appear to have machine-generated usernames?

505	Which user ID experienced the most logins to their account from different IP address and user agent combinations? Answer guidance: The user ID is an email address.

506	What is the most popular coupon code being used successfully on the site?

507	Several user accounts sharing a common password is usually a precursor to undesirable scenario orchestrated by a fraudster. Which password is being seen most often across users logging into http://store.froth.ly.

508	Which HTML page was most clicked by users before landing on http://store.froth.ly/magento2/checkout/ on August 19th? Answer guidance: Use earliest=1503126000 and latest=1503212400 to identify August 19th. Answer example: http://store.froth.ly/magento2/bigbrew.html

509	Which HTTP user agent is associated with a fraudster who appears to be gaming the site by unsuccessfully testing multiple coupon codes?