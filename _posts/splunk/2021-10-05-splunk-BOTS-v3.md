---
layout: post
current: post
cover:  assets/built/images/bots-v3.jpg
navigation: True
title: splunk-bots-v3 write up
date: '2021-10-05 20:04:36 +0530'
tags: [splunk]
class: post-template
subclass: 'post tag-splunk'
author: wind-flow
---
{% include bots-table-of-contents.html %}

BOTS-V3

200	List out the IAM users that accessed an AWS service (successfully or unsuccessfully) in Frothly's AWS environment? Answer guidance: Comma separated without spaces, in alphabetical order. (Example: ajackson,mjones,tmiller)

201	What field would you use to alert that AWS API activity have occurred without MFA (multi-factor authentication)? Answer guidance: Provide the full JSON path. (Example: iceCream.flavors.traditional)

202	What is the processor number used on the web servers? Answer guidance: Include any special characters/punctuation. (Example: The processor number for Intel Core i7-8650U is i7-8650U.)

203	Bud accidentally makes an S3 bucket publicly accessible. What is the event ID of the API call that enabled public access? Answer guidance: Include any special characters/punctuation.

204	What is the name of the S3 bucket that was made publicly accessible?

205	What is the name of the text file that was successfully uploaded into the S3 bucket while it was publicly accessible? Answer guidance: Provide just the file name and extension, not the full path. (Example: filename.docx instead of /mylogs/web/filename.docx)

206	What is the size (in megabytes) of the .tar.gz file that was successfully uploaded into the S3 bucket while it was publicly accessible? Answer guidance: Round to two decimal places without the unit of measure. Use 1024 for the byte conversion. Use a period (not a comma) as the radix character.

207문제는 없네요

208	A Frothly endpoint exhibits signs of coin mining activity. What is the name of the first process to reach 100 percent CPU processor utilization time from this activity on this endpoint? Answer guidance: Include any special characters/punctuation.

209	When a Frothly web server EC2 instance is launched via auto scaling, it performs automated configuration tasks after the instance starts. How many packages and dependent packages are installed by the cloud initialization script? Answer guidance: Provide the number of installed packages then number of dependent packages, comma separated without spaces.

210	What is the short hostname of the only Frothly endpoint to actually mine Monero cryptocurrency? (Example: ahamilton instead of ahamilton.mycompany.com)

211	How many cryptocurrency mining destinations are visited by Frothly endpoints?

212	Using Splunk's event order functions, what is the first seen signature ID of the coin miner threat according to Frothly's Symantec Endpoint Protection (SEP) data?

213	According to Symantec's website, what is the severity of this specific coin miner threat?

214	What is the short hostname of the only Frothly endpoint to show evidence of defeating the cryptocurrency threat? (Example: ahamilton instead of ahamilton.mycompany.com)

215	What is the FQDN of the endpoint that is running a different Windows operating system edition than the others?

216	According to the Cisco NVM flow logs, for how many seconds does the endpoint generate Monero cryptocurrency? Answer guidance: Round to the nearest second without the unit of measure.

217	What kind of Splunk visualization was in the first file attachment that Bud emails to Frothly employees to illustrate the coin miner issue? Answer guidance: Two words. (Example: choropleth map)

218	What IAM user access key generates the most distinct errors when attempting to access IAM resources?

219	Bud accidentally commits AWS access keys to an external code repository. Shortly after, he receives a notification from AWS that the account had been compromised. What is the support case ID that Amazon opens on his behalf?

220	AWS access keys consist of two parts: an access key ID (e.g., AKIAIOSFODNN7EXAMPLE) and a secret access key (e.g., wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY). What is the secret access key of the key that was leaked to the external code repository?

221	Using the leaked key, the adversary makes an unauthorized attempt to create a key for a specific resource. What is the name of that resource? Answer guidance: One word.

222	Using the leaked key, the adversary makes an unauthorized attempt to describe an account. What is the full user agent string of the application that originated the request?

223	The adversary attempts to launch an Ubuntu cloud image as the compromised IAM user. What is the codename for that operating system version in the first attempt? Answer guidance: Two words.

224	Frothly uses Amazon Route 53 for their DNS web service. What is the average length of the distinct third-level subdomains in the queries to brewertalk.com? Answer guidance: Round to two decimal places. (Example: The third-level subdomain for my.example.company.com is example.)

225	Using the payload data found in the memcached attack, what is the name of the .jpeg file that is used by Taedonggang to deface other brewery websites? Answer guidance: Include the file extension.

300	What is the full user agent string that uploaded the malicious link file to OneDrive?

301	What external client IP address is able to initiate successful logins to Frothly using an expired user account?

302	According to Symantec's website, what is the discovery date of the malware identified in the macro-enabled file? Answer guidance: Provide the US date format MM/DD/YY. (Example: January 1, 2019 should be provided as 01/01/19)

303	What is the password for the user that was successfully created by the user "root" on the on-premises Linux system?

304	What is the name of the user that was created after the endpoint was compromised?

305	What is the process ID of the process listening on a "leet" port?

306	A search query originating from an external IP address of Frothly's mail server yields some interesting search terms. What is the search string?

307	What is the MD5 value of the file downloaded to Fyodor's endpoint system and used to scan Frothly's network?

308	Based on the information gathered for question 304, what groups was this user assigned to after the endpoint was compromised? Answer guidance: Comma separated without spaces, in alphabetical order.

309	At some point during the attack, a user's domain account is disabled. What is the email address of the user whose account gets disabled and what is the email address of the user who disabled their account? Answer guidance: Comma separated without spaces, in alphabetical order. (Example: jdoe@mycompany.com,tmiller@mycompany.com)

310	Another set of phishing emails were sent to Frothly employees after the adversary gained a foothold on a Frothly computer. This malicious content was detected and left behind a digital artifact. What is the name of this file? Answer guidance: Include the file extension. (Example: badfile.docx)

311	Based on the answer to question 310, what is the name of the executable that was embedded in the malware? Answer guidance: Include the file extension. (Example: explorer.exe)

312	How many unique IP addresses "used" the malicious link file that was sent?  
313문제도 없네요

314	What port number did the adversary use to download their attack tools?

315	During the attack, two files are remotely streamed to the /tmp directory of the on-premises Linux server by the adversary. What are the names of these files? Answer guidance: Comma separated without spaces, in alphabetical order, include the file extension where applicable.

316	Based on the information gathered for question 314, what file can be inferred to contain the attack tools? Answer guidance: Include the file extension.

317	What is the first executable uploaded to the domain admin account's compromised endpoint system? Answer guidance: Include the file extension.

318	From what country is a small brute force or password spray attack occurring against the Frothly web servers?

319	The adversary created a BCC rule to forward Frothly's email to his personal account. What is the value of the "Name" parameter set to?

320	What is the password for the user that was created on the compromised endpoint?

321	The Taedonggang adversary sent Grace Hoppy an email bragging about the successful exfiltration of customer data. How many Frothly customer emails were exposed or revealed?

322	What is the path of the URL being accessed by the command and control server? Answer guidance: Provide the full path. (Example: The full path for the URL https://imgur.com/a/mAqgt4S/lasd3.jpg is /a/mAqgt4S/lasd3.jpg)

323	At least two Frothly endpoints contact the adversary's command and control infrastructure. What are their short hostnames? Answer guidance: Comma separated without spaces, in alphabetical order.

324	Who is Al Bungstein's cell phone provider/carrier? Answer guidance: Two words.

325	Microsoft cloud services often have a delay or lag between "index time" and "event creation time". For the entire day, what is the max lag, in minutes, for the sourcetype: ms:aad:signin? Answer guidance: Round to the nearest minute without the unit of measure.

326	According to Mallory's advertising research, how is beer meant to be enjoyed? Answer guidance: One word.
327도..

328	What text is displayed on line 2 of the file used to escalate tomcat8's permissions to root? Answer guidance: Provide contents of the entire line.

329	One of the files uploaded by Taedonggang contains a word that is a much larger in font size than any other in the file. What is that word?

330	What Frothly VPN user generated the most traffic? Answer guidance: Provide the VPN user name.

331	Using Splunk commands only, what is the upper fence (UF) value of the interquartile range (IQR) of the count of event code 4688 by Windows hosts over the entire day? Use a 1.5 multiplier. Answer guidance: UF = Q3 + 1.5 x IQR

332	What is the CVE of the vulnerability that escalated permissions on Linux host hoth? Answer guidance: Submit in normal CVE format. (Example: cve-2018-9805)

333	What is the CVE of the vulnerability that was exploited to run commands on Linux host hoth? Answer guidance: Submit in normal CVE format. (Example: cve-2018-9805)

{% gist moon9342/d37bb68b8a51c21d4fe6d1b03dfdfa3e %}
