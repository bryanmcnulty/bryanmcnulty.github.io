---
title: "HTB • Halloween Invitation"
tags:
  - "Easy Difficulty"
  - "Beginner"
  - "Blue Team"
  - "Forensics"
  - "Visual Basic"
  - "PowerShell"
  - "Malware Analysis"
  - "Malicious Document"
  - "Office Macros"
  - "Deobfuscation"
excerpt: "Halloween Invitation is an easy forensics challenge on Hack the Box that involves the analysis of a malicious Microsoft Office document. The products used to solve this challenge include CyberChef and oledump.py from the Didier Stevens Suite."
categories:
  - "Writeups"
  - "Hack the Box Challenges"
---

Halloween Invitation is an easy forensics challenge created by [**P3t4**](https://app.hackthebox.com/users/23) on [**Hack the box**](https://app.hackthebox.com/challenges/halloween-invitation) that involves the analysis of a malicious Microsoft Office document. The products used to solve this challenge include CyberChef and oledump.py from the Didier Stevens Suite.

> An email notification pops up. It's from your theater group. Someone decided to throw a party. The invitation looks awesome, but there is something suspicious about this document. Maybe you should take a look before you rent your banana costume.

## OLEDump

We will first check the document we are given for malicious macros using `oledump.py` from the [DidierStevensSuite](https://github.com/DidierStevens/DidierStevensSuite) repository on GitHub.

```bash
oledump.py ./invitation.docm
```
{:.nolineno}
>
```
A: word/vbaProject.bin
 A1:       416 'PROJECT'
 A2:        65 'PROJECTwm'
 A3: M    1532 'VBA/Module1'
 A4: M   19739 'VBA/ThisDocument'
 A5:      3900 'VBA/_VBA_PROJECT'
 A6:       659 'VBA/dir'
```
{:.nolineno}

It looks like this document contains macros in streams `A3` and `A4` which is indicated by the capital 'M'. Let's extract the source for these two streams.

```bash
oledump.py ./invitation.docm -v -s A3 > A3.vba
oledump.py ./invitation.docm -v -s A4 > A4.vba
```
{:.nolineno}

Now we have two source files that we can begin to analyze.

## VBA Deobfuscation

The code in these files appears to be obfuscated, but we can tell that the code in `A4.vba`{:.filepath} is assembling an encoded command to use with PowerShell. We also notice a bunch of hex strings being concatenated in the code so we decide to concatenate them ourselves.

```bash
cat ./A4.vba |
  tail -72 |
  head -55 |
  sed 's/^[^"]*"//;s/"[^"]*$//;s/"[^"]*"//' |
  sed -z 's/\n/20/g'
```
{:.nolineno}

Now we should have a super long hex string that we can plug into [CyberChef](https://gchq.github.io/CyberChef/) to decode.

![CyberChef input](/assets/img/post/htb-challenges-halloween-invitation/cyberchef.png)
_We enter the hex string into CyberChef's web interface_

The decoded product looks like some space-separated decimal bytes, so I'll add another operation called **From Decimal**. Now the decoded product of the this operation looks like base64 so we'll add another layer, this time **From Base64**. After this operation we finally get some kinda-readable text but it is using UTF-16 encoding so we remove the extra null bytes with the **Remove null bytes** operation.

![CyberChef decode](/assets/img/post/htb-challenges-halloween-invitation/cyberchef-2.png)
_We successfully decode the hex string into a line of powershell code_

Our final product is some powershell code with the flag at the very end of it.
