---
title: "HTB - Halloween Invitation"
excerpt: "Hack The Box Challenges • Forensics • Easy"
layout: "htb_challenge"
htb:
  challenge:
    name: "Halloween Invitation"
    url: "https://app.hackthebox.com/challenges/halloween-invitation"
  difficulty: "Easy"
  category: "Forensics"
  author:
    - name: "P3t4"
      url: "https://app.hackthebox.com/users/23"
---

> An email notification pops up. It's from your theater group. Someone decided to throw a party. The invitation looks awesome, but there is something suspicious about this document. Maybe you should take a look before you rent your banana costume.

## OLEDump

We will first check the document we are given for malicious macros using `oledump.py` from the [DidierStevensSuite](https://github.com/DidierStevens/DidierStevensSuite) repository on GitHub.

```bash
$ oledump.py ./invitation.docm
```
```
A: word/vbaProject.bin
 A1:       416 'PROJECT'
 A2:        65 'PROJECTwm'
 A3: M    1532 'VBA/Module1'
 A4: M   19739 'VBA/ThisDocument'
 A5:      3900 'VBA/_VBA_PROJECT'
 A6:       659 'VBA/dir'
```

It looks like this document contains macros in streams `A3` and `A4` which is indicated by the capital 'M'. Let's extract the source for these two streams.

```bash
$ oledump.py ./invitation.docm -v -s A3 > A3.vba
$ oledump.py ./invitation.docm -v -s A4 > A4.vba
```

Now we have two source files that we can begin to analyze.

## VBA Deobfuscation

The code in these files appears to be obfuscated, but we can tell that the code in `A4.vba` is assembling an encoded command to use with PowerShell.

We also notice a bunch of hex strings being concatenated in the code so we decide to do this step ourselves.

```bash
$ cat ./A4.vba |
  tail -72 |
  head -55 |
  sed 's/^[^"]*"//;s/"[^"]*$//;s/"[^"]*"//' |
  sed -z 's/\n/20/g'
```

Now we should have a super long hex string that we can plug into [CyberChef](https://gchq.github.io/CyberChef/) to decode.

![](/assets/images/htb-challenges/halloween-invitation/cyberchef.png)

The decoded product looks like some space-separated decimal bytes, so I'll add another operation called `From Decimal`. Now the decoded product of the this operation looks like base64 so we'll add another operation called `From Base64`. After this operation we finally get some kinda-readable text but it is using UTF-16 encoding so we remove the null bytes with the `Remove null bytes` operation.

![](/assets/images/htb-challenges/halloween-invitation/cyberchef-2.png)

Our final product is some powershell code with the flag at the very end of it.
