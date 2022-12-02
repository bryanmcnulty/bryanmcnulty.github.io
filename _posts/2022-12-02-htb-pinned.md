---
title: "HTB - Pinned"
excerpt: "Hack The Box Challenges • Mobile • Easy"
layout: "htb_challenge"
htb:
  challenge:
    name: "Pinned"
    url: "https://app.hackthebox.com/challenges/pinned"
  difficulty: "Easy"
  category: "Mobile"
  author:
    - name: "bertolis"
      url: "https://app.hackthebox.com/users/27897"
---

> This app has stored my credentials and I can only login automatically. I tried to intercept the login request and restore my password, but this seems to be a secure connection. Can you help bypass this security restriction and intercept the password in plaintext?


## Introduction

For this challenge we are given an APK package called `pinned.apk` and a text file called `README.txt`. The challenge description explains that the subject has their credentials stored in this APK application. It also ends with a question implying that we will not conduct any static analysis and we will be bypassing some security measures. Finally, the `README.txt` file contains a message stating that we must install the application on a device running Android 10.0 or any version with API level 29 or earlier.

## Genymotion

We will use [Genymotion](https://www-v1.genymotion.com/download-trial/) to create and interact with an Android virtual machine. 

### Creating a Virtual Machine

First we open Genymotion on our desktop and press `Ctrl+N` to create a new virtual machine. Then we select `Google Pixel 3` from the menu and verify that `Android version` is set to `10.0.0`. Once that is done, we click `NEXT` and assign the hardware resources for the VM. We can keep the default configuration for the Display options and Android options then install the VM.

### Installing Applications

To install the `pinned.apk` application, we boot the VM then use the `adb` program.

```bash
$ sudo apt-get install adb # install adb
$ adb install pinned.apk
```

Once this is done, we can open the new app by navigating to our VM's screen and clicking `Pinned` in the app menu.

![pinned-app](/assets/images/htb-challenges/pinned/pinned-app.png)

## BurpSuite

### Proxy Setup

Let's set up [BurpSuite](https://portswigger.net/burp) to try to intercept any traffic sent by this application. First we go t o `Proxy > Options > Proxy Listeners > Add` and check `All interfaces` then click `OK` and enable interception in the `Proxy` tab.

### Connect to Proxy

To connect to the proxy we run a command on the guest device to change the global setting `http_proxy` to the address of the host machine's proxy server.

```bash
$ lhost="192.168.1.2" # Change me
$ lport="8080"
$ adb root
$ adb shell "settings put global http_proxy $lhost:$lport"
```

This should temporarily connect the guest device to the BurpSuite proxy.

Now when we open the app and click `LOGIN` we get an error on the burpsuite dashboard claiming that the secure connection to pinned.com:443 failed. This could mean that the application implements [certificate pinning](https://owasp.org/www-community/controls/Certificate_and_Public_Key_Pinning)

## Bypassing Certificate Pinning

To bypass the certificate pinning in this instance we will use a dynamic code instrumentation framework known as [Frida](https://github.com/frida/frida)

### Starting the Server

We first download and extract the frida server executable for our target OS and architecture.

```bash
$ target_os="android"
$ target_arch="$(adb shell 'getprop ro.product.cpu.abi')"
$ binary="frida-server-16.0.6-$target_os-$target_arch.xz"
$ wget "https://github.com/frida/frida/releases/download/16.0.6/$binary"
$ unxz $binary
```

Then we upload the binary to the android filesystem and run it.

```bash
$ location="/data/local/tmp/frida"
$ adb push ./frida-server* "$location"
$ adb shell "chmod +x $location"
$ adb shell "$location" &
```

### Universal Pinning Bypass Script

We will be using [this script](https://codeshare.frida.re/@pcipolloni/universal-android-ssl-pinning-bypass-with-frida/) alongside frida to effectively bypass certificate pinning. This script expects our custom certificate at `/data/local/temp/cert-der.crt` which will be BurpSuite's certificate in DER format.

Once we have exported BurpSuite's certificate we upload it to the expected location.

```bash
$ adb push ./burp.crt "/data/local/tmp/cert-der.crt"
```

Now we will locate the identifier for the application.

```bash
frida-ps -U -ai | grep -i "pinned"
```
```
3192  Pinned  com.example.pinned
```

The identifier for the suspected process is `com.example.pinned`. Let's run frida with the bypass script on this process.

```bash
frida -U \
  --codeshare "pcipolloni/universal-android-ssl-pinning-bypass-with-frida" \
  -f "com.example.pinned"
```

Now when we click `LOGIN` on the open window in the virtual machine we successfully intercept the login attempt with the flag.

![](/assets/images/htb-challenges/pinned/burpsuite.png)