---
title: "HTB • APKrypt"
tags:
  - "Easy Difficulty"
  - "Beginner"
  - "Mobile"
  - "Android"
  - "Reversing"
  - "Static Analysis"
  - "APK"
  - "Java"
  - "Cryptography"
excerpt: "APKrypt is an easy mobile challenge on Hack the Box that involves reverse-engineering via static analysis, android APK apps, and Cryptography."
categories:
  - "Writeups"
  - "Hack the Box Challenges"
---

APKrypt is an easy mobile created by [**bertolis**](https://app.hackthebox.com/users/27897) on [**Hack The Box**](https://app.hackthebox.com/challenges/APKrypt) that involves reverse-engineering an android app to find a key along with an encrypted string which we use to recover the flag.

> Can you get the ticket without the VIP code?

## Static Analysis

For this challenge, we'll perform some static analysis on `APKrypt.apk`{:.filepath} with [APKTool](https://github.com/iBotPeaches/Apktool) and [JD-GUI](https://github.com/java-decompiler/jd-gui).

### APKTool

We decompress and decode the APK file with the following command:

```bash
apktool decode "APKrypt.apk"{:.filepath}
```
{:.nolineno}

### Dex2jar

We'll use the `d2j-smali` utility from [dex2jar](https://github.com/pxb1988/dex2jar) to compile each _SMALI_ into a single _DEX_ file.

```bash
cd "./APKrypt/smali/com/example/apkrypt"
d2j-smali *
```
{:.nolineno}

This should produce `out.dex`{:.filepath}, which we can then convert to a _JAR_ archive using `d2j-dex2jar`.

```bash
d2j-dex2jar "./out.dex"
```
{:.nolineno}

### JD-GUI

Now we have `out-dex2jar.jar`{:.filepath}, which we can open in JD-GUI.

```bash
jd-gui "./out-dex2jar.jar"
```
{:.nolineno}

![JAR disassembly](/assets/img/post/htb-challenges-apkrypt/jd-gui.png)
_The disassembly of out-dex2jar.jar in jd-gui_

Within the **onCreate** method there is a click listener on a button that when clicked, takes the content of a text input field and compares its MD5 hash to `735c3628699822c4c1c09219f317a8e9`. If they match, the string `k+RLD5J86JRYnluaZLF3Zs/yJrVdVfGo1CQy5k0+tCZDJZTozBWPn2lExQYDHH1l` gets decrypted and displayed. If they don't match, we get the message `Wrong VIP code!`.

We also find the AES key used by the _decrypt_ method in **generateKey**.

```java
private static Key generateKey() throws Exception {
  	return new SecretKeySpec("Dgu8Trf6Ge4Ki9Lb".getBytes(), "AES");
}
```
{:.nolineno}

## Decryption

Now that we have the key, we'll decrypt the data in the _onCreate_ method with a simple python script using [PyCryptodome](https://github.com/Legrandin/pycryptodome). We can assume that the AES mode is ECB because there is no nonce or IV present in the program as far as we know.

```python
from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

KEY = b'Dgu8Trf6Ge4Ki9Lb'
ENC = b64decode('k+RLD5J86JRYnluaZLF3Zs/yJrVdVfGo1CQy5k0+tCZDJZTozBWPn2lExQYDHH1l')

cipher = AES.new(KEY, AES.MODE_ECB)
result = unpad(cipher.decrypt(ENC), 16)
print(result.decode())
```
{:file="decrypt.py"}

Running the script produces the flag.
