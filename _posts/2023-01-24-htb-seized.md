---
title: "HTB • Seized"
tags:
  - "DPAPI"
  - "Windows"
  - "Forensics"
  - "Blue Team"
  - "Medium Difficulty"
  - "Intermediate"
  - "Cryptography"
excerpt: "Seized is a medium-difficulty forensics challenge on Hack the Box that involves recovering credentials from a Windows AppData folder which are protected via DPAPI and stored by Google Chrome"
categories:
  - "Writeups"
  - "Hack the Box Challenges"
---

Seized is a medium-difficulty forensics challenge created by [**thewildspirit**](https://app.hackthebox.com/users/70891) on [**Hack the Box**](https://app.hackthebox.com/challenges/seized) that involves recovering credentials from a Windows AppData folder which are protected via DPAPI and stored by Google Chrome.

> Miyuki is now after a newly formed ransomware division which works for Longhir. This division's goal is to target any critical infrastructure and cause financial losses to their opponents. They never restore the encrypted files, even if the victim pays the ransom. This case is the number one priority for the team at the moment. Miyuki has seized the hard-drive of one of the members and it is believed that inside of which there may be credentials for the Ransomware's Dashboard. Given the AppData folder, can you retrieve the wanted credentials?

## Chrome User Data

There's some user data for Chrome at `AppData/Local/Google/Chrome/User Data/`{:.filepath}. This folder can contain all sorts of juicy info, and it might have the credentials for the ransomware dashboard. Within the standard `Default/Login Data`{:.filepath} database, we can verify that chrome stores the credentials that the challenge description was probably referring to.

```bash
login_data='./AppData/Local/Google/Chrome/User Data/Default/Login Data'
sqlite3 $login_data -cmd 'select * from logins'
```
{:.nolineno}

The returned entry has an email, **ransomoperator@draeglocker.com**, but the associated password looks to be encrypted. To decrypt the password, we need the DPAPI master key.

## DPAPI

The master key is stored at `AppData/Roaming/Microsoft/Protect/*/*`{:.filepath}, but it's encrypted and needs to be cracked.

### Recover Windows Password

We'll format the DPAPI master key into a crackable hash using the `DPAPImk2john` utility from [John the Ripper](https://github.com/openwall/john).

```bash
sid="S-1-5-21-3702016591-3723034727-1691771208-1002"
mkf="AppData/Roaming/Microsoft/Protect/$sid/865be7a6-863c-4d73-ac9f-233f8734089d"
DPAPImk2john -S $sid -mk $mkf -c local > dpapimk.john
```
{:.nolineno}

Then we'll crack the hash with John the Ripper and [this wordlist](https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/100k-most-used-passwords-NCSC.txt).

```bash
john --wordlist=100k.txt ./dpapimk.john
```
{:.nolineno}

We successfully crack the hash and recover the password "**ransom**". Now the password we found and the associated SID can be used to recover the plaintext master key with [pypykatz](https://github.com/skelsec/pypykatz).

### Recover Pre-Key

First we need a pre-key, which can be calculated with the unique SID and password of a user which we found earlier.

```bash
pass="ransom"
pypykatz dpapi prekey password $sid $pass
```
{:.nolineno}

### Decrypt Master Key

Now we'll use one of the pre-keys to decrypt the master key.

```bash
pkey="87ca22100fa54e86e4a2c476f67addf6b4375933" # The first pre-key
pypykatz dpapi masterkey -o ./masterkey.json $mkf $pkey
```
{:.nolineno}

The `masterkey.json`{:.filepath} file now contains the decrypted master key.

### Decrypt Chrome Secrets

Pypykatz has another tool we could use to decrypt Chrome secrets with the master key that we recovered.

```bash
pypykatz dpapi chrome \
	--logindata $login_data \
	./masterkey.json \
	"./AppData/Local/Google/Chrome/User Data/Local State"
```
{:.nolineno}

The flag can then be found in the output from the password column.
