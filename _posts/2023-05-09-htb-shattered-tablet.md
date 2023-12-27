---
title: "HTB • Shattered Tablet"
tags:
  - "Static Analysis"
  - "Reversing"
  - "Very Easy Difficulty"
  - "Beginner"
excerpt: "Shattered Tablet is a very easy reversing challenge on Hack the Box that involves recovering each byte of the flag from machine code, which we solve using radare2 and regular expressions."
categories:
  - "Writeups"
  - "Hack the Box Challenges"
---

_Shattered Tablet_ is a very easy reversing challenge created by [**clubby789**](https://app.hackthebox.com/users/83743) on [**Hack the Box**](https://app.hackthebox.com/challenges/shattered-tablet) that involves recovering each byte of the flag from machine code, which we solve using radare2 and regular expressions.

> Deep in an ancient tomb, you've discovered a stone tablet with secret information on the locations of other relics. However, while dodging a poison dart, it slipped from your hands and shattered into hundreds of pieces. Can you reassemble it and read the clues?

## Reversing

We'll use [radare2](https://github.com/radareorg/radare2) to analyze the target executable.

```bash
radare2 -AA ./tablet
```
{:.nolineno}

Let's disassemble the main function.

```bash
# radare2
pdf @main
```
{:.nolineno}

The main function compares each byte of our input to individual bytes directly in the machine code. The same pattern of `movzx`, `cmp`, then `jne` is repeated 40 times in a row from **0x11c6** to **0x136a**. Let's export these instructions to python and extract that chain of instructions

```bash
# radare2 shell
!echo \$((0x136a - 0x11c6)) # 420
0x11c6 # Move to beginning of target instructions
pcp 420 > tablet_opcodes.py # Export the raw bytes to a python script
```
{:.nolineno}

Then we'll extract the relevant information from the raw bytes using regular expressions in python.

```python
#!/usr/bin/env python3
import re
from tablet_opcodes import buf

# extract the movzx source address and cmp reference byte (index, value)
matches = re.findall(rb'\x0f\xb6\x45(.)\x3c(.)', buf)
# sort the findings by source address to effectively organize each byte by index
data = bytes([m[1][0] for m in sorted(matches)])
# print the sorted byte values
print(data)
```
{:file="rev.py"}

Running this program should print the flag.