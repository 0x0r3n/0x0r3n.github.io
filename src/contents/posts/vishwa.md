---
title: VishwaCTF challenges
published: 2025-03-10
description: Writeups for VishwaCTF challenges
tags: [Reversing, Forensics, Miscellaneous, Web, Crypto]
category: Writeups
draft: false
---

# Writeup for VishwaCTF'25

## Cryptography
### Chaos
>Author: Nikola
>Description:
>Chaos
You've stumbled upon a bunch of garbled nonsense—some might call them "encrypted messages," but who really knows? Most of it is just random junk, but hidden somewhere in this mess is an actual secret. No keys, no hints, just you and the chaos. Good luck figuring it out—if you even can.
Author: Abhinav @.0_0.ace.0_0.


---
#### Solution
> Challenge analysis:
- Script Functions
- Read data from file:
- Abhinav04139720.txt: contains messages loaded from a URL.
- flags.txt: contains flags to be encoded
- Scramble data: Data from two files is randomly mixed.
- Line-by-line encryption:
- Each line is encrypted using xor_encrypt() function.
- The result is saved to output.txt in Base85 format.
> Script solve:
 ```python=
 import base64

def xor_decrypt(encoded_msg):
    decoded = base64.b85decode(encoded_msg)
    transformed = bytearray(decoded)
    for i in range(len(transformed)):
        transformed[i] ^= (i % 256)  
    return transformed.decode(errors='ignore')

with open('output.txt', 'r') as f:
    encrypted_messages = f.read().strip().split('\n\n')

decrypted_messages = [xor_decrypt(msg) for msg in encrypted_messages]

with open('decrypted_output.txt', 'w') as f:
    for msg in decrypted_messages:
        f.write(f'{msg}\n')

print("Decryption complete! Check decrypted_output.txt")
 ```
>  decrypted_output.txt
```
Perhaps the flag is encoded in Base64? Or maybe hex?
Or maybe the real flag is just one character different from all these fakes?
VishwaCTF{Fl4g_Or_N0t_Th4t_1s_Th3_QuesT10n}
Maybe the flag is hidden elsewhere...
VishwaCTF{T00_M4ny_F4k3_Fl4Gs_G00d_Luck}
Or inside a comment in the source code?
This is not the flag, keep looking!
Or maybe there's a script generating multiple fake flags dynamically?
VishwaCTF{CrYpt0_cRyPT0_1g_It_1s_sOm3_7hiNg_t0_D0}
Maybe it's inside another challenge, cross-referencing flags?
Or is it?
But wait... isn't this too obvious?
What if it's a hash of the real flag?
VishwaCTF{NoT_ThE_ReaL_fLaG_K33P_tRy1Ng}
Or hidden in an image using steganography?
Happy hunting!
VishwaCTF{Y0u_WiLl_N3v3r_F1nd_1t}
Or maybe the real flag is hidden inside a hidden file?
Find_the_real_flag_somewhere_in_this_mess
Oh, did you think that was real? Keep digging!

```
> Flag: VishwaCTF{CrYpt0_cRyPT0_1g_It_1s_sOm3_7hiNg_t0_D0}
### Aria of the Lost Code
>Author: Nikola
>Description:
>A shattered data shard from an ancient relic has been recovered. It hums with a cryptic resonance, revealing a fragmented inscription in an unknown script. After intense decryption efforts, a single phrase emerged:
"The melody echoes beyond the void."
Can you uncover the true message hidden within?
Author: Abhinav @.0_0.ace.0_0.
Flag Format:
VishwaCTF{A4v4_a4a_4aa4a_Aa_44a4a4a4} 


---
#### Solution
![image](https://hackmd.io/_uploads/Bksq2T5jke.png)
- I found the cipher for this challenge is https://www.dcode.fr/hymnos-alphabet.
- The ciphers are stacked on top of each other so I need to separate them and decrypt them.
![image](https://hackmd.io/_uploads/BkPF1AqoJe.png)
> Flag: VishwaCTF{H4v3_y0u_7ri3d_Ar_70n3L1C0}

### Rhythmic Cipher
>Author: t4t3012
>A secret group has been exchanging messages using an unusual method—hiding words in plain sight through an old cipher. Their latest transmission has been intercepted.
Can you decode their message and uncover what they are trying to say?
Download `gif1.gif` and `gif2.gif` at [here](https://github.com/CyberCell-Viit/VishwaCTF-25-Challenges/tree/main/Cryptography/Rhythmic%20Cipher)

I extract frames from `gif1.gif` and `gif2.gif`
![image](https://hackmd.io/_uploads/rksLQAqsJx.png)
It is `Dancing Men Cipher`
![image](https://hackmd.io/_uploads/Hy4kERqsyx.png)
![image](https://hackmd.io/_uploads/Skj-4A9sJe.png)
![image](https://hackmd.io/_uploads/rymUERciyg.png)
`Flag: VishwaCTF{CIPHERD_DANCE}`

### Forgotten Cipher
>Author: I3isk3t
>Description:
Forgotten Cipher
The VIC cipher, a Cold War-era encryption, used evolving keys and transformations to secure messages. Inspired by this, the given cipher dynamically modifies its key and applies subtle bitwise transformations to obscure the text.XOR based transforms are used with base key as a single digit and bitwise shifts follow certain index rules.Reversing the process requires careful observation—can you unravel the sequence and restore the original message?
Author: Dhanashri @dhanashrib_15632

This challenge gave me a [files.txt](https://github.com/CyberCell-Viit/VishwaCTF-25-Challenges/blob/main/Cryptography/Forgotten%20Cipher/files.txt) :
```
Encrypted Message :- 0d4ac648a2f0bee7bccf0231c35e13ba7bc93a2d8f7d9498885e3f4998

Key Evolution Formula :- K(n) = [ K(n−1) × 3 + index ] mod 256
```
So there is an `Encrypted Message` and a `Key Evolution Formula`. Based on the formula, this encrypted message can be decrypted.
##### Understanding the Formula `K(n) = [ K(n−1) × 3 + index ] mod 256`:
- This formula describes how the encryption key evolves for each byte.
- We likely need an initial key value (K(0)) to start the decryption process.
##### Technique :
 - Decrypt the `Encrypted Message` using bit rotation + XOR and brute-force the original key (`K(n)`) from 0.

##### This is my script to Decrypt the Encrypted Message:
```#Decrypt
import string
import sys

sys.stdout.reconfigure(encoding='utf-8')

def rol(val, r_bits, max_bits=8):
    """Rotate left 8-bit"""
    return ((val << r_bits) & (2**max_bits - 1)) | (val >> (max_bits - r_bits))

def ror(val, r_bits, max_bits=8):
    """Rotate right 8-bit"""
    return ((val >> r_bits) | (val << (max_bits - r_bits))) & (2**max_bits - 1)

def decrypt(encrypted_hex, initial_key=0):
    """Decrypt using shift_then_xor method with key update before processing."""
    encrypted_bytes = [int(encrypted_hex[i:i+2], 16) for i in range(0, len(encrypted_hex), 2)]
    plaintext_chars = []
    key = initial_key

    for i, byte in enumerate(encrypted_bytes):
        key = (key * 3 + i) % 256  # Update key before processing
        
        shifted = ror(byte, 2) if i % 2 == 0 else rol(byte, 2)  # Reverse bit shift
        plain_byte = shifted ^ key  # XOR with key
        plaintext_chars.append(chr(plain_byte))

    return ''.join(plaintext_chars)

def is_mostly_printable(s, threshold=0.9):
    printable = set(string.printable)
    return sum(c in printable for c in s) / len(s) >= threshold

encrypted_hex = "0d4ac648a2f0bee7bccf0231c35e13ba7bc93a2d8f7d9498885e3f4998"

# Brute-force initial key
print("Trying different initial keys...\n")
for k in range(256):
    plaintext = decrypt(encrypted_hex, initial_key=k)
    if is_mostly_printable(plaintext, threshold=0.95):  # Adjust threshold if needed
        print(f"{plaintext}")
``` 
`Flag: VishwaCTF{VIC_Decoded_113510}`

## Digital Forensics

### Leaky Stream
>Author: nh0kt1g3r12
>In the middle of our conversation, some packets went amiss. We managed to resend a few but they were slightly altered.
Help me reconstruct the message and I'll reward you with something useful ;)
Authors:
Bhakti @debugger0145
Dhanashri @dhanashrib_15632

Using strings + grep on the pcap file, I easily got the flag:
![image](https://hackmd.io/_uploads/SJI4Qqniyg.png)

`Flag: VishwaCTF{this_is_first_part_this_second_part}`

### Persist
>Author: nh0kt1g3r12
>Description:
>Persist
User, “I logged onto my computer on FRIDAY and noticed something on the home screen before the computer shut down. Could it have been malware?”
Author: Parnika @parnika_maskar

I don't know why this challenge is named "Persist", though no persistence techniques were included in this challenge( or maybe I was wrong, please apologize). By opening `RecentDocs` key in `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`, we can obtain the flag in the name of the recent files:
![image](https://hackmd.io/_uploads/HywSE5niyx.png)

`Flag: VishwaCTF{b3l1ef_in_r3g_p0wer}`
### Whispers
>Author : t4t3012
>Description:
What car-turned-hippie in "Cars" shares its namesake with a San Francisco district known for its countercultural history?
#NOTE: Suggested Software WinRAR
Author: OM @ompannase

First I checked in TCP stream and found some message from 192.168.31.129:9001 with 192.168.31.129:57478
TCP stream 0:
```
Lines of code in a hidden thread,

.

Connecting the dots in patterns untold,

.

Layer upon layer, a system unseen,

.

*@*lways it whispers, the code out of sight,

.

Holding its secrets in digital veins,

.

You must look closely, where silence..remains.

.

exit

```
Stream 1:
```
.

0nward they flow, where secrets are led.

.

Across quiet channels, both subtle and bold.

.

Paths intertwined, where few have been.

.

Through silent corridors, beyond the light.

.

Waiting for those who seek through the chains

.

```
Stream 2:
```
220 (vsFTPd 3.0.3)

USER kali

331 Please specify the password.

PASS kali

230 Login successful.

SYST

215 UNIX Type: L8

FEAT

211-Features:
 EPRT
 EPSV
 MDTM
 PASV
 REST STREAM
 SIZE
 TVFS
211 End

CWD /var/local

250 Directory successfully changed.

EPSV

229 Entering Extended Passive Mode (|||33326|)

LIST

150 Here comes the directory listing.
226 Directory send OK.

TYPE I

200 Switching to Binary mode.

EPSV

229 Entering Extended Passive Mode (|||30531|)

STOR gotyou.zip

150 Ok to send data.
226 Transfer complete.

```
Oke I gather quite information about conversation. In conversation I found they download a file "gotyou.zip"
I start processing that file but it seems to be blocked by password
During several time I checked it out and cracked but it didn't work well and I come up with the new idea that gets all the first words from TCP in each line in order by request-response and attaches them to a password for password decompress file zip.
the password is "L@calPATHWY"
After extracting the zip file, I recieved 4 file jpg images. The `hehehe.jpg` looks suspicious as it's the heaviest file. (*As a Result I checked it with detect-it-easy )
![image](https://hackmd.io/_uploads/rk7sNVjskx.png)
then I used pyinstxtractor to unpacke and discompile with pyLinguage
Resource for toolkit :
https://github.com/extremecoders-re/pyinstxtractor (convert file exe to pyc it means python bytecode)
```
python pyinstxtractor.py hehehe.jpg
```
![image](https://hackmd.io/_uploads/SyzSINjoye.png)

putting file hehehe.pyc in pyLingual
https://pylingual.io/ (convert file pyc to py


and then the Flag in source code py
>Flag: VishwaCTF{h1dd3n_l0c4l_traff1c}
![image](https://hackmd.io/_uploads/SJobLEsoJx.png)


## Miscellanous
### Sanity Check
>Author: t4t3012
>Description: Let's get started and look at the bigger picture
>[sanity.txt](https://github.com/CyberCell-Viit/VishwaCTF-25-Challenges/blob/main/Miscellaneous/Sanity%20Check/sanity.txt)

Use notepad to open `sanity.txt` and reduce font size,You will see flag
![image](https://hackmd.io/_uploads/BJxEp6qjyg.png)
`Flag: VishwaCTF{being_a_jack_of_all_is_better_then_being_a_master_at_one}`
## OSINT
### Follow for clues
>Author: t4t3012
>Description : 🔍 Stay updated:
📌 Follow us on LinkedIn, Instagram, and Twitter 💬 Join our Discord for updates

The description mentioned social media sush as Discord, Instagram, Twitter. First of all I want to check them out and then at Instagram social media I find the flag in the description of post
![image](https://hackmd.io/_uploads/ByGWIXijJx.png)
>flag: VishwaCTF{L3t_Th3_hUn7_8Eg1n}

### Stadium!!!
>Author : t4t3012
>Description:
My friend wanted to play a cricket match, he told me to find the best place to play a game. So I did. Can you identify the stadium where we played our match?
Author: Abhinav @.0_0.ace.0_0.

![image](https://hackmd.io/_uploads/rJf_8QjjJg.png)
First I used google lens to search for more information about this image
![image](https://hackmd.io/_uploads/BJwnwXooyx.png)
I see the blog said about Cricket ground in Saling, Gilgit Baltistan
https://www.youlinmagazine.com/story/book-review-once-upon-a-time-in-nazimabad/MjUwMw==#google_vignette
I used google map to search keyword "Sailing, Gilgit baltistan" and then find nearby with "Cricket ground" keyword
https://www.google.com/maps/search/Cricket+ground/@35.1853061,76.3536075,1381m/data=!3m1!1e3!4m7!2m6!3m5!2sSaling!3s0x38e4abcf34852575:0x66947e9cce9b94e0!4m2!1d76.3767515!2d35.1891779?entry=ttu&g_ep=EgoyMDI1MDMwNC4wIKXMDSoASAFQAw%3D%3D
>flag : VishwaCTF{Saling_Cricket_Stadium_Ghanche}

### Lecture Code
>Author: nh0kt1g3r12
>Description: 
>A renowned computer science professor, known for his legendary lectures, once hinted at a hidden message buried within his online presence. Over the years, students speculated about a secret key—a passphrase that unlocks an unknown treasure of knowledge.
Recently, a rumor saying that cryptic message surfaced in an obscure GitHub repository was heard, was it fake or really exists and reveals his secret after all? quack!
Author: Riya @riya_shah28

Because this is an OSINT challenge, I started by investigating the author (since no username provided and I didn't get any idea from the description lmao).
I could easily get her social medias at https://vishwactf.com/heroes
![image](https://hackmd.io/_uploads/BymvH5niJg.png)

Navigating to her github, I found an old course from CS50 which has been forked to her github (and of course, it has some commitments :>). Here is her final commitment of a .py file: 
```python=
def custom_decrypt(encrypted_text):
    shift = 3  # Same shift used for encryption
    reversed_text = "".join(chr(ord(c) - shift) for c in encrypted_text)  # Reverse shift
    original_text = reversed_text[::-1]  # Reverse back to original
    print(original_text)

hidden_encrypted_pass = ""
custom_decrypt(hidden_encrypted_pass)
```
According to the description, we have to find the encrypted message, so let's investigate her other social medias :>, I'll begin with `Linkedin` first, and in one of her comments: 
![image](https://hackmd.io/_uploads/rkG3U9hj1e.png)

put `$nf7xtbr8vf` as the encrypted message, I managed to retrieve the flag:
![image](https://hackmd.io/_uploads/S1T1D5noyg.png)

`Flag: VishwaCTF{cs5o_qu4ck!}`

### The Summit:
>Author: nh0kt1g3r12
>Description:
>Hey, I recently attended an event where I saw some notable guests on the first day. Unfortunately, I can't quite remember the exact location of the event. However, I do remember it was an important event with a lot of attention from the media. Can you identify the location of this event and find out who the prominent guests were? Use publicly available data to figure it out, and provide any additional insights you can gather about the event.
Author: Abhinav @.0_0.ace.0_0.


![Screenshot_2025-03-10_234537_optimized_1000](https://hackmd.io/_uploads/Sy_JuqhiJx.png)

So, we can gather some information in this picture:
Date: 5th January 2025
Location: India
THeMIS is something relates to military

Start searching google with these information:
![image](https://hackmd.io/_uploads/SywGKqnikx.png)

So the event is Know Your Army Mela 2025, but where does it take place ?
![image](https://hackmd.io/_uploads/SyUPt92skg.png)

Location: 
![image](https://hackmd.io/_uploads/By40q52jJx.png)

And the guest:
![image](https://hackmd.io/_uploads/SJdks92i1e.png)

So our flag is:
`Flag: VishwaCTF{18.51,73.89_Devendra Fadnavis}`





## Reverse Engineering
### Hungry Friends
>Author: Nikola
>Description:
>Hungry Friends
Feed my friend.
Author: Abhinav @ .0_0.ace.0_0.


---
#### Solution
- This challenges they give me `snakes.exe`. I will analyze it in IDA.
- This main() function.
```cpp=
int __cdecl main(int argc, const char **argv, const char **envp)
{
  __time32_t v3; // eax
  int v4; // eax
  int v5; // ebx
  int v6; // eax
  int v7; // eax
  int v9; // [esp-Ch] [ebp-10h]
  int v10; // [esp-8h] [ebp-Ch]

  __main();
  v3 = time(0);
  srand(v3);
  HIDE_CURSOR();
  INIT_GAME();
  SPAWN_FOOD();
  while ( !GAME_OVER )
  {
    if ( _kbhit() )
    {
      v4 = _getch();
      if ( v4 == 100 )
      {
        DX = 1;
        DY = 0;
      }
      else if ( v4 > 100 )
      {
        if ( v4 == 115 )
        {
          DX = 0;
          DY = 1;
        }
        else if ( v4 == 119 )
        {
          DX = 0;
          DY = -1;
        }
      }
      else if ( v4 == 97 )
      {
        DX = -1;
        DY = 0;
      }
    }
    MOVE_SNAKE();
    DRAW_GAME();
    if ( CHAKDE == 9999 )
      SHOW_FLAG();
    Sleep(0x64u);
  }
  v5 = CHAKDE;
  v6 = std::operator<<<std::char_traits<char>>(&std::cout, "Game Over! Score: ", v9, v10);
  v7 = std::ostream::operator<<(v6, v5);
  std::ostream::operator<<(v7, &std::endl<char,std::char_traits<char>>);
  return 0;
}
```
- I will proceed to check the `SHOW_FLAG()` function.
```cpp=
int SHOW_FLAG(void)
{
  int v0; // eax
  int v1; // eax
  int v3; // [esp+8h] [ebp-30h]
  int v4; // [esp+Ch] [ebp-2Ch]
  _BYTE v5[28]; // [esp+18h] [ebp-20h] BYREF

  decrypt[abi:cxx11](v5, &encrypted);
  v0 = std::operator<<<std::char_traits<char>>(&std::cout, "\n\nCongratulations! Flag: ", v3, v4);
  v1 = std::operator<<<char>(v0, v5);
  std::ostream::operator<<(v1, &std::endl<char,std::char_traits<char>>);
  return (std::string::~string)(v5);
}
```
- I continue to analyze the ```=decrypt[abi:cxx11](v5, &encrypted);``` function.
```cpp=
int __cdecl decrypt[abi:cxx11](int a1, int a2)
{
  __int64 v2; // rax
  int v3; // eax
  unsigned int v4; // eax
  _DWORD *v5; // eax
  int v6; // edx
  _BYTE *v7; // edi
  __int64 v9; // [esp+4h] [ebp-44h]
  char v10; // [esp+17h] [ebp-31h] BYREF
  __int64 v11; // [esp+18h] [ebp-30h]
  unsigned int i; // [esp+24h] [ebp-24h]
  __int64 v13; // [esp+28h] [ebp-20h]

  LODWORD(v2) = generateKey();
  v13 = v2;
  std::allocator<char>::allocator(&v10);
  v3 = std::vector<unsigned long long>::size(a2);
  std::string::basic_string(a1, v3, 32, &v10);
  (std::allocator<char>::~allocator)(&v10);
  for ( i = 0; ; ++i )
  {
    v4 = std::vector<unsigned long long>::size(a2);
    if ( v4 <= i )
      break;
    v5 = std::vector<unsigned long long>::operator[](i);
    v6 = v5[1];
    LODWORD(v11) = *v5;
    HIDWORD(v11) = v6;
    v7 = std::string::operator[](a1, i, v9, HIDWORD(v9));
    v9 = 17LL;
    *v7 = (v11 - (v13 ^ (1337 * i))) / 0x11;
    v13 ^= v11;
  }
  return a1;
}
```
- Here i saw the program returns the value of the key.
```cpp=
__int64 generateKey(void)
{
  return 4183820235LL;
}
```
- From the above logic I will write the decode function.
```python=
def decrypt(a2, generate_key):
    a1 = [''] * len(a2) 
    key = generate_key() 
    for i in range(len(a2)):
        cipher_value = a2[i]
        plain_char = (cipher_value - (key ^ (1337 * i))) // 0x11
        a1[i] = chr(plain_char)
        key ^= cipher_value 
    
    return ''.join(a1)


a2 = [] 
def generate_key():
    return 4183820235 

flag = decrypt(a2, generate_key)
print(flag)
```
- However we don't have the encrypted data yet. It will be hidden in the stack so I will exploit it.
- I will try to encode the format flag using the above mechanism and look in the stack.
 ![image](https://hackmd.io/_uploads/rkQ1zTcskg.png)
- Here is the encrypted data.
- Solve script:
```python=
def decrypt(a2, generate_key):
    a1 = [''] * len(a2) 
    key = generate_key() 
    for i in range(len(a2)):
        cipher_value = a2[i]
        plain_char = (cipher_value - (key ^ (1337 * i))) // 0x11
        a1[i] = chr(plain_char)
        key ^= cipher_value 
    
    return ''.join(a1)


a2 = [0xf9600d81, 0x166c, 0x1df7, 0x1562, 0x83e, 0xd01, 0x134d, 0x2be2, 0x591, 0xbde, 0x1b0a,0x0bfd,0x0c9a,0x8076,0xf5cc,0x073b,0x1d84,0x145f,0x21bc,0x092b,0x043d,0x08aa,0x1a31,0x0d90,0x1205,0xe6f3,0x0715,0x138b,0x08da,0x1369,0x1ade,0x368c,0x0ae5,0x05ff,0x22c0,0x46b0,0x79c1, 0x8032 ] 
def generate_key():
    return 4183820235 

flag = decrypt(a2, generate_key)
print(flag)
```
> Flag: VishwaCTF{th3r3_4r3_5n4k35_all_4r0und}
### Safe Box
>Author: Nikola
>Description:
>There are many ways, but the choice is yours. 
 Author: Soham @sohamkolte
 

---
#### Solution
- This challenges they give me file `.NET` and i have to attack and get the flag from them
- When I run it it asks me to enter the box password to unlock the flag but if you enter it three times you won't be able to open it anymore.
 ![image](https://hackmd.io/_uploads/SkJ6mp9jyl.png)
 ![image](https://hackmd.io/_uploads/H1C7Nacoke.png)
- I was going to analyze the Assembly-CSharp.dll file to see how it works but it is Obfuscated
- I will beautify the code with d4dot.
https://github.com/de4dot/de4dot
![image](https://hackmd.io/_uploads/HyfeL65oke.png)
- Now the code is easier to read and analyze.
- But wait I tried to edit the code and run the `Safe` file again and it still doesn't change anything. Maybe they are tricking me with a fake code.
- After I rummaged around I found it. It was the original code for the `Safe` file.
- Here name file  `UnityEngine.NetworkUtils.dll`
 ![image](https://hackmd.io/_uploads/S1iT865okx.png)
- Here it is checking if i have entered it more than three times i will disable it by deleting it.
 ![image](https://hackmd.io/_uploads/Sk28DT9o1e.png)
 ![image](https://hackmd.io/_uploads/r1hPPa9syl.png)
- And this is the main function that needs to be modified so that the box is opened to get the flag.
 ![image](https://hackmd.io/_uploads/H1baD6cjyx.png)
- I will disable it by changing the condition to always true.
 ![image](https://hackmd.io/_uploads/ryGfd6qikg.png)
- Then i start fetch and get flag from program
 ![image](https://hackmd.io/_uploads/SyIuO6coyx.png)
>  Flag: WishwaCTF{h3r3_y0u_@r3}

## Steganography
### Quadrant
>Author: t4t3012
>Description: Four pieces of a forgotten code lie before you. Each fragment holds a part of a greater whole, but the puzzle is incomplete. Your task: find the pattern, align the pieces, and unlock the final code. Once the pieces fall into place, scan what you’ve created to uncover the secret within.
Let the search begin.
[QuadRant.zip](https://github.com/CyberCell-Viit/VishwaCTF-25-Challenges/blob/main/Steganography/Quadrant/QuadRant.zip)

Chall give me 4 png files ![image](https://hackmd.io/_uploads/B1j9RTcikx.png)
![image](https://hackmd.io/_uploads/r193069skx.png)
![image](https://hackmd.io/_uploads/SkvaCa5sJe.png)
![image](https://hackmd.io/_uploads/rk5RRa5iyg.png)
![image](https://hackmd.io/_uploads/rkkxJRqsJe.png)
I use paint to overlay the images and we will have the complete QR code.
![image](https://hackmd.io/_uploads/B1smeRqjyg.png)
`Flag: VishwaCTF{aG9lMTIzNDU2c3Bhc3NhZ2U=}`
### Spilled Paint Water
>Author: t4t3012
>Oops! I accidentally spilled paint all over my canvas. Now, the colors have blended too well :(
Can you restore my lost artwork?
>[canvas.svg](https://github.com/CyberCell-Viit/VishwaCTF-25-Challenges/blob/main/Steganography/Spilled%20Paint%20Water/canvas.svg)

Source of `canvas.svg`:
```=
<svg id="eEnmxFAjcr61" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 300 300" shape-rendering="geometricPrecision" text-rendering="geometricPrecision" project-id="325d788ad90b4729a3b39f752dd4d05d" export-id="a48c1b27901f4ee7a8d074ff5e6709e9" cached="false">
  <clipPath id="clipArea">
    <rect x="1000" y="1000" width="200" height="200"/>
  </clipPath>
  
  <g clip-path="url(#clipArea)">
    <style>
      svg {
    background-color:#a2b5e0  ;
  }
    </style>
    <line x1="7.865168" y1="-4.868914" x2="-7.865168" y2="4.868914" transform="translate(23.782772 74.531835)" fill="none" stroke="#a2b5e4" stroke-width="3"/>
    <line x1="-7.865168" y1="-4.494382" x2="7.865168" y2="4.494382" transform="translate(23.782772 83.895131)" fill="none" stroke="#a2b5e4" stroke-width="3"/>
    <line x1="7.865168" y1="-6.367041" x2="-7.865168" y2="6.367042" transform="translate(23.782772 94.756555)" fill="none" stroke="#a2b5e4" stroke-width="3"/>
    <line x1="0" y1="-12.546817" x2="0" y2="12.546817" transform="translate(48.876404 82.209738)" fill="none" stroke="#a2b5e4" stroke-width="3"/>
    <line x1="-10.486891" y1="0" x2="10.486892" y2="0" transform="translate(47.378277 69.662921)" fill="none" stroke="#a2b5e4" stroke-width="3"/>
    <line x1="0" y1="-10.11236" x2="0" y2="10.11236" transform="translate(57.865169 84.644195)" fill="none" stroke="#a2b5e4" stroke-width="3"/>
    <line x1="-8.988764" y1="0" x2="8.988764" y2="0" transform="translate(66.853933 74.531835)" fill="none" stroke="#a2b5e4" stroke-width="3"/>
    <line x1="0" y1="-4.681648" x2="0" y2="4.681648" transform="translate(75.842697 79.213483)" fill="none" stroke="#a2b5e4" stroke-width="3"/>
    <line x1="-8.988764" y1="0" x2="8.988764" y2="0" transform="translate(66.853933 84.644195)" fill="none" stroke="#a2b5e4" stroke-width="3"/>
    <line x1="-6.741573" y1="-5.430712" x2="6.741573" y2="5.430712" transform="translate(64.606742 89.325843)" fill="none" stroke="#a2b5e4" stroke-width="3"/>
    <line x1="0" y1="-12.546817" x2="0" y2="12.546817" transform="translate(81.835206 82.209738)" fill="none" stroke="#a2b5e4" stroke-width="3"/>
    <line x1="-7.490636" y1="0" x2="7.490637" y2="0" transform="translate(89.325843 69.662921)" fill="none" stroke="#a2b5e4" stroke-width="3"/>
    <line x1="0" y1="-14.794008" x2="0" y2="14.794008" transform="translate(96.81648 79.962547)" fill="none" stroke="#a2b5e4" stroke-width="3"/>
    <line x1="-7.490637" y1="0" x2="7.490637" y2="0" transform="translate(89.325843 94.756555)" fill="none" stroke="#a2b5e4" stroke-width="3"/>
    <line x1="-0.374532" y1="-14.794008" x2="0.374532" y2="14.794008" transform="translate(108.426966 79.962547)" fill="none" stroke="#a2b5e4" stroke-width="3"/>
    <line x1="4.494382" y1="-6.273409" x2="-4.494382" y2="6.273409" transform="translate(113.29588 75.93633)" fill="none" stroke="#a2b5e4" stroke-width="3"/>
    <line x1="-5.243446" y1="-6.273409" x2="5.243446" y2="6.273409" transform="translate(118.539326 88.483147)" fill="none" stroke="#a2b5e4" stroke-width="3"/>
    <line x1="1.123595" y1="-12.546817" x2="-1.123595" y2="12.546817" transform="translate(130.898877 82.209738)" fill="none" stroke="#a2b5e4" stroke-width="3"/>
    <line x1="-10.112359" y1="0" x2="10.112359" y2="0" transform="translate(139.887641 65.168539)" fill="none" stroke="#a2b5e4" stroke-width="3"/>
    <line x1="-3.932585" y1="0.702247" x2="3.932584" y2="-0.702247" transform="translate(135.955057 75.234083)" fill="none" stroke="#a2b5e4" stroke-width="3"/>
    <line x1="-6.928839" y1="0" x2="6.928838" y2="0" transform="translate(137.827716 89.325843)" fill="none" stroke="#a2b5e4" stroke-width="3"/>
    <line x1="0.374532" y1="-11.985019" x2="-0.374532" y2="11.985019" transform="translate(118.164794 127.340824)" fill="none" stroke="#a2b5e4" stroke-width="3"/>
    <line x1="-6.741573" y1="-9.737828" x2="6.741573" y2="9.737828" transform="translate(125.280899 125.093633)" fill="none" stroke="#a2b5e4" stroke-width="3"/>
    <line x1="-0.561798" y1="-13.857678" x2="0.561797" y2="13.857678" transform="translate(130.33708 120.973783)" fill="none" stroke="#a2b5e4" stroke-width="3"/>
    <line x1="-10.486891" y1="0" x2="10.486892" y2="0" transform="translate(168.726591 89.325843)" fill="none" stroke="#a2b5e4" stroke-width="3"/>
    <line x1="-8.2397" y1="0" x2="8.2397" y2="0" transform="translate(105.05618 139.325843)" fill="none" stroke="#a2b5e4" stroke-width="3"/>
    <line x1="-6.741573" y1="0" x2="6.741573" y2="0" transform="translate(151.498127 134.831461)" fill="none" stroke="#a2b5e4" stroke-width="3"/>
    <line x1="0" y1="-13.857678" x2="0" y2="13.857678" transform="translate(158.2397 120.973783)" fill="none" stroke="#a2b5e4" stroke-width="3"/>
    <line x1="-10.486891" y1="0" x2="10.486892" y2="0" transform="translate(168.726591 107.116105)" fill="none" stroke="#a2b5e4" stroke-width="3"/>
    <line x1="-10.486891" y1="0" x2="10.486892" y2="0" transform="translate(168.726591 115.355805)" fill="none" stroke="#a2b5e4" stroke-width="3"/>
    <line x1="0" y1="-10.112359" x2="0" y2="10.112359" transform="translate(183.707865 117.228465)" fill="none" stroke="#a2b5e4" stroke-width="3"/>
    <line x1="0" y1="-10.112359" x2="0" y2="10.112359" transform="translate(192.696629 117.228465)" fill="none" stroke="#a2b5e4" stroke-width="3"/>
    <line x1="-5.99251" y1="0" x2="5.992509" y2="0" transform="translate(198.689139 127.340824)" fill="none" stroke="#a2b5e4" stroke-width="3"/>
    <line x1="-0.749064" y1="-10.112359" x2="0.749064" y2="10.112359" transform="translate(211.423221 117.228465)" fill="none" stroke="#a2b5e4" stroke-width="3"/>
    <line x1="-6.741573" y1="0" x2="6.741573" y2="0" transform="translate(218.913858 127.340824)" fill="none" stroke="#a2b5e4" stroke-width="3"/>
    <line x1="-6.835206" y1="0" x2="6.835206" y2="0" transform="translate(144.662921 134.831461)" fill="none" stroke="#a2b5e4" stroke-width="3"/>
  </g>
</svg>
```
just remove this:
```
 <g clip-path="url(#clipArea)">
    <style>
      svg {
    background-color:#a2b5e0  ;
  }
```
The `<g clip-path="url(#clipArea)">` element applies the clipping path #clipArea to all elements inside the `<g>` group. This means that any shapes, images, or text inside the `<g>` will only be visible within the defined clipping area, while anything outside will be hidden.

It makes the color match the content we need to see so we have to delete it.
![image](https://hackmd.io/_uploads/HJzfoR9iyx.png)
`Flag: VishwaCTF{STROKE__N_FILL}`

### Lets Race
>Author: nh0kt1g3r12
>Description: 
>What car-turned-hippie in "Cars" shares its namesake with a San Francisco district known for its countercultural history?
#NOTE: Suggested Software WinRAR
Author: OM @ompannase

![Screenshot_2025-03-10_230431_2_optimized_950](https://hackmd.io/_uploads/S1UU19nsJe.png)

The challenge gave me a .png file with the image of `Chick Hicks`,`Lightning McQueen` and `Strip Weathers`. Based on the colors of each car, I guessd we have to extract the RGB data value of this image. By looking at the scoreboard, I can easily know the order of RGB bit planes to extract. 
We've already known the numbers which stand for `Chick Hicks` and `Strip Weathers`, `Lightning McQueen` is always the fastest, so his number must be 95. Using Stegsolve's data extract with the exact RBG order, I managed to get the flag:
![Screenshot_2025-03-10_231629_optimized_1000](https://hackmd.io/_uploads/Hyaezchjyg.png)

`Flag: ViswaCTF{1_l0v3_C0r5}`
### Echoes Of The Unknown
>Author: Nikola
>Description:
>Echoes Of The Unknown
Not everything is heard—some things must be seen.
Author: Dhanashri @dhanashrib_15632


---
- For this challenge they gave me a wav file. But when I listened to it, it seemed to be slowed down, so I tried speeding up the audio and decoding morsecode it.
- Decode Audio: https://morsecode.world/international/decoder/audio-decoder-adaptive.html
![image](https://hackmd.io/_uploads/rycwyo2jyl.png)
> Flag: ViswaCTF{CR4CK3D_7H3_C0D3}

## Web Exploitation
### Flames 
>Author: I3isk3t
>Description:
Find Your True Love <3.
https://flames.ctf-delivery-net.pp.ua/
Author: Abhinav @.0_0.ace.0_0.
Flag Format: VishwaCTF{}

![image](https://hackmd.io/_uploads/ryCftSjiyg.png)
Well, at first glance when I accessed this challenge's website, I noticed a hint in the title `Query of Love`. SQL injection huh. Let's give it a try first.
I tried the Basic UNION SQLi: `' UNION SELECT 1,2,3 -- -` in the `Name 1`, put a random string in `Name 2` then click Submit and boomm.
![image](https://hackmd.io/_uploads/rkmj2Bijkg.png)
Access the `Famous Love Stories` and I got the flag at the end of the list.

`Flag: VishwaCTF{SQL_1nj3ct10n_C4n_Qu3ry_Your_He4rt}`

### Are We Up

>Author: nh0kt1g3r12
>Description: No description was provided. No link was provided.
Author: Samarth @ark.dev
Flag Format: VishwaCTF{}

The challenge gave us a hint: `Check out the status of our website`. The CTF's website is https://vishwactf.com/. Normally, a status of a website is usually at the bottom of the website, so let's scroll all the way down. 
![image](https://hackmd.io/_uploads/BywaUKho1g.png)

U can click on its status, and get to a link: https://are-we-up-3dd2awd2.ctf-delivery-net.pp.ua/

![image](https://hackmd.io/_uploads/HJTeDFhi1e.png)

There's nothing much on this website, `/flag` gives us a fake flag, let's have a look at its html source code:
![image](https://hackmd.io/_uploads/B1RmvY3iJg.png)

Hmm interesting, we have a `/uptimer-a343s19` endpoint, let's navigate to it.
![image](https://hackmd.io/_uploads/SyO_wF3sye.png)

Basically, we input an url, and the server returns the status of that url, so it's gonna be an SSRF vulnerability here. I tried so many ways to redirect to localhost:8080/flag (as the home-page showed) but it keeps saying forbidden, I guessed I had to input something that redirects to localhost:8080/flag but it's not localhost:8080/flag or any variety of it. My idea is to host a web server that allows to input an url (just like this we-are-up) running at localhost:8080 using python, then expose it with webhook or ssh. After that I'm gonna submit my server's link, and input the url path(https://fbi.com:8080/flag in order to bypass localhost), so that the are-we-up server will connect to my server, and my server will redirect it to localhost:8080/flag (fbi.com is 127.0.0.1 in ip address).

Here's how I setup my web-server:
```python=
from flask import Flask, request, redirect

app = Flask(__name__)

@app.route('/')
def go_local():
    target = request.args.get('url')
    return redirect(target, code=302)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
```
![image](https://hackmd.io/_uploads/BkSNks2i1e.png)


![image](https://hackmd.io/_uploads/r1tl9YnsJg.png)

`Flag: VishwaCTF{Y0r4_lo7al_b4bby_A4k18aw2}`

### scan-it-to-stay-safe

>Author: nh0kt1g3r12
>Description:
>No description was provided.
https://scan-it-to-stay-safe.ctf-delivery-net.pp.ua/
Author: Samarth @ark.dev
Flag Format: VishwaCTF{}

![image](https://hackmd.io/_uploads/BJkucYni1x.png)

Just input your webhook server and get the flag, idk why it's categorized as a hard challenge...?

`Flag: VishwaCTF{Y0u_7R4c30lI7_3000_4rK}`

### forgot-h1-login

>Author: nh0kt1g3r12
>Description: 
>ark.dev forgot his HackerOne username and password, help him!!
https://forgot-h1-login.ctf-delivery-net.pp.ua/
Author: Samarth @ark.dev
Flag Format: VishwaCTF{}

So I was given a website with nothing than a login and reset password function. 
![image](https://hackmd.io/_uploads/ByfksF2jJe.png)

I guessed that we have to leak the password reset token link or something related.

Base on the description, we have the username: `ark.dev`. By searching on google hackerone email format, I've barely guessed his email:
![image](https://hackmd.io/_uploads/rJpEit3okx.png)

So his email must be `ark.dev@wearehackerone.com` or `ark.dev@hackerone.com`. By trying them all, the user's email is `ark.dev@hackerone.com`

![image](https://hackmd.io/_uploads/r1VuiFnjyg.png)

So what do we do now, password reset poisoning ? Nah, I've tried all of its varieties, and none of them worked. After stucking for a while, I added my email to the request and magic happened:
![image](https://hackmd.io/_uploads/ByMK2F2okl.png)
![image](https://hackmd.io/_uploads/SyxqchYnoye.png)

I tried to input the OTP but it didn't work. After a while, I took a look at the email source to see what has been sent to me.

![image](https://hackmd.io/_uploads/BkalTtnj1e.png)

And here goes our flag:
`Flag: VishwaCTF{y0u_4r3_7h3_h4ck3r_numb3r_0n3_2688658}`
