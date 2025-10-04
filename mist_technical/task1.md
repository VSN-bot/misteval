1. a.
     In this challenge, you have:

/challenge/hack: this produces data on stdout and stderr /challenge/the: you must redirect hack's stderr to this program /challenge/planet: you must redirect hack's stdout to this program Go get the flag!

Solve

<img width="1467" height="247" alt="Screenshot 2025-10-04 232224" src="https://github.com/user-attachments/assets/fce0c7d7-30ef-4514-bf12-4542c037d613" />


Learned about split piping for errors and outputs.

 b.We put a few happy, but diversely-named files in /challenge/files. Go cd there and run /challenge/run, providing a single argument: a short (3 characters or less) globbed word with two * globs in it that covers every word that contains the letter p.

Solve

<img width="1011" height="298" alt="image" src="https://github.com/user-attachments/assets/d5384fbf-42d1-48d7-afbf-a98f00d635c7" />

Learned about using multiple globs at the same time.

c.  I found that Zardus’s `~/.bashrc` was world-readable and contained the line `FLAG_GETTER_API_KEY=sk-XXXYYYZZZ`.
By reading it and running `flag_getter --key $(awk -F= '/FLAG_GETTER_API_KEY/{print $2}' /home/zardus/.bashrc)`, I retrieved the flag `pwn.college{HACKED}`.

<img width="1490" height="334" alt="Screenshot 2025-10-04 231747" src="https://github.com/user-attachments/assets/67f14db4-a816-42c9-ab70-fb3b01541624" />
2.1
<img width="1586" height="786" alt="image" src="https://github.com/user-attachments/assets/c59d6027-dacf-4b81-ae12-b148648a410b" />










3.1 . #!/usr/bin/env python3
from itertools import product
import string, sys

ALPH = string.ascii_uppercase
A2I = {c:i for i,c in enumerate(ALPH)}
I2A = {i:c for i,c in enumerate(ALPH)}
MOD = 26

def clean_text(s):
    return ''.join([c for c in s.upper() if c.isalpha()])

def text_to_nums(s):
    return [A2I[c] for c in s]

def nums_to_text(nums):
    return ''.join(I2A[n % MOD] for n in nums)

def chunk2(nums):
    if len(nums) % 2 != 0:
        nums.append(A2I['X'])
    return [nums[i:i+2] for i in range(0,len(nums),2)]

def det2(m):
    return (m[0][0]*m[1][1] - m[0][1]*m[1][0]) % MOD

def egcd(a,b):
    if b==0: return (a,1,0)
    g,x1,y1 = egcd(b, a%b)
    return (g, y1, x1 - (a//b)*y1)

def modinv(a,m):
    g,x,y = egcd(a,m)
    if g!=1: return None
    return x%m

def inv_matrix2(m):
    a,b=m[0]; c,d=m[1]
    det=det2(m)
    inv_det=modinv(det,MOD)
    if inv_det is None: return None
    inv=[[ ( inv_det*d)%MOD, ( inv_det*(-b))%MOD],
         [ ( inv_det*(-c))%MOD, ( inv_det*a)%MOD]]
    for i in range(2):
        for j in range(2):
            inv[i][j]%=MOD
    return inv

def mat_vec_mul(m,v):
    return [ (m[0][0]*v[0]+m[0][1]*v[1])%MOD,
             (m[1][0]*v[0]+m[1][1]*v[1])%MOD ]

def key_from_text(t):
    t=clean_text(t)
    if len(t)!=4: raise ValueError("Key must be 4 letters.")
    n=text_to_nums(t)
    return [[n[0],n[1]],[n[2],n[3]]]

def encrypt(k,pt):
    n=text_to_nums(clean_text(pt))
    pairs=chunk2(n); out=[]
    for p in pairs: out.extend(mat_vec_mul(k,p))
    return nums_to_text(out)

def decrypt(k,ct):
    inv=inv_matrix2(k)
    if inv is None: raise ValueError("Non-invertible key.")
    n=text_to_nums(clean_text(ct))
    pairs=chunk2(n); out=[]
    for p in pairs: out.extend(mat_vec_mul(inv,p))
    return nums_to_text(out)

def bruteforce(ct):
    n=text_to_nums(clean_text(ct))
    pairs=chunk2(n)
    for a,b,c,d in product(range(26), repeat=4):
        k=[[a,b],[c,d]]
        if modinv(det2(k),MOD):
            out=[]
            inv=inv_matrix2(k)
            for p in pairs: out.extend(mat_vec_mul(inv,p))
            print(f"{I2A[a]}{I2A[b]}{I2A[c]}{I2A[d]} -> {nums_to_text(out)}")

if __name__=="__main__":
    if len(sys.argv)<3:
        print("Usage:\n  encrypt <key> <text>\n  decrypt <key> <text>\n  bruteforce <cipher>")
        sys.exit(1)
    mode=sys.argv[1].lower()
    if mode=="encrypt":
        print(encrypt(key_from_text(sys.argv[2]), sys.argv[3]))
    elif mode=="decrypt":
        print(decrypt(key_from_text(sys.argv[2]), sys.argv[3]))
    elif mode=="bruteforce":
        bruteforce(sys.argv[2])
3.2



3.3
dingpadding


3.4
G I F I G D G A B


