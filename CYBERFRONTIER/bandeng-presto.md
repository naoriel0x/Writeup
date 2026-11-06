# Bandeng Presto — Writeup

**Event:** Cyber Frontier 2026 — Beyond the Attack  
**Kategori:** Cryptography  
**Author:** 0xgeorge  

---

## Deskripsi Soal

> Pulihkan arsip BP-POOL dari kapsul perangkat. Spesifikasi skema, format, dan pemeriksaan integritas ada di `files/recovery-spec.txt`. Satu kapsul memiliki isi yang tidak sesuai dengan commitment provisioning. Temukan dan tolak kapsul tersebut, pulihkan secret dengan jumlah minimum kapsul sah, kemudian autentikasi dan dekripsi arsip.
>
> Jawaban adalah plaintext arsip persis, tanpa newline. Format flag:  
> `CF2{bandeng_presto_<24 karakter pertama SHA256(plaintext UTF-8), heksadesimal huruf kecil>}`

**Lampiran:** `bandeng-presto-lampiran.zip`  
Berisi: `archive.enc`, `device-shares.csv`, `recovery-spec.txt`

---

## Analisis

### Struktur File

```
archive.enc       — arsip terenkripsi (JSON)
device-shares.csv — 5 kapsul perangkat beserta commitment SHA-256
recovery-spec.txt — spesifikasi skema pemulihan
```

### Skema Kriptografi

Setelah membaca `recovery-spec.txt`, skema yang digunakan adalah:

1. **Shamir Secret Sharing** atas **GF(2⁸)** dengan polinomial irreduksi `0x11B`, threshold **2-of-5**
2. Setiap kapsul memiliki *provisioning commitment* = SHA-256 dari `"<x_desimal>:" + raw_share_bytes`
3. Arsip terenkripsi menggunakan *keystream* XOR: `SHA-256(secret || counter32be)` mulai counter 0
4. Format `archive.enc` adalah JSON berisi `ciphertext_hex` dan `hmac_sha256`
5. Verifikasi HMAC-SHA256 dengan key = secret atas ciphertext sebelum menerima plaintext

### Isi `device-shares.csv`

| device | x | share_hex | commitment |
|--------|---|-----------|------------|
| BP-01 | 1 | `1f3f5f7f9fbfdfff8f2f4f6f8fafcfef` | `10a001...` |
| BP-02 | 2 | `88ee80dada98d634350fd55c7bc35266` | `4e1b3f...` |
| BP-03 | 3 | `0ca13cb91085d184aae6a34ddee7d0e8` | `a2854b...` |
| BP-04 | 4 | `bd5725d150d6c4b95a4ffa3a881b736f` | `568773...` |
| BP-05 | 5 | `391899e89acbc309c5a68c2b2d3ff1e1` | `bf6e57...` |

---

## Solusi

### Langkah 1 — Verifikasi Commitment

Untuk setiap kapsul, hitung SHA-256 dari `f"{x}:".encode() + share_bytes` dan bandingkan dengan commitment.

```python
import hashlib, csv

shares = {}
with open('device-shares.csv') as f:
    for row in csv.DictReader(f):
        x   = int(row['x'])
        sh  = bytes.fromhex(row['share_hex'])
        cmt = row['provisioning_commitment_sha256']
        computed = hashlib.sha256(f'{x}:'.encode() + sh).hexdigest()
        valid = (computed == cmt)
        shares[row['device']] = {'x': x, 'sh': sh, 'valid': valid}
        print(f"{row['device']}: {'OK' if valid else 'TAMPERED'}")
```

**Hasil:**
```
BP-01: OK
BP-02: OK
BP-03: OK
BP-04: TAMPERED  <-- kapsul ditolak
BP-05: OK
```

Kapsul **BP-04** memiliki share yang tidak sesuai commitmentnya.

---

### Langkah 2 — Pemulihan Secret via Shamir (GF 2⁸)

Dengan threshold 2-of-5, cukup gunakan 2 kapsul valid untuk interpolasi Lagrange di x=0.

Operasi GF(2⁸) dengan polinomial `0x11B`:
- Penjumlahan: XOR
- Perkalian: perkalian polinomial dengan reduksi modulo `0x11B`

```python
def gf_mul(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a  = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p

def gf_inv(a):
    result, base, exp = 1, a, 254
    while exp > 0:
        if exp & 1:
            result = gf_mul(result, base)
        base = gf_mul(base, base)
        exp >>= 1
    return result

def lagrange_at_zero(x1, y1, x2, y2):
    inv_d = gf_inv(x1 ^ x2)
    return gf_mul(gf_mul(y1, x2), inv_d) ^ gf_mul(gf_mul(y2, x1), inv_d)
```

Pemulihan secret byte-per-byte menggunakan BP-01 (x=1) dan BP-02 (x=2):

```python
s1 = shares['BP-01']
s2 = shares['BP-02']
n  = len(s1['sh'])

secret = bytes([
    lagrange_at_zero(s1['x'], s1['sh'][i], s2['x'], s2['sh'][i])
    for i in range(n)
])
```

**Secret:** `9b70e31c55a2d84f10c6397e2a8b4d61`

Verifikasi silang dengan pasangan BP-01 + BP-03 menghasilkan secret yang sama. ✅

---

### Langkah 3 — Autentikasi dan Dekripsi Arsip

`archive.enc` ternyata berformat JSON:
```json
{
  "ciphertext_hex": "62fbd1d047274b1daaf09d01d0e35dd98da05100f9364f1b13412a4e5c",
  "hmac_sha256":    "70ccdec8e3c1ca94989a188e9974c2022ec96c037ab48d9dc626164e35291e56"
}
```

**Verifikasi HMAC:**
```python
import hmac as hmac_mod, hashlib

ciphertext = bytes.fromhex(data['ciphertext_hex'])
mac_expected = bytes.fromhex(data['hmac_sha256'])

computed_mac = hmac_mod.new(secret, ciphertext, hashlib.sha256).digest()
assert hmac_mod.compare_digest(mac_expected, computed_mac)  # True
```

**Dekripsi (keystream XOR):**
```python
import struct

keystream = b''
counter   = 0
while len(keystream) < len(ciphertext):
    keystream += hashlib.sha256(secret + struct.pack('>I', counter)).digest()
    counter   += 1
keystream = keystream[:len(ciphertext)]

plaintext = bytes(a ^ b for a, b in zip(ciphertext, keystream)).decode('utf-8')
```

---

## Flag

**Plaintext:** `BP-POOL|R-73|restore=complete`

```python
import hashlib
sha = hashlib.sha256('BP-POOL|R-73|restore=complete'.encode()).hexdigest()
flag = f"CF2{{bandeng_presto_{sha[:24]}}}"
```

```
CF2{bandeng_presto_934e1e05dfaccf58f01482c3}
```

---

## Ringkasan Teknis

| Langkah | Teknik |
|---------|--------|
| Verifikasi kapsul | SHA-256 commitment check |
| Pemulihan secret | Shamir Secret Sharing — interpolasi Lagrange atas GF(2⁸) |
| Autentikasi | HMAC-SHA256 |
| Dekripsi | Stream cipher XOR — keystream SHA-256(secret \|\| counter) |
