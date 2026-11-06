# Gereja Blenduk — Writeup

**Event:** Cyber Frontier 2026 — Beyond the Attack  
**Kategori:** Reverse Engineering  
**Author:** 0xgeorge  

---

## Deskripsi Soal

> Validator arsip baru tidak lagi memeriksa setiap karakter secara terpisah. Pulihkan serial delapan byte yang memenuhi seluruh pemeriksaan, lalu buka vault. Runtime tersedia sebagai spesifikasi perilaku; analisis statis diperbolehkan.

**Lampiran:** `rev-gereja-blenduk-lampiran.zip`  
Berisi: `program.bin`, `runtime.py`, `vault.json`

---

## Analisis

### Struktur File

```
program.bin  — binary 148 byte berisi matrix koefisien + target (little-endian uint16)
runtime.py   — spesifikasi perilaku validator serial
vault.json   — arsip terenkripsi (ciphertext_hex)
```

### Skema Validasi (runtime.py)

Serial input adalah **8 byte ASCII**. Validator bekerja sebagai berikut:

**Langkah 1 — Transformasi linear per byte:**
```python
v = [(x * 197 + 31) & 0xFF for x in serial]
```

**Langkah 2 — Pemeriksaan sistem linear 8×8 (mod 257):**
```python
for i in range(8):
    assert sum(A[i][j] * v[j] for j in range(8)) % 257 == T[i]
```

Dimana `A` (8×8 matrix koefisien) dan `T` (8 target) dibaca dari `program.bin`.

### Format program.bin

```
magic   : 4 byte  ("BLV5")
data    : 72 × uint16 LE
  A[0..7][0..7] : 64 uint16  (matrix 8×8)
  T[0..7]       :  8 uint16  (target vector)
```

```python
import struct
b = open('program.bin', 'rb').read()
a = struct.unpack('<72H', b[4:])
A = [list(a[8*i : 8*i+8]) for i in range(8)]
T = list(a[64:72])
```

**Matrix A:**
```
[64,  132, 208,  38, 156,  86,  50,  73]
[132, 107, 160,  64, 192,  61,  82, 190]
[124, 120,  57,  92,   2,  33, 207,  10]
[159,   5,  15, 202, 252,  56,  44, 115]
[ 22,  63,  19,  30, 214, 234,  82, 215]
[ 59, 204, 220, 184, 187, 198, 172,  20]
[210, 163, 248,  46,  83,  72, 224, 167]
[ 83,  42, 237, 224,  73, 123, 211, 252]
```

**Target T:** `[195, 129, 7, 54, 141, 6, 62, 24]`

---

## Solusi

### Langkah 1 — Solve Sistem Linear atas Z/257Z

257 adalah bilangan prima, sehingga Z/257Z adalah *field*. Gunakan eliminasi Gauss mod 257.

```python
def modinv(x, m):
    g, inv, _ = extended_gcd(x % m, m)
    return inv % m if g == 1 else None

def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    g, x, y = extended_gcd(b % a, a)
    return g, y - (b // a) * x, x

def solve_mod(mat, tgt, mod):
    n   = len(mat)
    aug = [mat[i][:] + [tgt[i]] for i in range(n)]
    for col in range(n):
        pivot = next((r for r in range(col, n) if aug[r][col] % mod), None)
        aug[col], aug[pivot] = aug[pivot], aug[col]
        inv = modinv(aug[col][col], mod)
        aug[col] = [(x * inv) % mod for x in aug[col]]
        for row in range(n):
            if row != col and aug[row][col] % mod:
                f = aug[row][col]
                aug[row] = [(aug[row][k] - f * aug[col][k]) % mod for k in range(n+1)]
    return [aug[i][n] % mod for i in range(n)]

v = solve_mod(A, T, 257)
# v = [156, 155, 79, 196, 97, 19, 17, 98]
```

Verifikasi: semua 8 persamaan terpenuhi. ✅

---

### Langkah 2 — Invert Transformasi v → s

Dari `v[j] = (s[j] * 197 + 31) & 0xFF`:

```
s[j] = (v[j] - 31) * inv(197) mod 256
```

Cari invers 197 mod 256 (gcd(197, 256) = 1, invers ada):

```python
inv197 = modinv(197, 256)  # = 13

s_bytes = [((vi - 31) * inv197) % 256 for vi in v]
serial  = bytes(s_bytes).decode('ascii')
```

**Verifikasi per byte:**

| i | s | v_expected | (s×197+31)&0xFF | match |
|---|---|-----------|-----------------|-------|
| 0 | 89 (Y) | 156 | 156 | ✅ |
| 1 | 76 (L) | 155 | 155 | ✅ |
| 2 | 112 (p) | 79 | 79 | ✅ |
| 3 | 97 (a) | 196 | 196 | ✅ |
| 4 | 90 (Z) | 97 | 97 | ✅ |
| 5 | 100 (d) | 19 | 19 | ✅ |
| 6 | 74 (J) | 17 | 17 | ✅ |
| 7 | 103 (g) | 98 | 98 | ✅ |

**Serial:** `YLpaZdJg`

---

### Langkah 3 — Buka Vault

```bash
python3 runtime.py YLpaZdJg
```

---

## Flag

```
CF2{rev_gereja_blenduk_de2fe1fb3466b18bfaaa}
```

---

## Ringkasan Teknis

| Langkah | Teknik |
|---------|--------|
| Parse binary | Struct unpack little-endian uint16 |
| Solve constraint | Eliminasi Gauss atas Z/257Z (prime field) |
| Invert transform | Modular inverse: `inv(197) mod 256 = 13` |
| Recover serial | 8 byte ASCII = `YLpaZdJg` |
