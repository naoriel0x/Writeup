# Stasiun Tawang — Writeup

**Event:** Cyber Frontier 2026 — Beyond the Attack  
**Kategori:** Network Analysis / Digital Forensics  
**Author:** 0xgeorge  

---

## Deskripsi Soal

> Terminal TW-17 diduga mengirim arsip melalui resolver. Identifikasi lalu lintas terminal pada waktu insiden dan pulihkan objek lengkap, dengan menghindari retransmisi dan fragmen rusak.

**Lampiran:** `net-stasiun-tawang-lampiran.zip`  
Berisi: `dhcp.csv`, `incident.txt`, `tawang.pcap`

---

## Analisis

### Incident Info

```
Insiden: 12 Oktober 2026 09:20 WIB
Capture: RAW/IPv4/UDP
Format sinkronisasi: session.seq.chunk.crc32.sync.archive.invalid
CRC32 dihitung pada teks chunk ASCII
Encoding objek: base32 → zlib standard archive
```

### DHCP Leases

```csv
asset,ip,start_utc,end_utc
TW-17,192.0.2.61,2026-10-11T00:00Z,2026-10-12T00:00Z
TW-17,192.0.2.77,2026-10-12T00:00Z,2026-10-13T00:00Z
TW-23,192.0.2.88,2026-10-12T00:00Z,2026-10-13T00:00Z
```

Insiden terjadi pada **12 Oktober 2026**, sehingga TW-17 menggunakan IP **192.0.2.77**.

### Format DNS Query

```
session.seq.chunk.crc32.sync.archive.invalid
   b7e4.000.PCOHG5RTVLHEWLMJF4.01810e1a.sync.archive.invalid
```

| Field | Keterangan |
|-------|-----------|
| `session` | ID sesi (b7e4) |
| `seq` | Nomor urut chunk (000, 001, ...) |
| `chunk` | Data base32 |
| `crc32` | CRC32 hex dari teks chunk ASCII |

---

## Solusi

### Langkah 1 — Identifikasi IP TW-17 pada Waktu Insiden

```python
# 12 Oktober 2026 → TW-17 memakai 192.0.2.77
TARGET_IP = '192.0.2.77'
```

### Langkah 2 — Ekstrak Semua DNS Queries dari TW-17

```python
from scapy.all import rdpcap, DNS, IP
pkts = rdpcap('tawang.pcap')

for p in pkts:
    if p.haslayer(IP) and p.haslayer(DNS) and p[IP].src == TARGET_IP:
        name = p[DNS].qd.qname.decode().rstrip('.')
        print(name)
```

**Hasil — queries dari 192.0.2.77:**
```
b7e4.002.NREYOWWRMGDH5GP4SY.67886973.sync.archive.invalid
b7e4.000.PCOHG5RTVLHEWLMJF4.01810e1a.sync.archive.invalid
b7e4.001.XESLGOFTGYWL2JFRH4.67deebb8.sync.archive.invalid
b7e4.004.QQ4BPF2AQCAV.399b9605.sync.archive.invalid
b7e4.002.YS4PG5HDGMRWWOYERN.67886973.sync.archive.invalid
b7e4.000.4FJMLWEHLVTR5GHOCP.01810e1a.sync.archive.invalid
b7e4.004.VACQA2FPB4QQ.399b9605.sync.archive.invalid
b7e4.001.4HRFJ2LWYGTFOGLSEX.67deebb8.sync.archive.invalid
b7e4.003.KMJW3DAS2NWFEDGMNV.220ecab4.sync.archive.invalid
b7e4.003.VNMGDEFWN2SAD3WJMK.220ecab4.sync.archive.invalid
```

Setiap sequence (000–004) memiliki **dua varian chunk** — satu valid, satu retransmisi/korup.

### Langkah 3 — Verifikasi CRC32

Untuk setiap varian, verifikasi: `CRC32(chunk.encode('ascii')) == crc32_field`

```python
import binascii, collections

chunks = collections.defaultdict(set)

for p in pkts:
    if p.haslayer(IP) and p.haslayer(DNS) and p[IP].src == TARGET_IP:
        name  = p[DNS].qd.qname.decode().rstrip('.')
        parts = name.split('.')
        if len(parts) == 7 and parts[4] == 'sync':
            session, seq, chunk, crc32_hex = parts[0], parts[1], parts[2], parts[3]
            chunks[seq].add((chunk, crc32_hex))

valid = {}
for seq in sorted(chunks.keys()):
    for chunk, expected in chunks[seq]:
        computed = format(binascii.crc32(chunk.encode('ascii')) & 0xFFFFFFFF, '08x')
        if computed == expected:
            valid[seq] = chunk
            print(f'seq {seq}: VALID  → {chunk}')
        else:
            print(f'seq {seq}: REJECT → {chunk}  (got {computed}, expected {expected})')
```

**Hasil verifikasi:**

| seq | chunk VALID | chunk DITOLAK |
|-----|-------------|---------------|
| 000 | `PCOHG5RTVLHEWLMJF4` ✅ | `4FJMLWEHLVTR5GHOCP` ❌ |
| 001 | `XESLGOFTGYWL2JFRH4` ✅ | `4HRFJ2LWYGTFOGLSEX` ❌ |
| 002 | `YS4PG5HDGMRWWOYERN` ✅ | `NREYOWWRMGDH5GP4SY` ❌ |
| 003 | `KMJW3DAS2NWFEDGMNV` ✅ | `VNMGDEFWN2SAD3WJMK` ❌ |
| 004 | `VACQA2FPB4QQ` ✅ | `QQ4BPF2AQCAV` ❌ |

> **Catatan:** Chunk yang ditolak terlihat seperti versi terbalik/scramble dari chunk valid. Ini adalah fragmen korup yang sengaja dimasukkan sebagai noise.

### Langkah 4 — Reassemble dan Decode

```python
import base64, zlib

ordered = ''.join(valid[s] for s in sorted(valid.keys()))

# Pad ke kelipatan 8 untuk base32
padded = ordered + '=' * ((8 - len(ordered) % 8) % 8)
raw    = base64.b32decode(padded)

result = zlib.decompress(raw)
print(result.decode())
```

**Proses:**
```
Concatenated base32:
PCOHG5RTVLHEWLMJF4XESLGOFTGYWL2JFRH4YS4PG5HDGMRWWOYERNKMJW3DAS2NWFEDGMNVVACQA2FPB4QQ

After base32 decode (52 bytes): 789c73...  (zlib magic: 78 9c)
After zlib decompress: CF2{net_stasiun_tawang_3f23688e9ec86ed8f458}
```

---

## Flag

```
CF2{net_stasiun_tawang_3f23688e9ec86ed8f458}
```

---

## Ringkasan Teknis

| Langkah | Teknik |
|---------|--------|
| Identifikasi terminal | DHCP lease lookup pada tanggal insiden |
| Filter traffic | IP source = 192.0.2.77 |
| Validasi chunk | CRC32 verification per sequence |
| Reject fragmen korup | Chunk dengan CRC32 mismatch dibuang |
| Decode | Base32 decode → zlib decompress |
