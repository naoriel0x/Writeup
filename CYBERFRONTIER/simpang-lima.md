# Simpang Lima — Writeup

**Event:** Cyber Frontier 2026 — Beyond the Attack  
**Kategori:** Network Analysis / Digital Forensics  
**Author:** 0xgeorge  

---

## Deskripsi Soal

> Incident window: 2026-10-11T17:00:00Z through 2026-10-11T17:10:00Z.  
> Resolver: 10.26.0.53/UDP 53.  
> The relevant export was initiated by terminal-TW-204.  
> DNS TXT labels use `pNN.run-ID.archive.lab`. TXT data is `INDEX/TOTAL:BASE64`.  
> Reassemble by run-ID and index; accept only a complete sequence from the leased terminal during the incident window. Decode the concatenated Base64.  
> The answer is the decoded ASCII text; hash it without a newline.

**Lampiran:** `simpang-lima-lampiran.zip`  
Berisi: `dhcp-leases.csv`, `incident.txt`, `simpang-lima.pcap`

---

## Analisis

### DHCP Leases

```csv
client_id,ipv4,valid_from_utc,valid_until_utc
terminal-TW-204,10.26.5.17,2026-10-11T16:00:00Z,2026-10-11T18:00:00Z
test-laptop,10.26.5.99,2026-10-11T16:00:00Z,2026-10-11T18:00:00Z
```

Selama incident window (17:00–17:10 UTC), terminal-TW-204 memegang IP **10.26.5.17**.

### Format DNS TXT

```
pNN.run-ID.archive.lab  →  INDEX/TOTAL:BASE64_DATA
```

Data dieksfiltasi melalui DNS TXT query. Setiap run memiliki beberapa chunk yang harus digabung berdasarkan INDEX.

### Filtering PCAP

Dari analisis PCAP, ditemukan DNS TXT queries dari dua sumber:
- `10.26.5.17` (terminal-TW-204) — sumber yang dicari
- `10.26.5.99` (test-laptop) — bukan terminal yang relevan

---

## Solusi

### Langkah 1 — Ekstrak DNS TXT dari PCAP

```python
from scapy.all import rdpcap, DNS, DNSRR, IP
import datetime

pkts = rdpcap('simpang-lima.pcap')

TERMINAL_IP    = '10.26.5.17'
INCIDENT_START = datetime.datetime(2026, 10, 11, 17, 0, 0)
INCIDENT_END   = datetime.datetime(2026, 10, 11, 17, 10, 0)

for p in pkts:
    if p.haslayer(IP) and p.haslayer(DNS):
        if p[IP].src != TERMINAL_IP:
            continue
        dns = p[DNS]
        if dns.qr == 0 and dns.qd and dns.qd.qtype == 16:
            print(dns.qd.qname.decode())
```

### Langkah 2 — Identifikasi Runs

Semua DNS TXT queries dari `10.26.5.17`:

| run-ID | chunk | index/total | base64 |
|--------|-------|-------------|--------|
| run-7 | 1/5 | 1/5 | `U0wtMjA0fEFS` |
| run-7 | 2/5 | 2/5 | `Q0hJVkUtMTd8` |
| run-7 | 3/5 | 3/5 | `MjAyNi0xMC0x` |
| run-7 | 4/5 | 4/5 | `MVQxNzowMzox` |
| run-7 | 5/5 | 5/5 | `Mlo=` |
| run-8 | 1/5 | 1/5 | *(hanya 2 dari 5 chunk)* |
| run-9 | dari `10.26.5.99` | — | *(terminal salah)* |

### Langkah 3 — Seleksi Run yang Valid

Kriteria penerimaan:
1. ✅ Sumber IP = `10.26.5.17` (terminal-TW-204)
2. ✅ Dalam incident window
3. ✅ Sequence **lengkap** (semua INDEX 1..TOTAL ada)

| run | dari TW-204 | dalam window | lengkap | valid |
|-----|-------------|--------------|---------|-------|
| run-7 | ✅ | ✅ | ✅ 5/5 | **YA** |
| run-8 | ✅ | ✅ | ❌ 2/5 | tidak |
| run-9 | ❌ (10.26.5.99) | ✅ | ✅ 1/1 | tidak |

**Run yang diterima: run-7**

### Langkah 4 — Reassemble dan Decode

```python
import base64, hashlib

parts = {
    1: 'U0wtMjA0fEFS',
    2: 'Q0hJVkUtMTd8',
    3: 'MjAyNi0xMC0x',
    4: 'MVQxNzowMzox',
    5: 'Mlo=',
}

b64 = ''.join(parts[i] for i in sorted(parts))
decoded = base64.b64decode(b64).decode('ascii')
sha256  = hashlib.sha256(decoded.encode('utf-8')).hexdigest()
flag    = f"CF2{{simpang_lima_{sha256[:24]}}}"
```

**Decoded text:** `SL-204|ARCHIVE-17|2026-10-11T17:03:12Z`

---

## Flag

```
CF2{simpang_lima_b5531cbc45bfe17eb13942cb}
```

---

## Ringkasan Teknis

| Langkah | Teknik |
|---------|--------|
| Identifikasi terminal | DHCP lease lookup berdasarkan incident timestamp |
| Ekstrak payload | Filter DNS TXT query dari IP terminal di PCAP |
| Seleksi run | Complete sequence dari terminal yang benar dalam window |
| Decode | Concatenate Base64 → ASCII → SHA-256 untuk flag |
