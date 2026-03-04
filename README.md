# Mobile Legends Traffic Analysis Report

## Pendahuluan
Dokumen ini berisi hasil riset reverse engineering mendalam terhadap lalu lintas jaringan (network traffic) dari game Mobile Legends, berdasarkan analisis file PCAP dan HAR. Riset ini mencakup struktur protokol, arsitektur login, enkripsi, dan penilaian kerentanan keamanan.

**Lihat `ddos.md` untuk detail lengkap 8 vektor serangan DDoS yang ditemukan.**

## Ringkasan Eksekutif
*   **Arsitektur Hibrida:** HTTP/HTTPS (Config & Analytics) -> TCP (Login & Lobby) -> UDP (Match).
*   **Protokol Game:** UDP (Custom Reliable Protocol).
*   **Port Server:** 5508, 5513 (Game Logic), Port 30xxx (Lobby/Voice).
*   **Struktur Paket:** Header kustom 14-byte (Magic Byte `0x01` + Command + Session ID + Seq/Ack).
*   **Keamanan:** Enkripsi lemah pada *control flow* UDP. Session ID dinamis.
*   **Kerentanan:** Potensi amplifikasi UDP (DDoS) ~10x, Checksum Bypass (>50% packets), dan State Exhaustion.

---

## Direktori `vulnerability_pocs/`
Folder ini berisi skrip Proof-of-Concept (PoC) Python untuk menganalisis dan mendemonstrasikan kerentanan spesifik yang ditemukan:

| Script | Vektor Serangan (ID) | Deskripsi |
| :--- | :--- | :--- |
| `poc_amplification_calc.py` | **V-01** | Menghitung faktor amplifikasi handshake UDP (`0x71` -> `0x72`). |
| `poc_state_exhaustion_detect.py` | **V-02** | Mendeteksi sesi yang terjebak dalam loop `0x75` (Handover). |
| `poc_seq_injection_sim.py` | **V-03** | Menganalisis validasi Sequence Number dan *Window Injection*. |
| `poc_malformed_fuzz.py` | **V-04** | Mencari anomali ukuran payload (target Fuzzing). |
| `poc_voice_reflection_scan.py` | **V-05** | Memindai payload untuk kebocoran IP Voice Server (*cleartext*). |
| `poc_checksum_bypass.py` | **V-06** | Mengukur persentase paket dengan UDP Checksum = 0. |
| `poc_fragmentation_sim.py` | **V-07** | Menganalisis fragmentasi IP (Reassembly Exhaustion). |
| `poc_ttl_expiry_sim.py` | **V-08** | Menganalisis distribusi TTL untuk potensi serangan ICMP. |

**Cara Penggunaan:**
```bash
python3 vulnerability_pocs/poc_amplification_calc.py <file.pcap>
```

---

## 1. Arsitektur Jaringan Lengkap
Analisis gabungan PCAP dan HAR mengungkapkan arsitektur tiga lapis:

1.  **Layer 1: HTTP/HTTPS (Config & Analytics)**
    *   **Tujuan:** Mengunduh konfigurasi, pelaporan log (Firebase, Adjust).
    *   **Domain:** `tnc16-alisg.isnssdk.com`, `app.adjust.com`.
2.  **Layer 2: TCP (Login & Lobby)**
    *   **Tujuan:** Autentikasi akun, matchmaking.
    *   **Port:** Rentang 30000+.
3.  **Layer 3: UDP (In-Game Match)**
    *   **Tujuan:** Sinkronisasi state permainan *real-time*.
    *   **Port:** Rentang 5000+ (misal: 5508, 5513).

---

## 2. Analisis Struktur Paket UDP
Header tetap berukuran 14 byte:
`Magic (1) | Command (1) | Session ID (4) | Seq (4) | Ack (4) | Payload (...)`

**Command Penting:**
*   `0x71`: Client Hello (Init)
*   `0x72`: Server Hello (Session ID)
*   `0x75`: Handover/Verify (Sync Loop)
*   `0x51`: Game Data (Payload)

---

## 3. Analisis Keamanan Utama

### A. Potensi Amplifikasi (DDoS)
*   **Vector:** UDP Reflection/Amplification.
*   **Faktor Amplifikasi:** **~10.25x**.
*   **Risiko:** Tinggi. Penyerang dapat menggunakan server game sebagai *reflector*.

### B. UDP Checksum Bypass (Integrity)
*   **Temuan:** >50% paket memiliki Checksum 0.
*   **Risiko:** Memungkinkan serangan *Bit-Flipping* di tengah jalan tanpa terdeteksi oleh stack jaringan.

### C. Enkripsi & Privasi
*   **Analisis Entropi:** Rata-rata entropi payload UDP rendah (~4.2 bits/byte).
*   **Bukti:** String ASCII *cleartext* (IP Address, Config Voice) ditemukan dalam payload UDP.

---
*Dibuat oleh Jules (AI Researcher) untuk analisis trafik jaringan Mobile Legends.*
