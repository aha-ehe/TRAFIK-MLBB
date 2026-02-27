# Mobile Legends Traffic Analysis Report

## Pendahuluan
Dokumen ini berisi hasil riset reverse engineering mendalam terhadap lalu lintas jaringan (network traffic) dari game Mobile Legends, berdasarkan analisis file PCAP:
1.  `hasil-awal-game.pcap` (Login/Reconnect)
2.  `nyambung -kembali-ke-game.pcap` (Reconnect)
3.  `saat-dalam-pertandingan.pcap` (Gameplay/Sync)

Riset ini mencakup struktur protokol, pola handshake, enkripsi, dan penilaian kerentanan keamanan.

## Ringkasan Eksekutif
*   **Protokol Utama:** UDP (Custom Reliable Protocol)
*   **Port Server:** 5508, 5513 (Game Logic), Port 30xxx (Voice/Chat)
*   **Server IP Utama:** `103.157.33.7` (Login), `103.157.33.8` (Game)
*   **Struktur Paket:** Header kustom 14-byte (Magic Byte `0x01` + Command + Session ID + Seq/Ack).
*   **Keamanan:** Enkripsi lemah atau tidak ada pada *control flow*. String seperti IP dan "Voice_" dikirim dalam bentuk *cleartext*.
*   **Kerentanan:** Potensi amplifikasi UDP (DDoS) ~10x dan *Information Leakage* (IP & Session ID).

---

## 1. Arsitektur Jaringan & Performa
Komunikasi utama dalam pertandingan (in-match) menggunakan protokol UDP yang dimodifikasi untuk keandalan (*reliability*).

*   **Transport Layer:** UDP
*   **Game Tick Rate:** Estimasi **~15.4 - 16 Hz** (1 paket setiap ~60-65 ms) selama fase sinkronisasi/reconnect.
    *   *Catatan:* Tick rate ini konsisten rendah pada semua file sampel, mengindikasikan bahwa file-file tersebut menangkap fase *loading state* berat, bukan *smooth gameplay* (yang biasanya 30/60 Hz).
*   **Pola Koneksi:**
    *   Klien menggunakan port dinamis.
    *   Saat *reconnect*, klien melakukan handshake ulang dan mendapatkan Session ID baru.
    *   Server game berpindah port (misal dari 5508 ke 5513) tergantung pada *match instance*.

---

## 2. Analisis Struktur Paket (Reverse Engineering)
Berdasarkan analisis ribuan paket, ditemukan pola header tetap berukuran 14 byte.

### Format Header (14 Bytes)
| Offset | Ukuran | Field | Deskripsi |
| :--- | :--- | :--- | :--- |
| 0x00 | 1 Byte | **Magic Byte** | Selalu `0x01` pada paket game aktif. |
| 0x01 | 1 Byte | **Command** | Menentukan jenis paket (`0x51`, `0x52`, `0x71`, `0x75`). |
| 0x02 | 4 Bytes | **Session ID** | ID unik sesi (Little Endian). Berubah setiap kali *reconnect*. |
| 0x06 | 4 Bytes | **Seq Num** | Sequence Number (Little Endian). Penghitung urutan paket. |
| 0x0A | 4 Bytes | **Ack Num** | Acknowledgment Number (Little Endian). Mengonfirmasi paket terakhir. |
| 0x0E | ... | **Payload** | Data game (posisi hero, skill) dan *Control Message*. |

### Jenis Command Teridentifikasi
1.  **0x71 (Client Hello):** Paket inisiasi koneksi. Mengandung *string* identifikasi terbalik/scrambled: `eH tSEb abom ELIBOm` -> *"Mobile MOBA Best He..."* (Mobile Legends).
2.  **0x72 (Server Hello):** Respons server memberikan **Session ID** baru.
3.  **0x75 (Handover/Verify):** Klien mengonfirmasi sesi baru. **Dominan pada file sampel (>94%)**, menandakan fase sinkronisasi data yang panjang.
4.  **0x51 (Reliable Data):** Paket data utama (Payload posisi/skill/chat).
5.  **0x52 (Ack/Heartbeat):** Paket kecil (~10 bytes payload) untuk *Keep-alive*.

---

## 3. Analisis Proses Handshake & Reconnect
Analisis mendalam pada `saat-dalam-pertandingan.pcap` dan file lainnya:

1.  **Dominasi Command 0x75:** Pada file gameplay yang baru, 94.7% trafik adalah command `0x75`. Ini bukan *active gameplay*, melainkan **Handover Loop**. Klien dan server terus menerus menyinkronkan state (kemungkinan karena koneksi tidak stabil atau packet loss tinggi).
2.  **State Snapshot:** Paket `0x51` yang muncul memiliki ukuran besar (300-500 bytes) dan frekuensi rendah, ciri khas pengiriman *State Snapshot* (posisi semua hero, minion, turret) sekaligus, bukan update pergerakan *delta* yang kecil.

---

## 4. Analisis Keamanan & Kerentanan DDoS

### A. Potensi Amplifikasi (DDoS)
*   **Vector:** UDP Reflection/Amplification.
*   **Mekanisme:** Mengirim paket `0x71` kecil (52 bytes) dengan IP sumber palsu (korban).
*   **Dampak:** Server merespons dengan paket `0x72` yang jauh lebih besar (~540 bytes).
*   **Faktor Amplifikasi:** **~10.25x**.
*   **Risiko:** Tinggi. Penyerang dapat menggunakan server game sebagai *reflector*.

### B. Enkripsi & Privasi (Information Leakage)
*   **Analisis Entropi:** Rata-rata entropi payload adalah **4.2 - 4.4 bits/byte**.
*   **Kesimpulan:** Data **TIDAK TERENKRIPSI PENUH**. Entropi rendah menunjukkan data kemungkinan hanya dikompresi ringan atau berupa struktur biner mentah.
*   **Bukti:** String ASCII *cleartext* (IP Address, Config Voice) ditemukan dalam payload.

### C. Session Hijacking
*   **Session ID** dikirim *cleartext* di setiap header.
*   Jika penyerang dapat mengendus (sniff) jaringan, mereka dapat mengambil Session ID dan melakukan *Packet Injection*.

---

## Lampiran Teknis Lanjutan

### A. Fingerprint Protokol
*   **Offset 00 (Sub-command):** Sangat bervariasi.
*   **Offset 01-07 (Control Fields):** Pola tetap `45 03 70 ...` sering muncul, kemungkinan header objek game.

### B. Analisis Gameplay (File Baru)
File `saat-dalam-pertandingan.pcap` (IP Server `103.157.33.8`, Port `5513`) mengonfirmasi temuan sebelumnya:
*   **Tick Rate Rendah (~15 Hz):** Konsisten dengan mode *Safety/Sync*.
*   **Packet Loss/Retransmission:** Sangat tinggi. Indikasi koneksi buruk atau mekanisme *Reliable UDP* yang agresif saat paket drop.
*   **Kesimpulan:** Sampel trafik yang ada lebih merepresentasikan kondisi jaringan buruk (lag/reconnect) daripada kondisi ideal.

---
*Dibuat oleh Jules (AI Researcher) untuk analisis trafik jaringan Mobile Legends.*
