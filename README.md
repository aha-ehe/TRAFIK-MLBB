# Mobile Legends Traffic Analysis Report

## Pendahuluan
Dokumen ini berisi hasil riset reverse engineering mendalam terhadap lalu lintas jaringan (network traffic) dari game Mobile Legends, berdasarkan analisis file PCAP dan HAR:
1.  `hasil-awal-game.pcap` (Login/Reconnect)
2.  `nyambung -kembali-ke-game.pcap` (Reconnect)
3.  `saat-dalam-pertandingan.pcap` (Gameplay/Sync)
4.  `1.har` (Network Log - Login & Config)

Riset ini mencakup struktur protokol, arsitektur login, enkripsi, dan penilaian kerentanan keamanan.

## Ringkasan Eksekutif
*   **Arsitektur Hibrida:** HTTP/HTTPS (Config & Analytics) -> TCP (Login & Lobby) -> UDP (Match).
*   **Protokol Game:** UDP (Custom Reliable Protocol).
*   **Port Server:** 5508, 5513 (Game Logic), Port 30xxx (Lobby/Voice).
*   **Struktur Paket:** Header kustom 14-byte (Magic Byte `0x01` + Command + Session ID + Seq/Ack).
*   **Keamanan:** Enkripsi lemah pada *control flow* UDP. Session ID dinamis dan berubah saat *reconnect*.
*   **Kerentanan:** Potensi amplifikasi UDP (DDoS) ~10x dan *Information Leakage* (IP & Session ID).

---

## 1. Arsitektur Jaringan Lengkap
Analisis gabungan PCAP dan HAR mengungkapkan arsitektur tiga lapis:

1.  **Layer 1: HTTP/HTTPS (Config & Analytics)**
    *   **Tujuan:** Mengunduh konfigurasi, pelaporan log (Firebase, Adjust), dan layanan pelanggan (AIHelp).
    *   **Domain:** `tnc16-alisg.isnssdk.com`, `app.adjust.com`, `cdn-aihelp.net`.
    *   **Catatan:** HAR file menunjukkan komunikasi intensif dengan SDK pihak ketiga (ByteDance, Google) sebelum login game dimulai, namun **TIDAK** memuat IP Server Game secara langsung. Ini mengindikasikan server game diberikan lewat protokol TCP tertutup, bukan HTTP biasa.

2.  **Layer 2: TCP (Login & Lobby)**
    *   **Tujuan:** Autentikasi akun, matchmaking, chat global, dan pemilihan server.
    *   **Port:** Rentang 30000+ (terlihat di PCAP).
    *   **Mekanisme:** Klien terhubung ke *Gateway Server* via TCP persistent socket. Setelah match ditemukan, server mengirimkan IP dan Port UDP Game Server serta **Session Token** untuk handshake.

3.  **Layer 3: UDP (In-Game Match)**
    *   **Tujuan:** Sinkronisasi state permainan *real-time* (posisi hero, skill).
    *   **Port:** Rentang 5000+ (misal: 5508, 5513).
    *   **IP Server:** Dinamis per match (misal: `103.157.33.7`, `103.157.33.8`).

---

## 2. Analisis Struktur Paket UDP (Reverse Engineering)
Berdasarkan analisis ribuan paket, ditemukan pola header tetap berukuran 14 byte.

### Format Header (14 Bytes)
| Offset | Ukuran | Field | Deskripsi |
| :--- | :--- | :--- | :--- |
| 0x00 | 1 Byte | **Magic Byte** | Selalu `0x01` pada paket game aktif. |
| 0x01 | 1 Byte | **Command** | Menentukan jenis paket (`0x51`, `0x52`, `0x71`, `0x75`). |
| 0x02 | 4 Bytes | **Session ID** | ID unik sesi (Little Endian). Berubah setiap kali *reconnect* atau match baru. |
| 0x06 | 4 Bytes | **Seq Num** | Sequence Number (Little Endian). Penghitung urutan paket. |
| 0x0A | 4 Bytes | **Ack Num** | Acknowledgment Number (Little Endian). Mengonfirmasi paket terakhir. |
| 0x0E | ... | **Payload** | Data game (posisi hero, skill) dan *Control Message*. |

### Jenis Command Teridentifikasi
1.  **0x71 (Client Hello):** Paket inisiasi koneksi UDP. Membawa Token/Session ID yang didapat dari TCP Lobby.
2.  **0x72 (Server Hello):** Respons server memberikan **Session ID Baru** untuk sesi UDP ini.
3.  **0x75 (Handover/Verify):** Klien mengonfirmasi sesi baru. **Dominan pada file sampel (>94%)**, menandakan fase sinkronisasi data (Loading Screen/Reconnect).
4.  **0x51 (Reliable Data):** Paket data utama.
5.  **0x52 (Ack/Heartbeat):** Paket *Keep-alive*.

---

## 3. Analisis Dinamika Sesi & Reconnect
Analisis mendalam pada `saat-dalam-pertandingan.pcap`:

1.  **Dynamic Session ID:** Setiap kali terjadi *reconnect* atau gangguan jaringan, server memberikan Session ID baru via handshake `0x71` -> `0x72`.
    *   *Implikasi:* Serangan *Replay* menggunakan paket lama akan gagal karena Session ID sudah kadaluwarsa.
2.  **Handover Loop (0x75):** Jika koneksi tidak stabil, klien akan terjebak dalam loop command `0x75` untuk mencoba menyinkronkan state terakhir (Snapshot) sebelum diizinkan masuk ke *active gameplay*.

---

## 4. Analisis Keamanan & Kerentanan DDoS

### A. Potensi Amplifikasi (DDoS)
*   **Vector:** UDP Reflection/Amplification.
*   **Mekanisme:** Mengirim paket `0x71` kecil (52 bytes) dengan IP sumber palsu (korban).
*   **Dampak:** Server merespons dengan paket `0x72` yang jauh lebih besar (~540 bytes).
*   **Faktor Amplifikasi:** **~10.25x**.
*   **Risiko:** Tinggi. Penyerang dapat menggunakan server game sebagai *reflector*.

### B. Enkripsi & Privasi
*   **Analisis Entropi:** Rata-rata entropi payload UDP adalah **4.2 - 4.4 bits/byte**.
*   **Kesimpulan:** Data **TIDAK TERENKRIPSI PENUH**. Entropi rendah menunjukkan data kemungkinan hanya dikompresi ringan atau berupa struktur biner mentah.
*   **Bukti:** String ASCII *cleartext* (IP Address, Config Voice) ditemukan dalam payload UDP.

### C. Session Hijacking
*   **Session ID** dikirim *cleartext* di setiap header UDP.
*   Meskipun dinamis, jika penyerang berada dalam jaringan yang sama (Man-in-the-Middle) saat sesi berlangsung, mereka dapat mengambil Session ID aktif dan menyuntikkan paket palsu.

---

## Lampiran Teknis: Login Flow (HAR Analysis)
File `1.har` mengonfirmasi tahap pra-login:
1.  **Config Fetch:** Aplikasi mengontak `tnc16-alisg.isnssdk.com` untuk mendapatkan konfigurasi jaringan (akselerasi, CDN).
2.  **Analytics:** Melaporkan data perangkat ke `app.adjust.com` dan `firebaselogging.googleapis.com`.
3.  **Support Config:** Mengambil FAQ dan konfigurasi bantuan dari `cdn-aihelp.net`.
4.  **Absennya Game IP:** Tidak ditemukannya IP Game Server dalam respons HTTP memperkuat hipotesis bahwa alokasi server terjadi lewat protokol TCP/Socket biner setelah fase HTTP selesai.

---
*Dibuat oleh Jules (AI Researcher) untuk analisis trafik jaringan Mobile Legends.*
