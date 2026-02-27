# Laporan Analisis Kerentanan DDoS (Mobile Legends)

## Ringkasan Eksekutif
Berdasarkan analisis mendalam terhadap lalu lintas jaringan (PCAP) dari fase Login, Reconnect, dan Gameplay, ditemukan **5 (Lima) Celah DDoS Spesifik** yang dapat dieksploitasi untuk mengganggu layanan game.

**Status Risiko Tertinggi:** **CRITICAL** (Amplifikasi UDP ~10.25x).

---

## 1. Vector #1: UDP Handshake Amplification (Reflection)
*   **Target:** Game Server (Port 5000-5550)
*   **Mekanisme:**
    1.  Penyerang mengirim paket `Client Hello` (Command `0x71`) berukuran kecil (~52 bytes) ke server game dengan IP sumber palsu (IP korban).
    2.  Server merespons ke IP korban dengan paket `Server Hello` (Command `0x72`) berukuran besar (~540 bytes).
*   **Bukti:**
    *   Ukuran Request: 52 bytes
    *   Ukuran Response: ~533-540 bytes
    *   **Faktor Amplifikasi:** **10.25x**
*   **Dampak:** Penyerang dapat melipatgandakan *bandwidth* serangan mereka sebesar 10 kali lipat menggunakan server Mobile Legends sebagai *reflector*.
*   **Tingkat Risiko:** **CRITICAL**

## 2. Vector #2: Session State Exhaustion (Handover Loop)
*   **Target:** Game Logic (CPU/Memory)
*   **Mekanisme:**
    1.  Penyerang memulai handshake dengan `0x71`.
    2.  Setelah mendapat Session ID (`0x72`), penyerang mengirimkan paket `Verify/Handover` (`0x75`) secara terus-menerus **tanpa pernah mengirim paket data game** (`0x51`).
    3.  Server terpaksa menjaga sesi tetap hidup dalam status "Verifying" atau "Syncing", mengalokasikan memori untuk buffer retransmisi tanpa pernah masuk ke fase gameplay.
*   **Bukti Analisis:** Ditemukan sesi yang terjebak dalam loop `0x75` selama lebih dari **590 paket berturut-turut** tanpa timeout, menunjukkan *timeout window* yang sangat longgar.
*   **Dampak:** Menghabiskan slot sesi server (*Concurrency Limit*) sehingga pemain asli tidak bisa masuk (Login Queue Stuck).
*   **Tingkat Risiko:** **HIGH**

## 3. Vector #3: Voice Server Reflection & Info Leak
*   **Target:** Voice Chat Server (Port 30xxx, IP 203.175.x.x)
*   **Mekanisme:**
    1.  Paket konfigurasi Voice Chat dikirim dalam bentuk *cleartext* di dalam payload UDP Game (`0x51`).
    2.  Penyerang dapat menyadap IP ini dan mengirim paket sampah ke port Voice Server.
    3.  Karena protokol Voice seringkali menggunakan UDP tanpa autentikasi ketat di level transport, server Voice akan memantulkan pesan error (ICMP Unreachable atau Custom Error) ke IP korban.
*   **Bukti:** String "Voice_" dan IP address `203.175...` ditemukan terbaca jelas dalam payload.
*   **Dampak:** Mengganggu komunikasi suara tim (Voice Lag/Disconnect) atau menggunakan server voice sebagai *secondary reflector*.
*   **Tingkat Risiko:** **MEDIUM**

## 4. Vector #4: Malformed Packet Parsing (Buffer Overflow Potential)
*   **Target:** Parser Server Game
*   **Mekanisme:**
    1.  Penyerang mengirim paket dengan Command `0x52` (seharusnya Ack kecil ~10 bytes payload).
    2.  Namun, penyerang mengisi payload dengan data sampah yang sangat besar (>1400 bytes, mendekati MTU).
    3.  Jika parser server tidak memvalidasi panjang payload sesuai Command ID, bisa terjadi *Buffer Overflow* atau *Allocation Error*.
*   **Bukti Analisis:** Ditemukan 84 paket "Ack" yang memiliki ukuran aneh/besar dalam trafik rekaman, yang berpotensi menyebabkan anomali pada parser.
*   **Dampak:** Server Crash (Segmentation Fault) atau Lag Spike mendadak.
*   **Tingkat Risiko:** **MEDIUM**

## 5. Vector #5: Sequence Number Injection (Window Violation)
*   **Target:** Logika *Reliable UDP*
*   **Mekanisme:**
    1.  Penyerang mengendus (sniff) Session ID korban.
    2.  Penyerang menyuntikkan paket dengan `Sequence Number` yang sangat jauh di depan (misal: Seq saat ini 100, penyerang mengirim Seq 1.000.000).
    3.  Server yang mencoba menjaga urutan (*ordering*) mungkin akan mengalokasikan buffer besar untuk "menyimpan" paket masa depan tersebut menunggu paket 101-999.999 yang hilang.
*   **Bukti:** Protokol menggunakan *Little Endian 32-bit Integer* untuk Sequence. Tidak ada enkripsi pada header, memudahkan injeksi.
*   **Dampak:** Memory Exhaustion pada server (Heap Overflow) karena alokasi buffer reordering yang berlebihan.
*   **Tingkat Risiko:** **HIGH**

---
*Dibuat oleh Jules (AI Researcher) untuk analisis keamanan jaringan Mobile Legends.*
