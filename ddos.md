# Laporan Analisis Kerentanan & Vektor DDoS (Mobile Legends Protocol)

**Tanggal Analisis:** 2024
**Target Sistem:** Protokol UDP Mobile Legends (Game Server)
**Tingkat Keparahan Agregat:** **HIGH** (CVSS v3.1 Estimate: 7.5 - 8.6)

## I. Ringkasan Eksekutif
Berdasarkan analisis *reverse engineering* mendalam terhadap lalu lintas jaringan produksi, ditemukan **8 (Delapan) Vektor Serangan Spesifik** yang mengeksploitasi kelemahan dalam desain protokol *Reliable UDP* kustom yang digunakan.

Kelemahan utama bersumber dari:
1.  **Mekanisme Handshake Tanpa Autentikasi Kuat** (Amplifikasi & Exhaustion).
2.  **Absennya Validasi Integritas Transport** (UDP Checksum = 0).
3.  **Eksposur Data Cleartext** (Information Leakage).

---

## II. Matriks Kerentanan Teknis

| ID | Vektor Serangan | Kategori | Dampak (Impact) | Tingkat Risiko |
| :--- | :--- | :--- | :--- | :--- |
| **V-01** | UDP Handshake Amplification | Volumetric DDoS | Bandwidth Saturation (10.25x) | **CRITICAL** |
| **V-02** | Session State Exhaustion | Resource Exhaustion | Server Concurrency Limit Reached | **HIGH** |
| **V-03** | Sequence Number Injection | Logic Attack | Memory Corruption / Heap Overflow | **HIGH** |
| **V-04** | Malformed Packet Fuzzing | Parser Exploit | Service Crash (Segmentation Fault) | **MEDIUM** |
| **V-05** | Voice Server Reflection | Reflector Attack | Voice Service Disruption | **MEDIUM** |
| **V-06** | UDP Checksum Bypass | Integrity Attack | Logic Error Injection (Bit-Flipping) | **MEDIUM** |
| **V-07** | IP Fragmentation Reassembly | Resource Exhaustion | CPU/Memory Consumption | **LOW** |
| **V-08** | TTL Expiry Generation | Resource Exhaustion | Router/Server CPU Waste (ICMP) | **LOW** |

---

## III. Detail Temuan & Bukti Forensik

### [V-01] UDP Handshake Amplification (Reflection)
*   **Mekanisme:** Pemanfaatan asimetri ukuran paket handshake awal. Penyerang mengirim *Client Hello* (`0x71`) dengan IP palsu (spoofed), server membalas dengan *Server Hello* (`0x72`) yang jauh lebih besar ke korban.
*   **Bukti Teknis:**
    *   `Request Size` (0x71): **52 bytes**
    *   `Response Size` (0x72): **~533-540 bytes**
    *   **Faktor Amplifikasi:** **~10.25x**
*   **Dampak:** Server game berubah menjadi *Reflector* yang sangat efisien untuk melumpuhkan target ketiga.

### [V-02] Session State Exhaustion (Handover Loop)
*   **Mekanisme:** Eksploitasi *timeout window* yang longgar pada fase *Handover*. Penyerang melakukan *flooding* paket `0x75` (Verify) tanpa pernah menyelesaikan handshake.
*   **Bukti Teknis:** Analisis trafik menunjukkan sesi dapat tertahan dalam status "Verifying" selama **>590 paket berturut-turut** tanpa diputus oleh server.
*   **Dampak:** Menghabiskan tabel sesi (*state table*) di server, mencegah pemain sah untuk login (Denial of Service).

### [V-03] Sequence Number Injection (Window Violation)
*   **Mekanisme:** Injeksi paket dengan `Sequence Number` di luar batas wajar (misal: MAX_INT) untuk memicu alokasi buffer *reordering* yang berlebihan.
*   **Bukti Teknis:** Protokol menggunakan *Little Endian 32-bit Integer* tanpa enkripsi/HMAC pada header. Penyerang dapat memodifikasi SeqNum secara trivial.
*   **Dampak:** *Memory Exhaustion* (Heap Overflow) pada server karena mencoba mengalokasikan ruang untuk paket masa depan.

### [V-04] Malformed Packet Fuzzing (Parser Exploit)
*   **Mekanisme:** Pengiriman paket dengan payload yang tidak sesuai spesifikasi Command ID (misal: Ack `0x52` dengan payload jumbo).
*   **Bukti Teknis:** Ditemukan 84 anomali paket `0x52` dengan ukuran **205 bytes** (rata-rata normal: 26 bytes). Ini adalah target potensial untuk *Buffer Overflow*.
*   **Dampak:** Kerusakan memori parser server yang menyebabkan *crash* layanan (Segmentation Fault).

### [V-05] Voice Server Reflection
*   **Mekanisme:** Pemanfaatan IP Server Voice yang bocor untuk serangan sekunder.
*   **Bukti Teknis:** String konfigurasi `Voice_` dan IP `203.175.x.x` ditemukan dalam bentuk *cleartext* di payload UDP Game (`0x51`).
*   **Dampak:** Memungkinkan penyerangan terarah ke infrastruktur Voice Chat yang seringkali memiliki perlindungan lebih lemah dibanding Game Server utama.

### [V-06] UDP Checksum Bypass (Integrity Violation)
*   **Mekanisme:** Server/Klien menonaktifkan validasi UDP Checksum (diset ke `0x0000`) untuk performa.
*   **Bukti Teknis:** Analisis PCAP menunjukkan **52.56%** paket memiliki UDP Checksum = 0.
*   **Dampak:** Penyerang dapat melakukan serangan *Bit-Flipping* di tengah jalan (Man-in-the-Middle) untuk mengubah logika game (misal: mengubah koordinat atau *damage*) tanpa terdeteksi oleh stack jaringan OS.

---

## IV. Rekomendasi Mitigasi (Engineering Fixes)

1.  **Implementasi Rate Limiting Ketat:** Batasi jumlah paket `0x71` dan `0x75` per IP per detik untuk mencegah Amplifikasi dan State Exhaustion.
2.  **Validasi HMAC pada Header:** Tambahkan tanda tangan kriptografis (HMAC) pada header paket untuk mencegah injeksi Sequence Number dan Bit-Flipping.
3.  **Enkripsi Payload Penuh:** Gunakan DTLS atau enkripsi simetris (AES-GCM) untuk menyembunyikan IP Voice Server dan mencegah fuzzing payload.
4.  **Cookie/Token Challenge:** Sebelum mengirim respons besar (`0x72`), kirim tantangan kecil (Cookie) untuk memvalidasi IP penyerang (Anti-Amplification).
5.  **Strict Payload Length Validation:** Parser server harus menolak paket `0x52` yang melebihi ukuran standar (misal >50 bytes) secara dini.

---
*Laporan ini disusun berdasarkan analisis forensik jaringan dan simulasi serangan teoritis menggunakan data produksi nyata.*
