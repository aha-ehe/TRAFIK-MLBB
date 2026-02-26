# Mobile Legends Traffic Analysis Report

## Pendahuluan
Dokumen ini berisi hasil riset reverse engineering terhadap lalu lintas jaringan (network traffic) dari game Mobile Legends, berdasarkan analisis file PCAP `hasil-awal-game.pcap` dan `nyambung -kembali-ke-game.pcap`.

## Ringkasan Eksekutif
*   **Protokol Utama:** UDP
*   **Port Server:** 5508 (Game Logic), Port 30xxx (kemungkinan Voice/Chat)
*   **Server IP Utama:** `103.157.33.7` (pada sampel ini)
*   **Struktur Paket:** Header kustom 14-byte yang mencakup Magic Byte, Command, Session ID, Sequence Number, dan Acknowledgment Number.
*   **Temuan Keamanan:** Potensi amplifikasi UDP (DDoS) terdeteksi pada fase handshake/reconnect dengan faktor amplifikasi hingga ~10x.

---

## 1. Arsitektur Jaringan
Komunikasi utama dalam pertandingan (in-match) menggunakan protokol UDP untuk kecepatan dan efisiensi.

*   **Transport Layer:** UDP (User Datagram Protocol)
*   **IP Server:** `103.157.33.7`
*   **Port Server:** 5508
*   **Pola Koneksi:**
    *   Klien menggunakan port sumber acak (ephemeral).
    *   Saat *reconnect* (masuk kembali ke game), klien menggunakan port sumber baru untuk menghubungkan ke sesi yang sama atau membuat sesi baru.

---

## 2. Analisis Struktur Paket (Reverse Engineering)
Berdasarkan analisis heksadesimal dari ribuan paket, ditemukan pola header tetap berukuran 14 byte di awal payload UDP.

### Format Header (14 Bytes)
| Offset | Ukuran | Field | Deskripsi |
| :--- | :--- | :--- | :--- |
| 0x00 | 1 Byte | **Magic Byte** | Selalu `0x01` pada paket game aktif. |
| 0x01 | 1 Byte | **Command** | Menentukan jenis paket (misal: `0x51`, `0x52`, `0x75`). |
| 0x02 | 4 Bytes | **Session ID** | ID unik untuk sesi pertandingan (misal: `c2a94e79`). Tetap sama selama satu sesi aktif. |
| 0x06 | 4 Bytes | **Seq Num** | Sequence Number (Little Endian). Penghitung urutan paket. |
| 0x0A | 4 Bytes | **Ack Num** | Acknowledgment Number (Little Endian). Mengonfirmasi paket terakhir yang diterima. |
| 0x0E | ... | **Payload** | Data game terenkripsi/terkompresi (posisi hero, skill, dll). |

### Jenis Command (Hipotesis)
*   **0x51 (Reliable Data):** Paket data penting yang membutuhkan konfirmasi (ACK). Sering terlihat membawa payload lebih besar (~30-50 bytes).
*   **0x52 (Ack / Keep-alive):** Paket kecil (~10 bytes payload) yang sering muncul sebagai respons, kemungkinan besar berfungsi sebagai ACK atau heartbeat.
*   **0x71 / 0x75 (Handshake/Hello):** Terlihat dominan pada fase awal koneksi atau saat *reconnect*.

---

## 3. Analisis Proses Reconnect
Pada file `nyambung -kembali-ke-game.pcap`, terlihat proses negosiasi ulang sesi:

1.  **Client Hello:** Klien mengirim paket dengan command `0x71` atau `0x75`.
2.  **Server Response:** Server merespons dengan tantangan atau konfirmasi sesi.
3.  **Session Establishment:** Setelah handshake selesai, komunikasi kembali menggunakan command `0x51` dan `0x52` dengan **Session ID baru** (misal berubah dari `c2a94e79` menjadi `31aef586`).
4.  **Sequence Reset:** Sequence number di-reset atau disinkronisasi ulang mulai dari angka kecil (0, 1, 2...).

---

## 4. Analisis Keamanan & Kerentanan DDoS

### Potensi Amplifikasi (Amplification Attack)
Ditemukan potensi kerentanan amplifikasi pada fase handshake/reconnect.

*   **Mekanisme:** Penyerang dapat memalsukan IP korban (Spoofing) dan mengirim paket "Hello" kecil ke server game.
*   **Observasi Data:**
    *   Ukuran Paket Request (Klien): ~52 bytes
    *   Ukuran Paket Response (Server): ~540 bytes
    *   **Faktor Amplifikasi:** **~10.25x**
*   **Risiko:** Jika server tidak memvalidasi *state* koneksi sebelum mengirim respons besar, ini bisa digunakan untuk serangan DDoS refleksi (UDP Reflection Attack).

### Session Hijacking
*   **Session ID** (4 bytes) dikirim dalam bentuk *cleartext* di header UDP.
*   Jika penyerang berada dalam jaringan yang sama (Man-in-the-Middle) dan bisa mengendus trafik, mereka bisa mendapatkan Session ID dan mencoba menyuntikkan paket palsu (Packet Injection) untuk mengganggu permainan (misal: mengirim perintah "Disconnect").

## 5. Kesimpulan
Komunikasi Mobile Legends menggunakan protokol UDP kustom yang efisien dengan header sederhana untuk mengelola urutan (reliability) di atas UDP. Struktur ini umum pada game *real-time*. Namun, mekanisme handshake awal memiliki potensi risiko amplifikasi yang perlu diperhatikan.

---
*Dibuat oleh Jules (AI Researcher) untuk analisis trafik jaringan Mobile Legends.*
