# Analisis Trafik Mobile Legends dan Teknik "Lagging"

Dokumen ini merangkum hasil analisis terhadap file `.pcap` dan `.har` yang diberikan untuk memahami bagaimana teknik serangan "lagging" (membuat lag hanya pada satu pertandingan) dapat terjadi.

## Ringkasan Temuan

Berdasarkan analisis file, ditemukan bahwa game Mobile Legends menggunakan arsitektur hybrid:
1.  **Login & Matchmaking (HTTP/HTTPS):** Menggunakan protokol web standar untuk autentikasi dan pencarian pertandingan.
2.  **Gameplay Utama (UDP):** Menggunakan protokol UDP pada port dinamis (dalam kasus ini port **5508**) untuk pertukaran data game secara real-time.
3.  **State Sync / Reconnect (TCP):** Menggunakan protokol TCP pada port tertentu (dalam kasus ini port **5558**) untuk sinkronisasi ulang keadaan game jika koneksi terputus.

## Detail Teknis

### 1. Identifikasi Server Game
Dari file `hasil-awal-game.pcap` (trafik game normal), server game yang aktif adalah:
-   **IP:** `103.157.33.7`
-   **Port:** UDP `5508`

Trafik ini sangat dominan, menunjukkan bahwa ini adalah jalur komunikasi utama selama pertandingan berlangsung.

### 2. Identifikasi Celah Potensial (Attack Vector)
Pada file `nyambung -kembali-ke-game.pcap` (trafik saat reconnect), terlihat adanya komunikasi TCP yang intensif ke server yang sama (`103.157.33.7`) pada port **5558**.

-   **Observasi:** Port TCP `5558` *terbuka* dan menerima koneksi pada server game yang sama dengan yang menjalankan sesi UDP `5508`.
-   **Anomali:** Selama gameplay normal (`hasil-awal-game.pcap`), *tidak ada* trafik ke port TCP `5558` ini. Port ini "diam" namun tetap terbuka (listening).

### 3. Hipotesis Teknik Serangan "TCP-PPS"
Teknik yang Anda sebutkan ("Layer 4 TCP-PPS") kemungkinan besar bekerja dengan cara berikut:

1.  **Targeting:** Penyerang mengetahui IP server game (`103.157.33.7`) tempat pertandingan berlangsung. IP ini bisa didapatkan dengan cara *sniffing* trafik sendiri saat berada dalam pertandingan yang sama.
2.  **Flooding:** Penyerang mengirimkan banjir paket TCP (misalnya SYN Flood atau ACK Flood) ke port **5558** pada server tersebut.
3.  **Dampak:**
    -   Meskipun game menggunakan UDP (port 5508), serangan ke port TCP (5558) pada mesin yang sama akan membebani sumber daya jaringan server (CPU interrupts, Conntrack table, atau bandwidth antarmuka jaringan).
    -   Server menjadi sibuk memproses permintaan TCP palsu ini, sehingga paket UDP game yang sah menjadi tertunda (ping naik) atau terbuang (packet loss/freeze).
    -   Karena serangan ini menargetkan *instance* atau *port* spesifik pada server yang menangani pertandingan tersebut, efeknya sangat lokal: hanya pemain di pertandingan itu yang merasakan lag, sementara server secara keseluruhan mungkin tidak down.

## Kesimpulan

Teknik "lagging" tersebut mengeksploitasi arsitektur di mana server game UDP juga mengekspos layanan TCP (untuk fitur reconnect) di IP yang sama. Dengan membanjiri layanan sekunder (TCP 5558), penyerang dapat mengganggu layanan utama (UDP 5508) tanpa perlu memutus koneksi sepenuhnya, menciptakan efek "lag" atau "freeze" yang membuat permainan tidak nyaman bagi lawan.

**Catatan:** Moonton mungkin telah memitigasi ini dengan memisahkan IP untuk layanan TCP dan UDP, atau menggunakan perlindungan DDoS yang lebih canggih (seperti scrubbing center) untuk memfilter trafik TCP yang tidak sah ke port game.
