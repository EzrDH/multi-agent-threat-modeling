# DFD: Sistem Login E-Commerce Sederhana

## Deskripsi Sistem

Sistem login e-commerce yang memungkinkan pengguna terdaftar untuk mengakses akun
mereka. Sistem terdiri dari frontend web, backend authentication service, database
pengguna, dan session manager. Sistem juga menggunakan email-based password reset
untuk akun yang lupa password.

## Komponen DFD

### External Entities (Entitas Eksternal)

| ID | Nama | Deskripsi |
|----|------|-----------|
| E1 | Pengguna | Pengguna terdaftar yang ingin login ke akun |
| E2 | Email Service Provider | Layanan SMTP eksternal untuk mengirim email reset |

### Processes (Proses Internal)

| ID | Nama | Deskripsi |
|----|------|-----------|
| P1 | Web Browser | Aplikasi web frontend yang berjalan di browser pengguna |
| P2 | Login Service API | Backend service untuk autentikasi (Node.js/Express) |
| P3 | Password Reset Service | Service untuk handle permintaan reset password |
| P4 | Session Manager | Service untuk manajemen sesi login |

### Data Stores (Penyimpanan Data)

| ID | Nama | Deskripsi |
|----|------|-----------|
| D1 | User Database | PostgreSQL berisi data pengguna (username, email, password_hash) |
| D2 | Session Store | Redis untuk menyimpan session token aktif |
| D3 | Audit Log | File log untuk mencatat aktivitas login/logout |

### Data Flows (Alur Data)

| ID | Dari | Ke | Data | Protokol |
|----|------|------|------|----------|
| F1 | E1 Pengguna | P1 Web Browser | Username + password (plaintext) | HTTPS |
| F2 | P1 Web Browser | P2 Login Service API | Login request (JSON dengan credentials) | HTTPS REST |
| F3 | P2 Login Service API | D1 User Database | Query user by username | TCP/IP internal |
| F4 | D1 User Database | P2 Login Service API | User record + password_hash | TCP/IP internal |
| F5 | P2 Login Service API | P4 Session Manager | Create session request | HTTP internal |
| F6 | P4 Session Manager | D2 Session Store | Store session token + user_id | TCP/IP internal |
| F7 | P4 Session Manager | P1 Web Browser | Session cookie (JWT) | HTTPS (Set-Cookie) |
| F8 | P2 Login Service API | D3 Audit Log | Log entry (timestamp, username, success/fail) | File I/O |
| F9 | E1 Pengguna | P1 Web Browser | "Forgot password" + email | HTTPS |
| F10 | P1 Web Browser | P3 Password Reset Service | Reset request (email) | HTTPS REST |
| F11 | P3 Password Reset Service | D1 User Database | Verify email + generate reset token | TCP/IP internal |
| F12 | P3 Password Reset Service | E2 Email Service | Send reset link (SMTP) | SMTP/TLS |

### Trust Boundaries (Batas Kepercayaan)

| ID | Deskripsi |
|----|-----------|
| TB1 | **Internet Boundary** — antara entitas eksternal (E1, E2) dan komponen internal |
| TB2 | **Web Tier Boundary** — antara web browser dan backend services |
| TB3 | **Internal Network Boundary** — antara backend services dan data stores |

## Asumsi Keamanan Saat Ini

- HTTPS dipakai di seluruh komunikasi eksternal (TB1)
- Password disimpan sebagai hash di database (algoritma tidak ditentukan)
- Session token menggunakan JWT (algoritma signing tidak ditentukan)
- Tidak ada rate limiting eksplisit
- Tidak ada multi-factor authentication
- Tidak ada CAPTCHA
- Email reset menggunakan token UUID v4 dengan validitas 24 jam
- Database menggunakan koneksi terenkripsi (TLS internal)

## Tujuan Threat Modeling

Identifikasi seluruh ancaman keamanan pada sistem ini menggunakan framework STRIDE,
dengan perhatian khusus pada aspek-aspek kriptografi seperti:
- Algoritma password hashing
- JWT signing & verification
- TLS/SSL configuration
- Token randomness untuk password reset
- Storage credentials
