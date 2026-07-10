# Face Attendance API Backend

Backend REST API untuk aplikasi **Face Attendance (Face Recognition Attendance System)** menggunakan **CodeIgniter 3.1.13**, **PHP 7.2**, dan **MySQL**.

API ini dirancang sebagai backend utama yang berkomunikasi dengan aplikasi desktop Face Recognition berbasis Python. Seluruh komunikasi dilakukan menggunakan REST API dengan autentikasi perangkat (Device Authentication), sinkronisasi data pegawai, pengiriman data absensi, heartbeat perangkat, serta pengiriman system log.

---

# Fitur

* REST API berbasis JSON
* Device Authentication
* Access Token & Refresh Token
* Device Session Management
* Incremental Employee Synchronization
* Employee Face Registration
* Attendance API
* Bulk Attendance API
* Device Configuration API
* Device Heartbeat API
* Bulk System Log API
* Audit Log API
* Soft Delete Employee
* UUID Request Tracking
* Retry Friendly Response
* Compatible dengan aplikasi Face Attendance Python

---

# Teknologi

| Komponen       | Versi           |
| -------------- | --------------- |
| PHP            | 7.2.x           |
| Framework      | CodeIgniter 3   |
| Database       | MySQL / MariaDB |
| Web Server     | Apache / Nginx  |
| Authentication | Bearer Token    |
| Response       | JSON            |

---

# Struktur Project

```text
application/
│
├── controllers/
│   └── api/
│       └── v1/
│           └── Face_attendance.php
│
├── core/
│   └── MY_API_Controller.php
│
├── libraries/
│   └── face_attendance/
│       ├── Face_attendance_auth.php
│       ├── Face_attendance_repository.php
│       ├── Face_attendance_response.php
│       ├── Face_attendance_service.php
│       └── Face_attendance_validator.php
│
├── config/
│   └── face_attendance.php
│
└── logs/
```

---

# API Endpoint

## Authentication

| Method | Endpoint                      |
| ------ | ----------------------------- |
| POST   | `/api/v1/auth/device/login`   |
| POST   | `/api/v1/auth/device/refresh` |
| POST   | `/api/v1/auth/device/logout`  |
| GET    | `/api/v1/auth/device/profile` |

---

## Employee

| Method | Endpoint                                  |
| ------ | ----------------------------------------- |
| GET    | `/api/v1/employees/sync`                  |
| POST   | `/api/v1/employees/sync/acknowledge`      |
| POST   | `/api/v1/employees`                       |
| POST   | `/api/v1/employees/{employee_code}/faces` |

---

## Attendance

| Method | Endpoint                              |
| ------ | ------------------------------------- |
| POST   | `/api/v1/attendances`                 |
| POST   | `/api/v1/attendances/bulk`            |
| GET    | `/api/v1/attendances/{attendance_id}` |

---

## Device

| Method | Endpoint                                |
| ------ | --------------------------------------- |
| GET    | `/api/v1/devices/{device_id}/config`    |
| POST   | `/api/v1/devices/{device_id}/heartbeat` |

---

## System Log

| Method | Endpoint                   |
| ------ | -------------------------- |
| POST   | `/api/v1/system-logs/bulk` |

---

## Health Check

| Method | Endpoint                         |
| ------ | -------------------------------- |
| GET    | `/api/v1/face-attendance/health` |

---

# Standar Header

Semua endpoint (kecuali Login dan Refresh Token) menggunakan header berikut.

```http
Authorization: Bearer {access_token}
Accept: application/json
Content-Type: application/json
X-Device-ID: DEVICE-01
X-Request-ID: uuid-v4
```

---

# Format Response

## Success

```json
{
    "success": true,
    "message": "Request processed successfully",
    "data": {},
    "error_code": null,
    "meta": {
        "request_id": "uuid",
        "server_time": "2026-07-10T10:00:00+07:00"
    }
}
```

---

## Error

```json
{
    "success": false,
    "message": "Validation failed",
    "data": null,
    "error_code": "VALIDATION_ERROR",
    "errors": {},
    "meta": {
        "request_id": "uuid",
        "server_time": "2026-07-10T10:00:00+07:00",
        "retryable": false,
        "retry_after_seconds": null
    }
}
```

---

# HTTP Status

| Status | Keterangan            |
| ------ | --------------------- |
| 200    | OK                    |
| 201    | Created               |
| 400    | Bad Request           |
| 401    | Unauthorized          |
| 403    | Forbidden             |
| 404    | Not Found             |
| 409    | Conflict              |
| 422    | Validation Error      |
| 429    | Too Many Requests     |
| 500    | Internal Server Error |
| 503    | Service Unavailable   |

---

# Keamanan

API menerapkan beberapa mekanisme keamanan:

* Device Authentication
* Bearer Token Authentication
* Refresh Token Rotation
* SHA-256 Token Hashing
* Password Hash (`password_hash`)
* Password Verification (`password_verify`)
* Request UUID Tracking
* Audit Logging
* Soft Delete
* Secure File Upload
* Validation Layer
* Database Transaction
* Query Builder CodeIgniter

Data berikut **tidak pernah** disimpan ke log:

* Access Token
* Refresh Token
* Device Secret
* Face Image Base64
* Attendance Photo Base64
* Face Embedding

---

# Instalasi

## 1. Clone Repository

```bash
git clone https://github.com/username/face-attendance-api.git
```

---

## 2. Konfigurasi Database

Edit:

```text
application/config/database.php
```

Sesuaikan konfigurasi database MySQL.

---

## 3. Konfigurasi Base URL

Edit:

```text
application/config/config.php
```

Contoh:

```php
$config['base_url'] = 'http://localhost/apiattendance/';
```

---

## 4. Aktifkan mod_rewrite

Pastikan Apache mengaktifkan:

```
mod_rewrite
```

dan file `.htaccess` telah dikonfigurasi.

---

## 5. Import Database

Import seluruh tabel Face Attendance sesuai dokumentasi database proyek.

---

## 6. Jalankan Server

Contoh URL lokal:

```
http://localhost/apiattendance
```

---

# Contoh Health Check

```
GET /api/v1/face-attendance/health
```

Response:

```json
{
    "success": true,
    "message": "Face Attendance API is running",
    "data": {
        "api_status": "ok",
        "database_status": true
    }
}
```

---

# Integrasi Aplikasi Python

Contoh konfigurasi `.env` pada aplikasi Python:

```env
APP_NAME=Face Attendance
APP_VERSION=1.0.0
APP_ENV=development

MOCK_API=false

API_BASE_URL=http://localhost/apiattendance/api/v1

API_TIMEOUT=20

DEVICE_ID=DEVICE-01
DEVICE_CODE=DEVICE-01
DEVICE_SECRET=xxxxxxxxxxxxxxxxxxxxxxxx
```

---

# Roadmap

* [x] Device Authentication
* [x] Employee Synchronization
* [x] Attendance API
* [x] Device Heartbeat
* [x] Device Configuration
* [x] System Log API
* [ ] Swagger / OpenAPI Documentation
* [ ] JWT Authentication (Opsional)
* [ ] Unit Testing
* [ ] Integration Testing
* [ ] Docker Deployment
* [ ] CI/CD Pipeline
* [ ] API Rate Limiting
* [ ] Web Admin Dashboard

---

# Lisensi

Proyek ini dikembangkan untuk kebutuhan **Face Attendance System** dan dapat dimodifikasi sesuai kebutuhan organisasi atau perusahaan.
