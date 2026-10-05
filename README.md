# KeyPanel — Key Server + Admin Panel (Railway-Ready)

Server key untuk mod menu dengan protokol kompatibel **AbsoluteX** (payload `.so`), plus panel admin web untuk bikin key, atur waktu/kedaluwarsa, bind device, ban/unban, dan pantau pemakaian.

Zero dependency (Node.js murni, hanya `http` + `crypto` bawaan). Satu file `server.js`. Deploy ke Railway tinggal connect repo ini.

---

## Fitur

- **API key server** — kompatibel 100% dengan payload mod menu (POST `/`, body `user_key` + `serial`, respons `{status, data:{rng,expired,member_key}, reason}`)
- **Panel admin** (`/admin`) — login password, bikin key (1/3/7/14/30/60/90 hari, custom, lifetime), jumlah massal (batch 50), maks device per key, catatan
- **Setting waktu** — durasi saat bikin, perpanjang (`extend`), set expired manual (`setexpiry`), tampil sisa waktu di tabel
- **Device binding** — 1 key bisa dibatasi N serial device, ada tombol reset device
- **Ban / unban / hapus** key langsung dari panel
- **Stats** — total / aktif / expired / banned
- **Persistensi** — file JSON; pasang Volume Railway biar data tidak hilang saat redeploy

---

## Deploy ke Railway

1. Buka [railway.app](https://railway.app) → login pakai GitHub.
2. **New Project** → **Deploy from GitHub repo** → pilih `maqhjq23/keypanel`.
3. Masuk ke service → tab **Variables** → tambah minimal:
   ```
   ADMIN_PASSWORD = password_admin_lu
   ```
   Sangat disarankan juga:
   ```
   SESSION_SECRET = string_acak_panjang
   ```
4. Tab **Settings → Networking → Generate Domain** → dapat URL publik (mis. `https://keypanel-production.up.railway.app`).
5. Buka `https://<domain>/admin` → login pakai `ADMIN_PASSWORD`.

> Deploy ulang otomatis setiap kali ada push baru ke repo.

### Persist data (disarankan)

Tanpa volume, data key hilang saat redeploy/restart container.

1. Tab **Settings → Volumes** (atau tab service → Volumes) → **New Volume**.
2. Mount path: `/data`.
3. Tambah variable:
   ```
   DATA_DIR = /data
   ```

---

## Variabel Environment

| Variabel | Default | Keterangan |
|---|---|---|
| `ADMIN_PASSWORD` | *(kosong, WAJIB)* | Password login panel admin. Kosong = panel terkunci. |
| `SESSION_SECRET` | turunan password | Kunci HMAC cookie sesi admin. Ganti biar sesi stabil walau password diganti. |
| `KEY_PREFIX` | `BMX` | Prefix key generated, mis. `BMX-XXXX-XXXX-XXXX`. |
| `STATUS_OK` | `OK` | Nilai `status` saat valid (yang dibaca mod menu). |
| `REQUIRE_UA` | *(kosong)* | Kalau diisi (mis. `AbsoluteX/2.0`), request dengan UA lain ditolak. |
| `BIND_DEVICE` | `1` | `0` = matikan binding serial device. |
| `MAX_DEVICES` | `1` | Default maks device per key (bisa dioverride per key dari panel). |
| `EXPIRED_FMT` | `dd-mm-yyyy` | Format tanggal expired: `dd-mm-yyyy` / `iso` / `epoch`. |
| `LIFETIME_TEXT` | `Lifetime` | Teks expired untuk key tanpa batas. |
| `REASON_NOTFOUND` | `Key tidak ditemukan` | Pesan reason gagal. |
| `REASON_BANNED` | `Key diblokir` | Pesan reason key dibanned. |
| `REASON_EXPIRED` | `Key expired` | Pesan reason kadaluarsa. |
| `REASON_DEVICE` | `Device sudah terdaftar di key lain` | Pesan reason device melebihi batas. |
| `DATA_DIR` | `./data` | Folder penyimpanan `keys.json` (set `/data` kalau pakai Volume). |
| `PORT` | `3000` | Otomatis di-set Railway. |

---

## API — Validasi Key (dipanggil payload / mod menu)

### `POST /`  (juga: `POST|GET /api/verify`, `POST|GET /api/validate`)

```bash
curl -X POST https://<domain>/ \
  -H "User-Agent: AbsoluteX/2.0" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "user_key=BMX-XXXX-XXXX-XXXX&serial=DEVICE_SERIAL"
```

Respons sukses:

```json
{
  "status": "OK",
  "reason": "",
  "expired": "05-11-2026",
  "member_key": "BMX-XXXX-XXXX-XXXX",
  "data": {
    "rng": "a1B2c3...",
    "expired": "05-11-2026",
    "member_key": "BMX-XXXX-XXXX-XXXX",
    "status": "OK"
  }
}
```

Respons gagal: `status` kosong + `reason` berisi alasan (`Key tidak ditemukan` / `Key expired` / `Key diblokir` / `Device sudah terdaftar di key lain`).

---

## API — Admin (butuh cookie sesi dari `/admin/login`)

```bash
# login, simpan cookie
curl -c cookies.txt -X POST https://<domain>/admin/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "password=PASSWORD_LU"

# daftar key
curl -b cookies.txt https://<domain>/admin/api/list

# statistik
curl -b cookies.txt https://<domain>/admin/api/stats

# bikin key (durasi: 1/3/7/14/30/60/90/lifetime/custom + custom_days, qty max 50)
curl -b cookies.txt -X POST https://<domain>/admin/api/create \
  -H "Content-Type: application/json" \
  -d '{"duration":"30","qty":5,"max_devices":1,"note":"client ig @xxx"}'

# perpanjang 7 hari
curl -b cookies.txt -X POST https://<domain>/admin/api/extend \
  -H "Content-Type: application/json" \
  -d '{"key":"BMX-XXXX-XXXX-XXXX","days":7}'

# set expired manual (epoch ms)
curl -b cookies.txt -X POST https://<domain>/admin/api/setexpiry \
  -H "Content-Type: application/json" \
  -d '{"key":"BMX-XXXX-XXXX-XXXX","expires":1799999999000}'

# ban / unban / hapus / reset device
curl -b cookies.txt -X POST https://<domain>/admin/api/ban    -H "Content-Type: application/json" -d '{"key":"BMX-XXXX-XXXX-XXXX"}'
curl -b cookies.txt -X POST https://<domain>/admin/api/unban  -H "Content-Type: application/json" -d '{"key":"BMX-XXXX-XXXX-XXXX"}'
curl -b cookies.txt -X POST https://<domain>/admin/api/delete -H "Content-Type: application/json" -d '{"key":"BMX-XXXX-XXXX-XXXX"}'
curl -b cookies.txt -X POST https://<domain>/admin/api/reset  -H "Content-Type: application/json" -d '{"key":"BMX-XXXX-XXXX-XXXX"}'
```

---

## Jalankan Lokal

```bash
ADMIN_PASSWORD=test123 node server.js
# buka http://localhost:3000/admin
```

## Struktur

```
keypanel/
├── server.js      # seluruh app (API + panel + storage)
├── package.json   # start: node server.js (tanpa dependency)
├── railway.json   # konfigurasi build/deploy Railway + healthcheck /health
└── data/          # keys.json (dibuat otomatis; .gitignore)
```

## Catatan Keamanan

- Wajib ganti `ADMIN_PASSWORD` dari default; login di-rate-limit 8 percobaan lalu cooldown 10 menit.
- Set `REQUIRE_UA=AbsoluteX/2.0` supaya endpoint validasi hanya menerima UA payload (membingungkan scanner).
- Cookie sesi admin: HMAC-SHA256, HttpOnly, kadaluarsa 12 jam.
- Semua aksi admin dan endpoint verifikasi tidak di-cache (`no-store`).
