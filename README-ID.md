# Cloudflare Worker SEO Audit + ALTCHA

Paket backend untuk halaman `/p/seo-audit-intelligence.html` pada Bible Infographic Enterprise v7.12.

## Isi paket

- `src/index.js`: endpoint challenge, verifikasi ALTCHA, audit URL, CORS, redirect guard, batas HTML, timeout, dan proteksi alamat privat.
- `wrangler.jsonc`: konfigurasi Worker dan rate limit 10 audit per menit.
- `package.json`: ALTCHA dan Wrangler.
- `frontend-contract.js`: kontrak endpoint untuk integrasi XML berikutnya.

## 1. Prasyarat

- Akun Cloudflare.
- Node.js 20+ dan npm.
- Wrangler 4.36 atau lebih baru.

## 2. Instalasi

```bash
npm install
npx wrangler login
```

## 3. Buat secret ALTCHA

Buat string acak minimal 32 karakter, lalu simpan sebagai secret terenkripsi:

```bash
npx wrangler secret put ALTCHA_HMAC_SECRET
```

Jangan menaruh secret di `wrangler.jsonc` atau XML Blogger.

## 4. Periksa origin

`ALLOWED_ORIGINS` sudah berisi:

```text
https://grafis-rohani.blogspot.com
```

Jika memakai domain kustom, pisahkan beberapa origin dengan koma.

## 5. Uji lokal

```bash
npm run dev
```

Periksa:

```text
http://localhost:8787/health
http://localhost:8787/challenge
```

## 6. Validasi build

```bash
npm run check
```

## 7. Deploy

```bash
npm run deploy
```

Catat URL hasil deploy, contoh:

```text
https://seo-audit-api.username.workers.dev
```

## 8. Uji produksi

```bash
curl https://seo-audit-api.username.workers.dev/health
curl https://seo-audit-api.username.workers.dev/challenge
```

Endpoint `/audit` wajib menerima payload ALTCHA valid dari widget. Percobaan tanpa payload harus menghasilkan HTTP 400 atau 403.

## 9. Endpoint

### `GET /health`
Status layanan.

### `GET /challenge`
Menghasilkan challenge ALTCHA PBKDF2 yang berlaku 10 menit.

### `POST /audit`

```json
{
  "url": "https://example.com/article",
  "altcha": "PAYLOAD_BASE64_DARI_WIDGET"
}
```

Respons sukses mengembalikan HTML maksimal 1 MB untuk dianalisis oleh UI Blogger.

## 10. Proteksi yang aktif

- CORS hanya untuk origin blog.
- ALTCHA diverifikasi di Worker.
- Rate limit 10 audit per 60 detik.
- HTTP/HTTPS saja, tanpa kredensial URL atau port nonstandar.
- Blok localhost, domain internal, IPv4 privat/link-local, dan IPv6 lokal.
- Redirect manual dan divalidasi ulang, maksimal tiga hop.
- Timeout 10 detik.
- HTML maksimal 1 MB dan content type wajib HTML/XHTML.

## Catatan keamanan

Pemeriksaan host memblokir alamat privat yang terlihat langsung. Untuk kebijakan paling ketat, tambahkan allowlist domain karena runtime Worker tidak menyediakan resolusi DNS manual untuk memverifikasi setiap hasil DNS sebelum `fetch()`.

## Tahap selanjutnya

Setelah URL Worker tersedia, masukkan URL tersebut ke XML v7.12, muat widget ALTCHA v3 hanya pada halaman audit, lalu hubungkan hasil `/audit` ke penganalisis HTML lokal.
