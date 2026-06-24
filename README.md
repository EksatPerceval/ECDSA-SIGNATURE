# ECDSA PDF Digital Signature System

Sistem tanda tangan digital berbasis **Elliptic Curve Digital Signature Algorithm (ECDSA)** dengan kurva **NIST P-256** dan hashing **SHA-256** untuk dokumen PDF.

---

## Arsitektur

```
ecdsa-pdf-signer/
├── backend/
│   ├── server.js       ← Express API server (Node.js)
│   └── package.json
└── frontend/
    └── index.html      ← UI single-file (HTML + CSS + JS)
```

---

## Cara Menjalankan

### 1. Jalankan Backend

```bash
cd backend
npm install
node server.js
```

Server berjalan di **http://localhost:3001**

### 2. Buka Frontend

Buka file `frontend/index.html` langsung di browser, **atau** jalankan server statis:

```bash
cd frontend
npx serve .
```

Akses di **http://localhost:3000**

---

## Fitur

| Fitur | Deskripsi |
|-------|-----------|
| **Key Generation** | Generate pasangan kunci ECDSA (private + public) dengan kurva P-256 |
| **PDF Signing** | Tanda tangani dokumen PDF menggunakan ECDSA dengan SHA-256 |
| **Signature Stamp** | Stempel tanda tangan tertanam di halaman terakhir PDF |
| **Verification** | Verifikasi keaslian tanda tangan dan integritas dokumen |
| **History** | Riwayat semua tanda tangan dalam sesi berjalan |

---

## API Endpoints

| Method | Endpoint | Deskripsi |
|--------|----------|-----------|
| `POST` | `/api/generate-keys` | Generate key pair ECDSA |
| `POST` | `/api/sign` | Tanda tangani PDF (multipart/form-data) |
| `POST` | `/api/verify` | Verifikasi tanda tangan PDF |
| `GET`  | `/api/signatures` | Daftar semua tanda tangan |
| `GET`  | `/api/health` | Health check |

---

## Alur Kerja ECDSA

```
1. KEY GENERATION
   ──────────────
   ec.genKeyPair() pada kurva P-256
   → Private Key (256-bit scalar)
   → Public Key (titik pada kurva eliptik)

2. SIGNING (Hash & Sign)
   ─────────────────────
   SHA-256(PDF_bytes) → document_hash
   ECDSA_Sign(private_key, document_hash) → DER_signature

3. VERIFICATION
   ─────────────
   SHA-256(PDF_bytes) → document_hash
   ECDSA_Verify(public_key, document_hash, DER_signature) → true/false
```

---

## Keamanan

- Kurva: **NIST P-256** (secp256r1) — standar FIPS 186-4
- Hash: **SHA-256** — 256-bit message digest
- Panjang tanda tangan DER: ~70-72 byte
- Keamanan ekivalen RSA-3072

---

## Catatan Produksi

> Dalam penggunaan nyata:
> - **Private key TIDAK boleh dikirim ke server** — signing harus dilakukan di sisi klien
> - Gunakan HSM (Hardware Security Module) untuk penyimpanan kunci
> - Implementasikan PKI (Certificate Authority) untuk validasi identitas
> - Tambahkan timestamp dari TSA (Timestamp Authority) yang terpercaya
