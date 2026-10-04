# Desain Penelitian dan Aturan Perhitungan

Dokumen ini sumber kebenaran untuk semua perhitungan di framework. Bagian Methodology di paper ditulis dari
dokumen yang sama, jadi kode dan paper tidak boleh berbeda.

## 1. Pertanyaan penelitian

- **RQ1.** Apakah menambahkan tinjauan LLM pada pipeline SAST meningkatkan deteksi SQL Injection (CWE-89) dan
  Cross-Site Scripting (CWE-79) dibanding SAST saja?
- **RQ2.** Bagaimana perbedaan kinerja Gemini, GPT, dan Grok dalam peran tersebut, dan apakah gabungan ketiganya
  (ensemble) lebih baik dari model terbaik secara tunggal?
- **RQ3.** Seberapa besar peran petunjuk dari SAST? Dengan kata lain, apakah LLM yang diberi hasil CodeQL lebih
  baik daripada LLM yang membaca kode sendirian?
- **RQ4.** Berapa harga yang dibayar: false positive, waktu eksekusi pipeline, biaya API, dan konsistensi
  antar-run?

## 2. Unit analisis dan cakupan

- Unit analisis adalah **satu test case** OWASP Benchmark (satu file Java).
- Setiap test case punya satu kategori resmi (`sqli` atau `xss`) dan satu label (rentan atau tidak).
- Sebuah test case **hanya dinilai pada CWE kategorinya sendiri**. Ini mengikuti cara penilaian resmi OWASP
  Benchmark. Putusan untuk CWE lain tetap disimpan dan dilaporkan secara deskriptif sebagai "off-category
  alerts", tapi tidak masuk confusion matrix.
- Pemetaan kategori: `sqli` → `CWE-89`, `xss` → `CWE-79`.

## 3. Skenario

| ID | Masukan ke LLM | Run | Keterangan |
|---|---|---|---|
| `A` | tidak ada LLM | 1 | CodeQL saja, baseline |
| `B-<model>` | kode + temuan CodeQL di file itu (termasuk jalur aliran data) | `runs_b` (default 3) | LLM memberi putusan akhir |
| `C-<model>` | kode saja | `runs_c` (default 1) | Mengukur kontribusi petunjuk SAST |
| `ENS` | tidak ada panggilan baru | turunan | Voting dari `B-*` run 1 |

`<model>` adalah kunci model di konfigurasi: `gemini`, `gpt`, `grok`.

**Aturan ensemble.** Untuk tiap test case, ambil putusan `B-gemini`, `B-gpt`, `B-grok` dari run 1 pada CWE
kategorinya. Putusan yang error tidak ikut voting. Test case dinyatakan rentan jika jumlah suara "rentan"
paling sedikit `ensemble.min_votes` (default 2). Jika putusan valid kurang dari `min_votes`, pakai putusan
CodeQL (sama dengan fallback Skenario B).

## 4. Metrik

### 4.1 Confusion matrix

Per skenario, per CWE, dan gabungan kedua CWE (pooled):

| | Label rentan | Label tidak rentan |
|---|---|---|
| Diprediksi rentan | TP | FP |
| Diprediksi tidak rentan | FN | TN |

### 4.2 Kapan CodeQL dianggap mendeteksi

Test case dianggap terdeteksi oleh CodeQL jika ada minimal satu alert di file tersebut yang rule-nya memiliki tag
CWE sama dengan CWE kategori test case. Tag CWE dibaca dari `properties.tags` rule di SARIF dengan format
`external/cwe/cwe-NNN`, dinormalisasi menjadi `CWE-N` (tanpa nol di depan). Satu rule bisa punya beberapa tag CWE.

Hanya rule dari query suite yang ditetapkan di konfigurasi yang dipakai. Alert dengan tingkat `note` tetap
dihitung, karena OWASP Benchmark menilai keberadaan temuan, bukan tingkat keparahannya.

### 4.3 Rumus

```
TPR (recall)    = TP / (TP + FN)
FPR             = FP / (FP + TN)
Precision       = TP / (TP + FP)
F1              = 2 * Precision * TPR / (Precision + TPR)
Accuracy        = (TP + TN) / (TP + FP + TN + FN)
Benchmark Score = TPR - FPR
```

Jika penyebut nol, nilai metrik ditulis `null` (bukan 0) dan diberi catatan di laporan. Benchmark Score adalah
metrik utama yang dipakai OWASP Benchmark (setara Youden's J), rentangnya -1 sampai 1, dengan 0 berarti
setara tebakan acak.

### 4.4 Run berulang

- **Analisis utama memakai run 1** untuk semua skenario. Ini ditetapkan sebelum melihat hasil supaya tidak ada
  pemilihan run yang menguntungkan.
- Untuk `B-*` dengan lebih dari satu run, laporkan juga rata-rata dan simpangan baku tiap metrik antar-run.
- Analisis sensitivitas: putusan mayoritas dari semua run `B-*` (2 dari 3), dilaporkan terpisah.

### 4.5 Peran LLM terhadap temuan CodeQL

Khusus `B-*`, hitung jumlah test case per kategori `sast_action` (definisi di bagian 6), dipecah lagi menurut
label sebenarnya. Contoh baris laporan: "Gemini menolak 31 temuan CodeQL; 27 di antaranya memang bukan
kerentanan (penolakan benar), 4 sebenarnya rentan (penolakan salah)."

### 4.6 Konsistensi

Untuk tiap model `B-*` dengan `runs_b` > 1:
- **Flip rate**: proporsi test case yang putusannya tidak sama di semua run.
- **Kesepakatan pasangan**: rata-rata proporsi putusan yang sama untuk setiap pasangan run.

### 4.7 Waktu dan biaya

- Waktu CodeQL: durasi langkah analisis, diukur dari timestamp sebelum dan sesudah langkah `analyze`.
- Waktu LLM per skenario: jumlah latensi semua panggilan (setara eksekusi berurutan) dan waktu dinding job.
- Waktu pipeline `B-<model>` = waktu CodeQL + waktu dinding job review model tersebut.
- Biaya per panggilan = `(input_tokens * harga_input + output_tokens * harga_output) / 1_000_000`, dengan harga
  dari konfigurasi. Token reasoning dihitung sebagai output. Respons yang diambil dari cache tetap dilaporkan
  dengan biaya panggilan aslinya, dan ditandai sebagai cache hit.
- Laporkan total dan per test case.

### 4.8 Uji statistik

Uji McNemar pada ketepatan putusan per test case (benar atau salah terhadap label), run 1, gabungan kedua CWE.
Pasangan yang diuji:

1. `A` vs setiap `B-<model>` (RQ1)
2. `A` vs `ENS` (RQ1, RQ2)
3. `B-<model>` vs `C-<model>` untuk model yang sama (RQ3)
4. `ENS` vs `B-<model>` terbaik menurut Benchmark Score (RQ2)

Pakai versi exact (binomial) jika jumlah pasangan yang berbeda kurang dari 25, selain itu versi chi-square
dengan koreksi kontinuitas. Koreksi perbandingan ganda dengan metode Holm, α = 0,05. Laporkan jumlah pasangan
berbeda (b, c), statistik, p-value mentah, dan p-value terkoreksi.

## 5. Skema respons LLM

LLM wajib membalas dengan JSON yang sesuai skema berikut. Skema dikirim lewat fitur structured output tiap
provider, lalu divalidasi ulang di sisi framework.

```json
{
  "type": "object",
  "properties": {
    "verdicts": {
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "cwe": { "type": "string", "enum": ["CWE-89", "CWE-79"] },
          "vulnerable": { "type": "boolean" },
          "line": { "type": ["integer", "null"] },
          "confidence": { "type": "string", "enum": ["high", "medium", "low"] },
          "reason": { "type": "string" },
          "recommendation": { "type": ["string", "null"] }
        },
        "required": ["cwe", "vulnerable", "line", "confidence", "reason", "recommendation"],
        "additionalProperties": false
      }
    }
  },
  "required": ["verdicts"],
  "additionalProperties": false
}
```

Nilai `enum` untuk `cwe` dibangkitkan dari daftar CWE di konfigurasi, bukan ditulis tetap.

Validasi tambahan setelah skema:
- Harus ada tepat satu verdict untuk setiap CWE dalam cakupan. Verdict ganda atau hilang dianggap respons tidak
  valid.
- `line`, jika diisi, harus berada dalam rentang jumlah baris file. Jika di luar rentang, set menjadi `null` dan
  catat peringatan (putusan tetap dipakai).
- `recommendation` wajib terisi jika `vulnerable` bernilai true. Jika kosong, catat peringatan saja.

`confidence` sengaja berupa kategori, bukan angka. Angka keyakinan dari LLM umumnya tidak terkalibrasi, dan
kategori lebih mudah dibandingkan antar-model.

## 6. Normalisasi temuan

Setiap putusan diubah menjadi `Finding`:

| Field | Isi |
|---|---|
| `case_id` | nama netral hasil sanitasi, misalnya `Case0042` |
| `file` | path relatif di repositori |
| `cwe` | `CWE-89` atau `CWE-79` |
| `vulnerable` | boolean, atau null jika error |
| `line` | baris, boleh null |
| `source` | `codeql`, `gemini`, `gpt`, `grok`, `mock` |
| `scenario` | `A`, `B-gemini`, ..., `ENS` |
| `run` | nomor run |
| `sast_action` | lihat di bawah, hanya untuk `B-*` |
| `confidence`, `reason`, `recommendation` | dari LLM |
| `error` | null, atau jenis error |
| `fallback` | true jika putusan diambil dari CodeQL karena LLM error |

**Nilai `sast_action`** (dibandingkan pada CWE yang sama di file yang sama):

| CodeQL mendeteksi | LLM menyatakan rentan | `sast_action` |
|---|---|---|
| ya | ya | `confirmed` |
| ya | tidak | `rejected` |
| tidak | ya | `added` |
| tidak | tidak | `none` |

`sast_action` dihitung oleh framework, tidak diminta dari LLM, supaya definisinya konsisten.

## 7. Penanganan error LLM

Urutan per panggilan:

1. Kegagalan jaringan, rate limit (HTTP 429), atau error server (5xx): retry dengan exponential backoff,
   maksimal `llm.max_network_retries` kali.
2. Respons diterima tapi tidak valid (bukan JSON, tidak sesuai skema, verdict ganda atau hilang): kirim ulang
   prompt yang sama, maksimal `llm.max_format_retries` kali. Setiap percobaan dicatat di log.
3. Jika tetap gagal, putusan dicatat dengan `error` terisi.

Dampak error ke penilaian:
- `B-*`: putusan jatuh ke hasil CodeQL (`fallback = true`). Alasannya, di pipeline sungguhan kegagalan LLM
  tidak boleh menghentikan pipeline, dan perilaku paling masuk akal adalah tetap memakai hasil SAST.
- `C-*`: dihitung sebagai "tidak rentan", karena tidak ada sumber lain.
- Jumlah error dan tingkat error per model selalu dilaporkan, termasuk berapa yang berasal dari masalah format.

Error 4xx selain 429 (misalnya kunci salah, model tidak ditemukan, parameter tidak dikenal) tidak di-retry.
Proses berhenti dengan pesan jelas, karena itu masalah konfigurasi, bukan masalah sementara.

## 8. Cache dan log

**Cache.** Kunci cache adalah SHA-256 dari gabungan: model ID, versi template prompt, prompt yang sudah dirender,
nomor run, dan parameter pemanggilan (reasoning, max output). Nomor run ikut dalam kunci supaya run 2 dan 3
benar-benar panggilan baru, bukan salinan run 1. Isi cache adalah respons mentah plus metadata token dan
latensi. Cache disimpan di `.cache/llm/` dan di GitHub Actions memakai `actions/cache`.

**Log.** Satu baris JSONL per percobaan panggilan di `results/raw/calls-<scenario>-<model>-run<N>.jsonl`:

```
timestamp, case_id, scenario, model_key, model_id, run, attempt, cache_hit,
input_tokens, output_tokens, reasoning_tokens, latency_ms, cost_usd,
status (ok | invalid_format | network_error | api_error), error_message, raw_response
```

`raw_response` disimpan apa adanya untuk audit. Tidak boleh ada API key, header otorisasi, atau isi `.env`.

## 9. Pipeline GitHub Actions

Urutan job: `prefilter` → `codeql` → `review` (matrix) → `aggregate` → `report`.

| Job | Isi | Permissions |
|---|---|---|
| `prefilter` | Gitleaks, seleksi file, menghasilkan daftar file untuk LLM | `contents: read` |
| `codeql` | init, analyze, unggah SARIF ke artifact dan Code Scanning | `contents: read`, `security-events: write` |
| `review` | matrix `model × scenario`, loop run di dalam job | `contents: read` |
| `aggregate` | normalisasi, ensemble, evaluasi | `contents: read` |
| `report` | SARIF per model, laporan HTML, komentar PR | `contents: read`, `security-events: write`, `pull-requests: write` |

Pemicu:
- `workflow_dispatch` dengan input `limit`, `models`, `scenarios`. Ini jalur utama untuk eksperimen.
- `push` dan `pull_request` dari branch di repositori yang sama: pipeline penuh dengan model dari konfigurasi.
- `pull_request` dari fork: hanya `prefilter` dan `codeql`. Job yang butuh secret dilewati dengan kondisi
  `github.event.pull_request.head.repo.full_name == github.repository`.

Konkurensi: satu pipeline per branch (`concurrency` group), run lama dibatalkan untuk push, tidak dibatalkan
untuk `workflow_dispatch` supaya eksperimen tidak terputus.

## 10. Pelaporan

**Komentar PR.** Ringkasan jumlah temuan per sumber, lalu maksimal `report.max_pr_findings` temuan, diurutkan
berdasarkan jumlah sumber yang sepakat lalu tingkat keyakinan. Setiap temuan: file dan baris, CWE, sumber yang
menemukan, alasan singkat, rekomendasi. Ditutup dengan tautan ke artifact laporan lengkap.

**SARIF.** Satu file per model dengan `runs[0].tool.driver.name` = `trisula-<model>`, diunggah dengan `category`
berbeda, sehingga di tab Security tiap model tampil sebagai tool terpisah.

**Laporan HTML.** Dua bagian.
- Evaluasi: tabel metrik per skenario dan CWE, confusion matrix, grafik TPR vs FPR, rincian `sast_action`,
  konsistensi, waktu, biaya, hasil McNemar.
- Developer: daftar temuan per file dengan sumber, tingkat kesepakatan, alasan, rekomendasi. Bisa difilter per CWE
  dan per sumber.

**Grafik paper** (`results/figures/`, PDF vektor, lebar satu kolom IEEE 3,5 inci, font serif ukuran 8):
1. TPR dan FPR per skenario, dipisah per CWE.
2. Posisi tiap skenario di ruang TPR vs FPR, dengan garis diagonal tebakan acak.
3. Komposisi `sast_action` per model (confirmed, rejected, added), dipisah benar dan salah.
4. Biaya per test case vs Benchmark Score per skenario.

Grafik tidak memakai judul di dalam gambar (judul ada di caption paper) dan memakai palet yang tetap terbaca
saat dicetak hitam putih.

## 11. Prefilter

Hanya relevan untuk input ke LLM. CodeQL tetap menganalisis seluruh `source_paths`.

1. Ambil file sesuai `project.source_paths` dan ekstensi bahasa (`.java` untuk Java; `.ts`, `.tsx`, `.js`, `.jsx`
   untuk JavaScript/TypeScript).
2. Buang yang cocok dengan pola `project.exclude`.
3. Jalankan Gitleaks. File yang punya temuan secret dikeluarkan dari input LLM.
4. Pindai pola data pribadi sederhana: email, nomor telepon Indonesia (`08…` atau `+62…`), deret 16 digit
   (kemungkinan NIK). Default hanya peringatan. Jika `prefilter.pii_mode: exclude`, file ikut dikeluarkan.
5. Tulis `results/prefilter.json`: file yang lolos, file yang dikeluarkan beserta alasannya (jenis temuan dan nomor
   baris, tanpa nilai).

## 12. Ancaman validitas

- **Kontaminasi data.** OWASP Benchmark publik dan mungkin pernah dilihat model saat pelatihan. Dimitigasi dengan
  sanitasi (DATASET.md bagian 4), tapi tidak bisa dihilangkan sepenuhnya.
- **Konteks terbatas.** LLM hanya melihat satu file. Sebagian test case aman atau tidaknya bergantung pada kelas
  helper yang tidak disertakan. Kesalahan karena hal ini dianalisis terpisah di bagian analisis kesalahan.
- **Dataset sintetis.** Test case OWASP Benchmark pendek dan polanya seragam, berbeda dari kode aplikasi nyata.
  Studi kasus aplikasi nyata dilakukan pada tahap TA.
- **Versi model.** Model berstatus preview atau bisa diperbarui diam-diam oleh provider. Model ID dan tanggal
  eksperimen dicatat, respons mentah disimpan.
- **Nondeterminisme.** Model reasoning tidak sepenuhnya deterministik. Ditangani dengan run berulang dan
  pelaporan konsistensi.
- **Sensitivitas prompt.** Hasil bisa berubah dengan formulasi prompt berbeda. Satu template yang sama dipakai
  untuk semua model dan tidak diubah setelah eksperimen dimulai.
- **Penyetaraan reasoning.** Tingkat reasoning antar-provider tidak benar-benar setara meski namanya sama.
- **Pilihan query CodeQL.** Hasil baseline bergantung pada query suite. Suite yang dipakai dicatat.
- **Biaya.** Dihitung dari harga daftar saat eksperimen, bukan tagihan aktual.

## 13. Catatan keputusan

| Keputusan | Pilihan | Alasan |
|---|---|---|
| Objek uji paper | OWASP Benchmark Java | Ground truth per test case tersedia dan bisa dinilai otomatis |
| CWE | 89 dan 79 | Arahan dosen: batasi ke beberapa kategori OWASP. Keduanya jalur umum kebocoran data |
| SAST | CodeQL | Native di GitHub, dukungan Java kuat, dipakai sebagai baseline di IRIS |
| Peran LLM | Augmentasi (konfirmasi, tolak, tambah) | Memungkinkan pengukuran kenaikan deteksi sekaligus penurunan false positive |
| Model | Penerus resmi dari keluarga model di Koterba et al. | Versi yang diuji Koterba et al. sudah dipensiunkan provider |
| Prompt | Zero-shot, satu template untuk semua model | Few-shot berisiko membocorkan pola benchmark dan menguntungkan model tertentu |
| Kelas helper | Tidak disertakan | Menjaga input setara dengan analisis per file di pipeline nyata. Dibahas sebagai keterbatasan |
| Analisis utama | Run 1 | Ditetapkan sebelum melihat hasil |
| Fallback B | Putusan CodeQL | Perilaku yang wajar di pipeline produksi |
| Confidence | Kategori | Angka keyakinan LLM tidak terkalibrasi |

## 14. Menunggu keputusan pembimbing

- Persetujuan rencana paper ISRITI dan posisi co-author.
- Objek studi kasus TA: Rumah Pilah atau alternatif lain.
- Apakah kategori CWE tetap 89 dan 79 atau ditambah.
- Apakah mode DAST masuk lingkup TA.
- Cakupan pembahasan UU PDP di TA.
- Judul TA yang disesuaikan dengan lingkup baru.

Semua nilai terkait sudah berada di `config/trisula.yml`, jadi perubahan keputusan tidak memerlukan perubahan kode.
