# Catatan Implementasi

Ditulis 5 Oktober 2026 setelah Fase 1 sampai 11 selesai.

## Status fase

| Fase | Isi | Commit |
|---|---|---|
| Persiapan | Rename LASA ke TRISULA di dokumen starter | `089523c` |
| 1 | Konfigurasi, skema, kerangka CLI | `9c3e348` |
| 2 | Sampling berstrata | `6f8f65e` |
| 3 | Sanitasi dengan tree-sitter | `b2d4f20` |
| 4 | Job CodeQL dan parser SARIF | `20928d3` |
| 5 | Adaptor LLM, render prompt, `review` | `c27b250` |
| 6 | Job review matrix dan `ci.yml` | `af1a88a` |
| 7 | Normalisasi dan ensemble | `d890526` |
| 8 | Evaluasi dan uji McNemar | `3e3f89d` |
| 9 | SARIF, komentar PR, HTML, grafik | `21f4daa` |
| 10 | Prefilter dan Gitleaks | `6ce0a99` |
| 11 | Demo, README, lisensi | `df107ff` |

Tes: 119 lulus, 0 gagal (`pytest -q`). `ruff check .` dan `ruff format --check .` bersih. `actionlint` 1.7.12
bersih untuk kedua workflow.

Uji clone bersih: repositori di-clone ke folder baru, venv Python 3.12 baru, `pip install -r requirements.txt`,
lalu `python -m trisula demo` selesai sekitar 3 detik tanpa API key, dan seluruh tes lulus di clone tersebut.

## Open questions

### 1. Pemeriksaan sisa string menghentikan sanitasi pada data asli

`python -m trisula sanitize` pada sampel asli (BenchmarkJava commit `8b67a88d73b2594570fc21150705283de884620b`,
seed 42) berhenti dengan 199 temuan, sesuai DATASET.md bagian 5 butir 5. Target tidak berubah karena semua
perubahan baru ditulis setelah pemeriksaan lolos. Token pemicu:

| Token | Jumlah file | Sifat |
|---|---|---|
| `X-XSS-Protection` (header) | 100 | nama header HTTP, tapi hanya muncul di kasus xss |
| `org.owasp.esapi.ESAPI` | 48 | library encoder ESAPI |
| `java.util.HashMap` | 29 | kelas JDK, cocok dengan kategori `hash` |
| `org.owasp` lalu `.esapi` di baris berikutnya | 6 | panggilan ESAPI yang terpotong baris |
| `getRequestDispatcher("/sqli-02/BenchmarkTestNNNNN.html")` | 4 | kebocoran kategori yang tidak dicakup aturan 3 |

Keputusan yang dibutuhkan:
- Isi `benchmark.sanitize.allowed_matches`. Usulan: `X-XSS-Protection`, `org.owasp.esapi`, `java.util.HashMap`.
  Pencocokan dilakukan per baris tanpa membedakan huruf besar kecil, jadi 6 kasus ESAPI yang terpotong baris
  tetap gagal. Pilihannya: tambahkan `org.owasp` (lebih longgar), atau ubah pencocokan agar memakai teks yang
  barisnya sudah disambung.
- Header `X-XSS-Protection: 0` hanya ada di kasus xss, jadi tetap menjadi petunjuk kategori walaupun sah sebagai
  kode. Perlu diputuskan apakah dibiarkan (dan dibahas sebagai ancaman validitas) atau dihapus saat sanitasi.
- Empat kasus meneruskan request ke `/sqli-0N/<nama>.html`. Usulan: perluas aturan 3 sehingga setiap string
  literal berpola `/<kategori>-NN/<nama asli>` diganti path netral yang sama.

Sampai diputuskan, pipeline penuh pada data asli (lokal maupun di GitHub Actions) berhenti di tahap `sanitize`.
Demo dan tes memakai fixture sendiri dengan `allowed_matches: [X-XSS-Protection]`.

Sebagai uji coba saja, sanitasi dengan `allowed_matches` sementara (`X-XSS-Protection`, `org.owasp`,
`java.util.HashMap`, `/sqli-0`, tidak di-commit) berhasil untuk 200 kasus, semua file ter-parse, prefilter
meloloskan 200 file, dan `review --model mock --scenario B --run 1` berjalan untuk 200 kasus.

### 2. Mengunci `benchmark.ref`

DATASET.md meminta `master` diganti hash commit saat sampling pertama. Saya tidak mengubah nilai konfigurasi.
Commit yang dipakai saat pengembangan: `8b67a88d73b2594570fc21150705283de884620b` (tercatat juga di
`data/sample_meta.json`). `data/` sengaja di-.gitignore sampai ref dikunci; setelah itu commit dengan
`git add -f data/sample_list.csv data/name_mapping.csv data/sample_meta.json`.

### 3. Keputusan implementasi yang perlu dikonfirmasi

Hal-hal berikut tidak diatur eksplisit di DESIGN.md, jadi saya memilih yang paling wajar:

- **Waktu pipeline** `B-<model>` = durasi CodeQL + waktu dinding run utama saja, bukan seluruh job (job memuat
  tiga run, sedangkan pipeline sungguhan hanya menjalankan satu).
- **Simpangan baku antar-run** memakai simpangan baku sampel (`statistics.stdev`, n-1).
- **Konsistensi dan mayoritas run** memakai putusan akhir, termasuk putusan fallback ke CodeQL bila LLM error.
- **Pasangan McNemar**: b = hanya skenario pertama yang benar, c = hanya skenario kedua yang benar. Koreksi Holm
  diterapkan atas semua pasangan sekaligus.
- **ENS** hanya dibentuk jika semua anggota punya putusan B pada run ensemble. Jika ada anggota yang belum
  dijalankan (misalnya uji coba dengan satu model), ENS dilewati dengan peringatan, karena hasilnya akan identik
  dengan CodeQL dan menyesatkan. Field `source` untuk ENS bernilai `ensemble` (tidak ada di daftar DESIGN.md
  bagian 6).
- **Prefilter** memindai `project.llm_paths`, bukan seluruh `source_paths`, supaya helper yang memang tidak dikirim
  tidak memenuhi laporan. Selain Gitleaks, prefilter memakai pola kunci bawaan yang ketat (format kunci AWS,
  GitHub, OpenAI, Google, xAI, Slack, private key) agar file berisi kunci tetap tertahan saat Gitleaks tidak
  terpasang di lokal. Pada 200 kasus asli, pola bawaan dan PII tidak mengeluarkan satu file pun.
- **Review membutuhkan `prefilter.json`.** Tanpa file itu, `review` menolak berjalan, sehingga tidak ada file yang
  terkirim ke LLM tanpa lewat prefilter.
- **Cache** menyimpan seluruh percobaan yang menghasilkan respons dari API (termasuk respons rusak yang diulang),
  tanpa kegagalan jaringan. Saat cache hit, percobaan diputar ulang ke log dengan `cache_hit: true` dan biaya
  aslinya. Kunci cache memakai model ID, dan file cache dipisah per kunci model di `.cache/llm/<model>/`.
- **SARIF per model** hanya memuat putusan rentan non-fallback. Putusan tanpa baris ditaruh di baris 1 karena
  Code Scanning mewajibkan lokasi. Level SARIF dipetakan dari confidence: high ke error, medium ke warning,
  low ke note.
- **Job prefilter** juga menyiapkan target (`sample`, `sanitize`, `mvn compile`) karena `targets/` tidak di-commit.
  Untuk target non-benchmark, dua langkah pertama perlu dihapus dari workflow.

## TODO tersisa

- Workflow belum pernah dijalankan di GitHub; yang sudah dipastikan hanya lolos `actionlint`. Hal yang perlu
  dilihat di run pertama: `paths` CodeQL untuk Java dengan `build-mode: none`, unggah SARIF tanpa input
  `category` (tiap file memakai `automationDetails.id`), flag `gh pr comment --edit-last --create-if-none`, dan
  struktur folder hasil `download-artifact` dengan `merge-multiple`.
- `mvn -q -DskipTests compile` pada proyek hasil pangkas belum dicoba di lokal; di workflow hasilnya dicatat di
  `results/compile_status.json` tanpa menghentikan pipeline.
- Gitleaks belum dijalankan terhadap 200 kasus asli. Jika aturan `generic-api-key` menandai kasus benchmark,
  kasus itu keluar dari input LLM dan jumlah sampel efektif berkurang. Periksa `results/prefilter.json` di run
  pertama.
- Penempatan label di grafik 2 dan 4 otomatis (diselang-seling atas dan bawah). Dengan data asli, label mungkin
  masih perlu dirapikan manual untuk paper.
- Laporan HTML belum punya tooltip hover pada grafik; angka lengkap ada di tabel di bawahnya.

## Yang harus diverifikasi saat pertama memakai API sungguhan

Jalankan `python -m trisula review --model <kunci> --scenario B --run 1 --limit 3` untuk tiap model, lalu periksa
`results/raw/calls-B-<kunci>-run1.jsonl`:

1. `model_id` di log sesuai konfigurasi dan diterima API (tidak ada HTTP 404).
2. `request_params`: Gemini mengirim `thinking_level: MEDIUM`, GPT dan Grok mengirim `reasoning.effort: medium`.
3. Structured output diterima: GPT dan Grok dengan `text.format` `json_schema` mode `strict`; Gemini dengan
   `response_json_schema`. Jika Gemini menolak `response_json_schema`, cek apakah perlu pindah ke Interactions API
   (dokumentasi structured output Gemini kini hanya mencontohkan API itu).
4. Token: untuk Gemini, `output_tokens` di log = `candidates_token_count + thoughts_token_count`. Pastikan
   `candidates_token_count` memang belum memuat token berpikir; jika sudah, biaya Gemini terhitung dua kali.
   Untuk GPT dan Grok, pastikan `output_tokens` sudah memuat `reasoning_tokens`.
5. Grok: respons tidak membuat log membengkak. Yang disimpan hanya `output_text`, jadi
   `reasoning.encrypted_content` tidak ikut.
6. Status `ok` tanpa retry untuk ketiga kasus. Jika ada `invalid_format`, baca `error_message` dan `raw_response`.
7. Hitung biaya per kasus dari log, proyeksikan ke 200 kasus x (3 run B + 1 run C) x 3 model sebelum menambah saldo.
8. Retry bawaan SDK dimatikan (`max_retries=0` untuk openai, `HttpRetryOptions(attempts=1)` untuk google-genai).
   Pastikan percobaan ulang karena 429 atau 5xx muncul sebagai baris `network_error` terpisah di log.

## Usulan perubahan

- **`config/trisula.yml`**: isi `allowed_matches` (lihat Open question 1). Komentar di baris
  `gemini.reasoning` ("Pro mungkin hanya menerima low/high") sudah tidak berlaku; dokumentasi per 4 Oktober 2026
  mencantumkan `medium`. Nilainya tidak saya ubah.
- **DATASET.md aturan 3**: perluas penggantian path servlet ke semua string literal berpola
  `/<kategori>-NN/<nama asli>`, bukan hanya di `@WebServlet`.
- **DATASET.md aturan 5**: pertimbangkan pencocokan kata utuh untuk nama kategori. Pencocokan substring membuat
  `hash` cocok dengan `HashMap` dan `hashCode`, sehingga daftar pengecualian akan panjang.
- **PROVIDERS.md**: pertimbangkan `store: false` di Responses API (OpenAI dan xAI) agar respons tidak disimpan di
  sisi provider. Belum saya pakai karena belum dipastikan xAI menerima parameter itu, dan parameter yang tidak
  dikenal menghentikan proses (error 4xx).
- **DESIGN.md bagian 6**: tambahkan `ensemble` ke daftar nilai `source`.

PROVIDERS.md sudah saya perbarui untuk dua butir `[verifikasi]` yang terjawab oleh dokumentasi resmi (tingkat
thinking Gemini 3.1 Pro dan cara mengirim reasoning ke Grok), sesuai instruksi di dokumen itu sendiri.

## Penyimpangan dari struktur di CLAUDE.md

- Sampling dan sanitasi ditulis sebagai `trisula/sampling.py` dan `trisula/sanitize.py`, bukan di `tools/`,
  supaya bisa diimpor langsung oleh CLI tanpa memanipulasi `sys.path`.
- Orkestrasi review ada di `trisula/review.py`; `trisula/llm/base.py` berisi satu jalur pemanggilan per file.
  Render prompt ada di `trisula/llm/prompt.py`.
- `trisula/report/build.py` menjalankan keempat keluaran laporan; `trisula/demo.py` untuk subcommand `demo`.
- Fixture demo ada di `demo/` (bukan `tests/fixtures`) karena dipakai saat runtime oleh `python -m trisula demo`.
- `jsonschema` ditambahkan ke `requirements.txt`, hanya dipakai tes untuk memvalidasi SARIF terhadap skema resmi
  OASIS (`tests/fixtures/sarif-schema-2.1.0.json`).
- `results/` seluruhnya di-.gitignore (PLAN.md hanya menyebut `results/raw/`), karena semua isinya dibangkitkan
  ulang. Hasil eksperimen final bisa di-commit dengan `git add -f`.

## Audit gaya

Pencarian di seluruh file yang di-track (kecuali skema SARIF vendor) untuk daftar kata terlarang, frasa template
bahasa Indonesia, em dash, dan emoji. Hasil sebelum perbaikan: satu kata (`harness` di deskripsi
`pyproject.toml`), sudah diganti. Setelah perbaikan: tidak ada temuan. Tidak ada `print(` di paket, tidak ada
komentar `# Step`, `TODO`, `NOTE:`, atau komentar yang mengulang kode. Nama generik `result` dan `item` di luar
cakupan sangat kecil sudah diganti.

## Pengecekan kepemilikan commit

Perintah `git log --format='%an <%ae>%n%B' | grep -iE 'claude|anthropic|co-authored'` pada seluruh riwayat
(12 commit, `089523c` sampai `df107ff`) tidak mengeluarkan baris apa pun. Semua commit ber-author
Muhammad Ilham Ridho Priyadi. Pengecekan yang sama dijalankan setelah setiap commit dan selalu kosong.
