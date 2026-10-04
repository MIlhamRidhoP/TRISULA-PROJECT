# Catatan Implementasi

Ditulis 5 Oktober 2026 setelah Fase 1 sampai 11 selesai, lalu diperbarui setelah keputusan pemilik atas open
questions.

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
| Keputusan 1 | Aturan 3 diperluas, aturan 5 dipersempit, `allowed_matches`, ref dikunci | `139ef17` |
| Keputusan 2 | `data/` di-commit (metadata saja) | `b1fca23` |
| Keputusan 3 | Compile tanpa Spotless, unggah SARIF tidak memblokir | `d34d52f` |

Tes: 129 lulus, 0 gagal (`pytest -q`). `ruff check .` dan `ruff format --check .` bersih. `actionlint` 1.7.12
bersih untuk kedua workflow.

Uji clone bersih: repositori di-clone ke folder baru, venv Python 3.12 baru, `pip install -r requirements.txt`,
lalu `python -m trisula demo` selesai sekitar 3 detik tanpa API key, dan seluruh tes lulus di clone tersebut.

## Keputusan yang sudah diterapkan

### Sanitasi (sebelumnya open question 1)

Diterapkan sesuai keputusan, dan DATASET.md bagian 5 sudah disesuaikan:
- Aturan 3: di string literal mana pun, segmen `/<kategori>-NN/` untuk kategori apa pun di expected results
  diganti `servlet_path_prefix`. Empat kasus `getRequestDispatcher` kini menjadi `"/case/CaseNNNN.html"`.
- Aturan 5: yang diperiksa hanya `benchmarktest`, `owasp.benchmark`, `org/owasp/benchmark`, kata `benchmark`
  utuh sebagai identifier atau segmen path, dan `sqli`/`xss` di string literal atau sebagai segmen path.
  "Identifier" saya tafsirkan sebagai kata utuh, jadi `benchmarking` tidak dihitung; `BenchmarkTest` tetap
  tertangkap lewat pola `benchmarktest`.
- `allowed_matches: [X-XSS-Protection]` dengan komentar alasan di konfigurasi.

Hasil pada sampel asli (commit benchmark terkunci, seed 42): 200 kasus tersanitasi, semua ter-parse, **tidak ada
hit tersisa**, jadi tidak ada daftar hit untuk ditinjau. Yang tersisa di kode test case dan terlihat oleh model:
header `X-XSS-Protection` di 100 kasus xss (diizinkan) dan `org.owasp.esapi` di 48 kasus (library, sesuai
keputusan). Header itu tetap menjadi petunjuk kategori bagi model; layak disebut di ancaman validitas paper.

### `benchmark.ref` dan `data/` (sebelumnya open question 2)

`benchmark.ref` dikunci ke `8b67a88d73b2594570fc21150705283de884620b`. `data/` tidak lagi di-.gitignore.
`sample` dan `sanitize` dijalankan ulang dengan konfigurasi asli. Yang di-commit: `data/sample_list.csv`,
`data/name_mapping.csv`, dan juga `data/sample_meta.json` (commit benchmark, jumlah kandidat, daftar kategori yang
dibaca `sanitize`). Ketiganya metadata, bukan kode benchmark; catatan ini ada di README dan DATASET.md.
`targets/` tetap di-.gitignore.

## Open questions

Tidak ada yang terblokir. Butir di bawah adalah keputusan implementasi yang sebaiknya dikonfirmasi.

### Keputusan implementasi yang perlu dikonfirmasi

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

## Verifikasi lokal

- **Kompilasi Maven** (JDK 24.0.2, Maven 3.9.11): `mvn -q -B -DskipTests compile` pada `targets/benchmark` gagal,
  bukan karena kode, tapi karena plugin Spotless di pom BenchmarkJava menjalankan `spotless:apply` saat build dan
  mencari `DevStyleHtml.prefs` yang ikut terbuang saat pemangkasan. Kalau berhasil berjalan, `apply` akan
  memformat ulang kode tersanitasi dan menggeser nomor baris, jadi Spotless memang harus dilewati. Dengan
  `-Dspotless.skip=true` kompilasi berhasil dan 200 kelas `CaseNNNN` terbentuk. File sumber tidak tersentuh
  (waktu modifikasi sama dengan saat sanitasi). Langkah compile di workflow sudah memakai flag itu.
- **Gitleaks** 8.30.1 (Windows, checksum diverifikasi) terhadap 200 kasus: `no leaks found`. Prefilter dengan
  Gitleaks aktif meloloskan 200 file, tanpa pengecualian dan tanpa peringatan PII.
- **Pipeline `models=mock` tanpa secret**: matrix dari input `models=mock` menghasilkan dua job (`mock`/B dan
  `mock`/C) dengan `key_env` kosong, sehingga semua variabel kunci bernilai string kosong dan adaptor mock tidak
  membaca kunci apa pun. Urutan perintah Python semua job dijalankan di lokal pada 200 kasus asli (CodeQL diganti
  SARIF kosong karena CodeQL CLI tidak terpasang): `parse-sarif`, `review` B (3 run) dan C, `ensemble` (ENS
  dilewati dengan peringatan karena anggota ensemble bukan mock), `evaluate`, dan `report` semuanya selesai dengan
  exit 0.
- Satu hal yang bisa menggagalkan run tanpa secret sudah diperbaiki: sebelumnya SARIF diunggah di dalam langkah
  `analyze`, sehingga repositori yang belum mengaktifkan Code Scanning akan menghentikan job `codeql` dan seluruh
  pipeline. Sekarang `analyze` memakai `upload: never`, lalu unggahan dilakukan di langkah `upload-sarif`
  terpisah dengan `continue-on-error: true` (begitu juga unggahan SARIF per model di job `report`).

## TODO tersisa

- Workflow belum pernah dijalankan di GitHub; pemeriksaan di atas hanya simulasi lokal ditambah `actionlint`.
  Yang perlu dilihat di run pertama: `paths` CodeQL untuk Java dengan `build-mode: none`, unggah SARIF per model
  tanpa input `category`, flag `gh pr comment --edit-last --create-if-none`, dan struktur folder hasil
  `download-artifact` dengan `merge-multiple`.
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

- **`config/trisula.yml`**: komentar di baris `gemini.reasoning` ("Pro mungkin hanya menerima low/high") sudah
  tidak berlaku; dokumentasi per 4 Oktober 2026 mencantumkan `medium`. Nilainya tidak saya ubah.
- **PROVIDERS.md**: pertimbangkan `store: false` di Responses API (OpenAI dan xAI) agar respons tidak disimpan di
  sisi provider. Belum saya pakai karena belum dipastikan xAI menerima parameter itu, dan parameter yang tidak
  dikenal menghentikan proses (error 4xx).
- **DESIGN.md bagian 6**: tambahkan `ensemble` ke daftar nilai `source`.
- **DESIGN.md bagian 12**: tambahkan header `X-XSS-Protection` yang hanya muncul di kasus xss sebagai petunjuk
  kategori yang sengaja dibiarkan.

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

Perintah `git log --format='%an <%ae>%n%B' | grep -iE 'claude|anthropic|co-authored'` dijalankan setelah setiap
commit dan pada seluruh riwayat (`089523c` sampai commit catatan ini). Hasilnya selalu kosong. Semua commit
ber-author Muhammad Ilham Ridho Priyadi.
