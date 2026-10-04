# Catatan Implementasi

## Open questions

### 1. Pemeriksaan sisa string menghentikan sanitasi pada data asli

`python -m trisula sanitize` pada sampel asli (BenchmarkJava commit `8b67a88d73b2594570fc21150705283de884620b`,
seed 42) berhenti dengan 199 temuan, sesuai aturan DATASET.md bagian 5 butir 5. Target tidak berubah karena
semua perubahan baru ditulis setelah pemeriksaan lolos. Rincian token pemicu:

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
- Header `X-XSS-Protection: 0` hanya ada di kasus xss, jadi tetap menjadi petunjuk kategori meskipun sah sebagai
  kode. Perlu diputuskan apakah dibiarkan (dan dibahas sebagai ancaman validitas) atau dihapus saat sanitasi.
  Menghapusnya mengubah perilaku servlet, walau tidak memengaruhi ada tidaknya kerentanan di sisi server.
- Empat kasus meneruskan request ke `/sqli-0N/<nama>.html`. Usulan: perluas aturan 3 sehingga setiap string
  literal berpola `/<kategori>-NN/<nama asli>` diganti dengan path netral yang sama.

Sampai diputuskan, pipeline penuh pada data asli tidak bisa melewati tahap `sanitize`. Demo dan tes memakai
fixture sendiri dengan `allowed_matches: [X-XSS-Protection]`.

## Hasil pengecekan dokumentasi provider (4 Oktober 2026)

- Gemini: halaman thinking menyebut `gemini-3.1-pro-preview` menerima `low`, `medium`, `high`. Jadi
  `reasoning: medium` di konfigurasi valid dan tidak perlu menjadi open question. Halaman structured output kini
  hanya mencontohkan Interactions API (`client.interactions.create` dengan `response_format`). Adaptor tetap
  memakai `generate_content` dengan `response_json_schema` sesuai PROVIDERS.md, karena SDK google-genai 2.28 masih
  menyediakannya dan dokumentasi tidak menandainya deprecated.
- GPT-5.3-codex: hanya Responses API, effort `low`/`medium`/`high`/`xhigh`, mendukung structured outputs.
- Grok 4.7: `reasoning: {"effort": ...}` di Responses API, nilai `low`/`medium`/`high`/`xhigh`.
- Retry bawaan SDK dimatikan (`max_retries=0` untuk openai, `HttpRetryOptions(attempts=1)` untuk google-genai)
  supaya setiap percobaan tercatat di log TRISULA.

## Penyimpangan dari struktur di CLAUDE.md

- Sampling dan sanitasi ditulis sebagai `trisula/sampling.py` dan `trisula/sanitize.py`, bukan di `tools/`,
  supaya bisa diimpor langsung oleh CLI tanpa memanipulasi `sys.path`.
