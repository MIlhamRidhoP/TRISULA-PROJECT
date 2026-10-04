# Dataset: OWASP Benchmark Java

## 1. Sumber dan lisensi

- Repositori: https://github.com/OWASP-Benchmark/BenchmarkJava
- Lisensi: GPL-2.0. File benchmark **tidak boleh di-commit** ke repositori ini. Skrip mengunduh saat dijalankan
  dan menyimpannya di `.cache/benchmark/`.
- Versi dikunci lewat `benchmark.ref` di konfigurasi: commit `8b67a88d73b2594570fc21150705283de884620b`. Jangan
  diubah selama eksperimen. Hash commit ini ditulis di paper.
- `data/` di repositori hanya berisi metadata hasil sampling dan sanitasi (`sample_list.csv`, `name_mapping.csv`,
  `sample_meta.json`): nama test case, kategori, label, dan path baru. Tidak ada kode benchmark di sana. Kode
  hasil pangkas ada di `targets/`, yang tidak di-commit.

Hal yang perlu diverifikasi langsung dari repositori saat implementasi (jangan diasumsikan):
- nama dan lokasi file expected results (biasanya `expectedresults-1.2.csv` di root),
- format kolomnya,
- lokasi folder test case dan helper.

## 2. File expected results

Format yang diharapkan (verifikasi dulu):

```
# test name, category, real vulnerability, cwe, Benchmark version: 1.2, 2016-06-1
BenchmarkTest00001,pathtraver,true,22
BenchmarkTest00002,pathtraver,true,22
...
```

- Baris yang diawali `#` adalah header.
- Kolom `real vulnerability` bernilai `true` atau `false`.
- Kategori yang dipakai diambil dari `cwes[].benchmark_category` di konfigurasi (`sqli`, `xss`).
- Cocokkan juga kolom `cwe` dengan CWE di konfigurasi. Kalau ada test case dengan kategori benar tapi CWE berbeda,
  hentikan proses dan laporkan, karena itu tanda format atau versi berbeda dari yang diasumsikan.

## 3. Sampling

Parameter dari `benchmark.sample` di konfigurasi.

1. Untuk setiap kategori, pisahkan test case berlabel rentan dan tidak rentan.
2. Ambil `per_category * vulnerable_ratio` test case rentan dan sisanya tidak rentan, secara acak dengan
   `random.Random(seed)`. Urutkan dulu daftar kandidat berdasarkan nama sebelum diacak, supaya hasil tidak
   bergantung pada urutan baca file.
3. Jika kandidat tidak cukup, hentikan dengan pesan berisi jumlah yang tersedia.
4. Catat jumlah kandidat yang tersedia per kategori dan label di log. Angka ini ditulis di paper.
5. Tulis `data/sample_list.csv`:

```
original_name,category,cwe,vulnerable
BenchmarkTest00008,sqli,CWE-89,true
...
```

Default: 100 per kategori, rasio 0,5, seed 42, sehingga total 200 test case (50/50/50/50).

## 4. Target analisis

CodeQL butuh konteks proyek supaya bisa mengenali sumber input (misalnya `HttpServletRequest.getParameter`) dan
dependensi. Kalau hanya 200 file yang disalin tanpa proyeknya, CodeQL bisa gagal mengenali tipe dan hasil baseline
jadi lebih buruk dari seharusnya. Itu akan membuat perbandingan tidak adil.

Karena itu `targets/benchmark/` berisi **proyek BenchmarkJava yang dipangkas**:

- `pom.xml` dan struktur folder Maven tetap utuh.
- Folder helper tetap utuh (dibutuhkan CodeQL untuk resolusi tipe).
- Folder test case hanya berisi 200 file sampel. Test case lain dihapus.
- File non-Java yang tidak dibutuhkan untuk kompilasi atau analisis boleh dihapus untuk memperkecil ukuran,
  tapi catat apa saja yang dihapus.

Yang dikirim ke LLM hanya file di folder test case (`project.llm_paths`). Helper tidak dikirim (lihat DESIGN.md
bagian 13).

Setelah pemangkasan dan sanitasi, proyek harus tetap bisa dikompilasi dengan `mvn -q -DskipTests compile`.
Jalankan pemeriksaan ini di CI. Kalau tidak bisa dikompilasi, CodeQL dengan `build-mode: none` masih bisa
berjalan, tapi catat kondisinya karena bisa memengaruhi hasil baseline.

## 5. Sanitasi anti-kontaminasi

Tujuannya mengurangi peluang model mengenali test case dari hafalan, dan menghapus petunjuk label yang tidak
akan ada di kode sungguhan. Sanitasi dilakukan sebelum CodeQL, jadi Skenario A, B, dan C menganalisis kode
yang persis sama.

Aturan, berurutan:

1. **Hapus semua komentar** (line, block, dan Javadoc) memakai tree-sitter-java. Jangan memakai regex, karena
   string literal bisa berisi `//` atau `/*`. Setelah dihapus, rapikan baris kosong berturut-turut menjadi
   maksimal satu.
2. **Nama netral.** Setiap `BenchmarkTestNNNNN` dipetakan ke `<class_prefix>NNNN` (default `Case0001` dst).
   Urutan nomor baru diacak dengan seed yang sama, supaya nomor baru tidak mencerminkan nomor asli.
   Penggantian berlaku di semua tempat: nama kelas, nama file, string literal (nama parameter, nama cookie,
   nama header sering memakai nama test case), dan referensi lain.
3. **Path servlet.** Nilai di anotasi `@WebServlet` diganti menjadi `<servlet_path_prefix>NNNN`
   (default `/case/0001`). Path aslinya mengandung nama kategori seperti `/sqli-00/`, yang merupakan
   kebocoran label. Di string literal lain mana pun, segmen path berpola `/<kategori>-NN/` untuk kategori apa pun
   di expected results diganti dengan `<servlet_path_prefix>`. Contoh: `getRequestDispatcher("/sqli-02/foo.html")`
   menjadi `getRequestDispatcher("/case/foo.html")`.
4. **Nama paket** (jika `sanitize.rename_package: true`). Ganti `package_from` menjadi `package_to` di
   deklarasi `package`, pernyataan `import`, nama lengkap kelas, dan struktur folder, di seluruh proyek yang
   dipangkas. Ini menghilangkan kata `owasp` dan `benchmark` dari kode yang dilihat model.
5. **Pemeriksaan sisa.** Setelah sanitasi, cari pola berikut di folder test case tanpa membedakan huruf besar
   kecil:
   - `benchmarktest`, `owasp.benchmark`, dan `org/owasp/benchmark` di mana pun;
   - kata `benchmark` sebagai identifier atau segmen path utuh (bukan bagian kata lain);
   - nama kategori dalam cakupan konfigurasi (`sqli`, `xss`) bila muncul di string literal atau sebagai segmen
     path (misalnya `com.example.sqli`).

   Nama kategori di luar cakupan tidak diperiksa, karena muncul sah di nama library (misalnya `hash` di
   `java.util.HashMap`). `org.owasp.esapi` bukan pelanggaran: itu library sanitasi sungguhan yang harus tetap
   terlihat oleh model. Jika ditemukan, laporkan file, baris, dan potongan kodenya, lalu hentikan. Pengecualian
   yang memang sah dicatat eksplisit di `allowed_matches` beserta alasannya, bukan diabaikan diam-diam.
6. Tulis `data/name_mapping.csv`:

```
original_name,case_id,new_path
BenchmarkTest00008,Case0137,targets/benchmark/src/main/java/.../Case0137.java
```

## 6. Verifikasi sebelum eksperimen

Checklist yang dijalankan otomatis oleh `python -m trisula sample` dan `sanitize`, dan dicatat hasilnya:

- [ ] Jumlah sampel per kategori dan label sesuai konfigurasi.
- [ ] Hash commit benchmark tercatat.
- [ ] Tidak ada sisa string terlarang (aturan 5).
- [ ] Semua file test case ter-parse tanpa error node.
- [ ] Proyek terkompilasi (atau kondisinya tercatat).
- [ ] `name_mapping.csv` lengkap dan setiap `case_id` unik.
