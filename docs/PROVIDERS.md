# Provider LLM

Dikumpulkan per 4 Oktober 2026. API LLM berubah cepat, jadi setiap butir bertanda **[verifikasi]** wajib dicek
ke dokumentasi resmi sebelum diimplementasikan. Kalau dokumentasi resmi berbeda dengan catatan di sini, ikuti
dokumentasi resmi lalu perbarui dokumen ini.

## Ringkasan

| Kunci | Provider | Model ID | SDK | API | Harga input / output per 1M token | Env var |
|---|---|---|---|---|---|---|
| `gemini` | Google | `gemini-3.1-pro-preview` | `google-genai` | Gemini API (`generate_content`) | $2,00 / $12,00 | `GEMINI_API_KEY` |
| `gpt` | OpenAI | `gpt-5.3-codex` | `openai` | Responses API | $1,75 / $14,00 | `OPENAI_API_KEY` |
| `grok` | xAI | `grok-4.7` | `openai` dengan `base_url="https://api.x.ai/v1"` | Responses API | $2,00 / $6,00 | `XAI_API_KEY` |

Harga Gemini berlaku untuk prompt di bawah 200 ribu token. Prompt di penelitian ini jauh di bawah batas itu.

Kenapa model ini: Koterba et al. memakai Gemini 3 Pro, GPT-5 Codex, dan Grok 4. Ketiga versi itu sudah tidak
tersedia atau berstatus deprecated di API resmi per Oktober 2026, sehingga dipakai penerus resmi dari keluarga
yang sama. Catat ini di bagian Methodology dan ancaman validitas.

## Aturan umum untuk semua adaptor

- Prompt sistem dan prompt pengguna dirender dari `prompts/sast_review.md`.
- Pakai fitur structured output native dengan skema dari DESIGN.md bagian 5, lalu tetap validasi ulang dengan
  Pydantic. Jangan mengandalkan model "biasanya mengikuti format".
- Tidak mengatur `temperature`, `top_p`, atau seed. Model reasoning generasi ini umumnya tidak mendukung atau tidak
  menyarankan pengaturan tersebut. Konsistensi diukur lewat run berulang. **[verifikasi]** untuk tiap model.
- Tingkat reasoning dari `llm.models.<kunci>.reasoning`. Nilai yang benar-benar dikirim ke API dicatat di log.
- `max_output_tokens` dari konfigurasi. Untuk model reasoning, batas ini biasanya mencakup token berpikir, jadi
  jangan terlalu kecil. Jika respons terpotong karena batas, perlakukan sebagai `invalid_format` dan catat
  penyebabnya.
- Ambil jumlah token dari objek usage di respons, bukan menghitung sendiri.
- Panggilan bersifat satu giliran (single-turn). Tidak ada riwayat percakapan, tidak ada tools, tidak ada web search.

## Google Gemini

Dokumentasi:
- https://ai.google.dev/gemini-api/docs/latest-model
- https://ai.google.dev/gemini-api/docs/structured-output
- https://ai.google.dev/gemini-api/docs/thinking
- https://ai.google.dev/gemini-api/docs/pricing
- https://ai.google.dev/gemini-api/docs/deprecations

Pola pemanggilan (gambaran, nama parameter **[verifikasi]**):

```python
from google import genai
from google.genai import types

client = genai.Client(api_key=os.environ["GEMINI_API_KEY"])
response = client.models.generate_content(
    model=model_id,
    contents=user_prompt,
    config=types.GenerateContentConfig(
        system_instruction=system_prompt,
        response_mime_type="application/json",
        response_json_schema=verdict_schema,      # atau response_schema, cek mana yang didukung
        thinking_config=types.ThinkingConfig(thinking_level=reasoning),
        max_output_tokens=max_output_tokens,
    ),
)
```

Catatan:
- Seri Gemini 3 memakai `thinking_level`, bukan `thinking_budget`. Mengirim keduanya sekaligus menghasilkan
  error.
- Nilai `thinking_level` yang tersedia untuk model Pro **[verifikasi]**. Ada indikasi model Pro hanya menerima
  `low` dan `high` (default `high`). Jika `medium` tidak diterima, **jangan memilih sendiri**. Catat di
  `NOTES.md` sebagai open question, karena ini keputusan desain (penyetaraan reasoning antar-model).
  Dicek 4 Oktober 2026: halaman thinking mencantumkan `low`, `medium`, `high` untuk `gemini-3.1-pro-preview`.
- Dicek 4 Oktober 2026: halaman structured output kini hanya mencontohkan Interactions API
  (`client.interactions.create` dengan `response_format`). `generate_content` dengan `response_json_schema` masih
  ada di SDK google-genai 2.28 dan tidak ditandai deprecated, jadi adaptor tetap memakainya.
- Usage: `usage_metadata.prompt_token_count`, `candidates_token_count`, `thoughts_token_count`. Token berpikir
  ditagih dengan tarif output.
- Model Pro tidak tersedia di free tier. Project Google Cloud harus mengaktifkan billing.
- `gemini-3-pro-preview` sudah dimatikan. Pastikan tidak ada sisa referensi ke model ID itu.

## OpenAI GPT

Dokumentasi:
- https://developers.openai.com/api/docs/models/gpt-5.3-codex
- https://developers.openai.com/api/docs/pricing
- Dokumentasi Responses API dan structured outputs di situs yang sama

Pola pemanggilan (gambaran, **[verifikasi]**):

```python
from openai import OpenAI

client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])
response = client.responses.create(
    model=model_id,
    instructions=system_prompt,
    input=user_prompt,
    reasoning={"effort": reasoning},
    text={"format": {
        "type": "json_schema",
        "name": "trisula_verdicts",
        "schema": verdict_schema,
        "strict": True,
    }},
    max_output_tokens=max_output_tokens,
)
text = response.output_text
```

Catatan:
- `gpt-5.3-codex` hanya tersedia lewat Responses API, bukan Chat Completions.
- Mode `strict` mensyaratkan semua properti masuk `required` dan `additionalProperties: false` di setiap objek.
  Skema di DESIGN.md sudah memenuhi syarat itu. Field yang boleh kosong memakai tipe `["string", "null"]`.
- Usage: `usage.input_tokens`, `usage.output_tokens`, `usage.output_tokens_details.reasoning_tokens`.
  `output_tokens` sudah mencakup token reasoning **[verifikasi]**, jadi jangan dijumlahkan dua kali.
- `gpt-5-codex` berstatus deprecated. Jangan dipakai.

## xAI Grok

Dokumentasi:
- https://docs.x.ai/developers/grok-4-7
- https://docs.x.ai/developers/models
- https://docs.x.ai/developers/pricing
- https://docs.x.ai/developers/model-capabilities/text/reasoning
- https://docs.x.ai/developers/model-capabilities/text/structured-outputs

Pola pemanggilan sama dengan GPT, hanya klien yang berbeda:

```python
client = OpenAI(api_key=os.environ["XAI_API_KEY"], base_url="https://api.x.ai/v1")
response = client.responses.create(model="grok-4.7", ...)
```

Catatan:
- xAI menyarankan Responses API. Chat Completions berstatus legacy.
- Tingkat reasoning yang tersedia: `low`, `medium`, `high` (default), `xhigh`. Cara mengirimnya di Responses API
  (`reasoning.effort` atau parameter lain) **[verifikasi]**. Dicek 4 Oktober 2026: `reasoning: {"effort": ...}`.
- Respons Responses API dari `grok-4.7` selalu menyertakan `reasoning.encrypted_content`. Karena panggilan
  bersifat satu giliran, bagian ini diabaikan, tapi jangan sampai ikut tersimpan berulang di log sehingga file
  membengkak. Simpan teks output dan usage saja di `raw_response`.
- xAI menyarankan `prompt_cache_key` untuk memperbesar peluang cache hit. **Jangan dipakai** di eksperimen ini
  kecuali diputuskan lain, supaya perbandingan biaya antar-provider tidak bias. Jika usage melaporkan token yang
  ter-cache, simpan angkanya di log, tapi biaya utama tetap dihitung dengan harga daftar.
- `grok-4` dan `grok-4-fast` sudah tidak tersedia. Varian Grok 4.7 Fast tidak tersedia di API publik.

## Kebijakan data (relevan untuk studi kasus TA)

Sebelum mengirim kode aplikasi nyata (misalnya Rumah Pilah), periksa kebijakan penggunaan data API dari ketiga
provider: apakah data dipakai untuk pelatihan, berapa lama disimpan, dan di negara mana diproses. Ringkasan
kebijakan dan tanggal pengecekannya dicatat di dokumen TA. Untuk OWASP Benchmark hal ini tidak menjadi masalah
karena datanya publik.

## Uji coba pertama dengan API sungguhan

1. Isi saldo kecil di tiap provider.
2. Jalankan `python -m trisula review --model <kunci> --scenario B --run 1 --limit 3`.
3. Periksa di log: model ID yang tercatat, tingkat reasoning yang benar-benar terkirim, jumlah token, biaya, dan
   apakah JSON lolos validasi tanpa retry.
4. Hitung biaya per test case dari uji coba, lalu proyeksikan ke run penuh sebelum menambah saldo.
