Hand-written files shaped like the BenchmarkJava layout, used by `python -m trisula demo` and the tests.
None of this is OWASP Benchmark code.

- `benchmark_mini/`: 18 servlet cases (8 sqli, 8 xss, 2 cmdi) with an expected results file.
- `codeql.sarif`: CodeQL-style SARIF for the sanitized case IDs the demo produces with seed 42.
  If sampling or sanitization changes, its paths and line numbers must be updated.
