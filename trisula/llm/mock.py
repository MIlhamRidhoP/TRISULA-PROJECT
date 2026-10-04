import hashlib
import json
import re

from trisula.llm.base import Completion, CompletionRequest, LLMAdapter

# Peluang putusan mock pada Skenario B mengikuti CodeQL, dan peluang putusan berubah antar-run.
# Nilainya hanya membuat data demo terlihat wajar; tidak dipakai di eksperimen.
AGREE_WITH_CODEQL = 0.8
FLIP_BETWEEN_RUNS = 0.1


def _unit(*parts: object) -> float:
    digest = hashlib.sha256("|".join(map(str, parts)).encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big") / 2**64


class MockAdapter(LLMAdapter):
    """Putusan deterministik dari hash nama file. Sebagian respons sengaja rusak untuk menguji jalur retry."""

    def complete(self, request: CompletionRequest) -> Completion:
        key, path = self.model_key, request.file_path
        cwe_ids = request.schema["properties"]["verdicts"]["items"]["properties"]["cwe"]["enum"]
        input_tokens = (len(request.system) + len(request.user)) // 4

        if _unit(key, path, request.run, request.attempt, "format") < self.model.invalid_response_rate:
            broken = '{"verdicts": [' if _unit(key, path, request.attempt) < 0.5 else '{"verdicts": []}'
            return Completion(text=broken, input_tokens=input_tokens, output_tokens=10, reasoning_tokens=0)

        has_hints = "<static_analysis_findings" in request.user
        verdicts = []
        for cwe in cwe_ids:
            flagged = re.search(rf"Rule: \S+ \([^)]*\b{cwe}\b[^)]*\)\n  Location: line (\d+)", request.user)
            if has_hints:
                agrees = _unit(key, path, cwe, "agree") < AGREE_WITH_CODEQL
                vulnerable = bool(flagged) == agrees
            else:
                vulnerable = _unit(key, path, cwe, "guess") < 0.5
            if _unit(key, path, cwe, request.run, "flip") < FLIP_BETWEEN_RUNS:
                vulnerable = not vulnerable
            verdicts.append(
                {
                    "cwe": cwe,
                    "vulnerable": vulnerable,
                    "line": int(flagged.group(1)) if vulnerable and flagged else None,
                    "confidence": ("high", "medium", "low")[int(_unit(key, path, cwe, "confidence") * 3)],
                    "reason": f"Mock verdict for {cwe}.",
                    "recommendation": "Mock recommendation." if vulnerable else None,
                }
            )
        return Completion(
            text=json.dumps({"verdicts": verdicts}),
            input_tokens=input_tokens,
            output_tokens=60 * len(cwe_ids),
            reasoning_tokens=0,
            request_params={"reasoning": self.model.reasoning},
        )
