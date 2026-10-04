import httpx
from google import genai
from google.genai import errors, types

from trisula.config import LLMConfig, ModelConfig
from trisula.llm.base import Completion, CompletionRequest, FatalAPIError, LLMAdapter, TransientAPIError


class GeminiAdapter(LLMAdapter):
    def __init__(self, model_key: str, model: ModelConfig, llm: LLMConfig):
        super().__init__(model_key, model, llm)
        # attempts=1 mematikan retry bawaan SDK; retry ditangani Reviewer supaya setiap percobaan tercatat.
        self._client = genai.Client(
            api_key=self.api_key,
            http_options=types.HttpOptions(
                timeout=int(self.llm.request_timeout_seconds * 1000),
                retry_options=types.HttpRetryOptions(attempts=1),
            ),
        )

    def complete(self, request: CompletionRequest) -> Completion:
        config = types.GenerateContentConfig(
            system_instruction=request.system,
            response_mime_type="application/json",
            response_json_schema=request.schema,
            thinking_config=types.ThinkingConfig(thinking_level=self.model.reasoning),
            max_output_tokens=self.llm.max_output_tokens,
        )
        try:
            response = self._client.models.generate_content(
                model=self.model.model_id, contents=request.user, config=config
            )
        except httpx.TransportError as exc:
            raise TransientAPIError(f"{type(exc).__name__}: {exc}") from exc
        except errors.APIError as exc:
            if exc.code == 429 or exc.code >= 500:
                raise TransientAPIError(f"HTTP {exc.code}: {exc.message}") from exc
            raise FatalAPIError(f"{self.model_key}: HTTP {exc.code}: {exc.message}") from exc

        usage = response.usage_metadata
        candidate = response.candidates[0] if response.candidates else None
        thoughts = (usage.thoughts_token_count or 0) if usage else None
        return Completion(
            text=response.text or "",
            input_tokens=usage.prompt_token_count if usage else None,
            # Token berpikir dilaporkan terpisah dari candidates_token_count dan ditagih dengan tarif output.
            output_tokens=(usage.candidates_token_count or 0) + thoughts if usage else None,
            reasoning_tokens=thoughts,
            cached_tokens=usage.cached_content_token_count if usage else None,
            truncated=candidate is not None and candidate.finish_reason == types.FinishReason.MAX_TOKENS,
            request_params={
                "thinking_level": config.thinking_config.thinking_level.value,
                "max_output_tokens": self.llm.max_output_tokens,
            },
        )
