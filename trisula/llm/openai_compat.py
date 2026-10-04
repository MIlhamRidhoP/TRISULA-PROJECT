import openai

from trisula.config import LLMConfig, ModelConfig
from trisula.llm.base import Completion, CompletionRequest, FatalAPIError, LLMAdapter, TransientAPIError

SCHEMA_NAME = "trisula_verdicts"


class OpenAICompatAdapter(LLMAdapter):
    """GPT dan Grok lewat Responses API. Grok cukup memakai base_url xAI (PROVIDERS.md)."""

    def __init__(self, model_key: str, model: ModelConfig, llm: LLMConfig):
        super().__init__(model_key, model, llm)
        # Retry ditangani Reviewer supaya setiap percobaan tercatat di log.
        self._client = openai.OpenAI(
            api_key=self.api_key,
            base_url=self.model.base_url,
            timeout=self.llm.request_timeout_seconds,
            max_retries=0,
        )

    def complete(self, request: CompletionRequest) -> Completion:
        params = {
            "reasoning": {"effort": self.model.reasoning},
            "max_output_tokens": self.llm.max_output_tokens,
        }
        text_format = {"type": "json_schema", "name": SCHEMA_NAME, "schema": request.schema, "strict": True}
        try:
            response = self._client.responses.create(
                model=self.model.model_id,
                instructions=request.system,
                input=request.user,
                text={"format": text_format},
                **params,
            )
        except openai.APIConnectionError as exc:
            raise TransientAPIError(f"{type(exc).__name__}: {exc}") from exc
        except openai.APIStatusError as exc:
            if exc.status_code == 429 or exc.status_code >= 500:
                raise TransientAPIError(f"HTTP {exc.status_code}: {exc.message}") from exc
            raise FatalAPIError(f"{self.model_key}: HTTP {exc.status_code}: {exc.message}") from exc

        usage = response.usage
        truncated = (
            response.status == "incomplete"
            and response.incomplete_details is not None
            and response.incomplete_details.reason == "max_output_tokens"
        )
        return Completion(
            text=response.output_text,
            input_tokens=usage.input_tokens if usage else None,
            # Di Responses API output_tokens sudah mencakup reasoning_tokens.
            output_tokens=usage.output_tokens if usage else None,
            reasoning_tokens=usage.output_tokens_details.reasoning_tokens if usage else None,
            cached_tokens=usage.input_tokens_details.cached_tokens if usage else None,
            truncated=truncated,
            request_params=params,
        )
