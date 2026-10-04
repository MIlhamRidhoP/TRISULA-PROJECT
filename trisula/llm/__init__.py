from trisula.config import Config
from trisula.llm.base import LLMAdapter


def create_adapter(config: Config, model_key: str) -> LLMAdapter:
    model = config.llm.models[model_key]
    # Impor ditunda supaya demo dengan mock tidak perlu memuat SDK provider.
    match model.provider:
        case "google":
            from trisula.llm.gemini import GeminiAdapter

            return GeminiAdapter(model_key, model, config.llm)
        case "openai":
            from trisula.llm.openai_compat import OpenAICompatAdapter

            return OpenAICompatAdapter(model_key, model, config.llm)
        case "mock":
            from trisula.llm.mock import MockAdapter

            return MockAdapter(model_key, model, config.llm)
