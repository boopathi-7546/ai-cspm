import os
import pytest
from conftest import SAMPLE_REPORTS
from cspm.cti_extractor import extract_report, parse_report
from cspm.llm import complete, get_client, get_provider


def rep(name="R1_cloud_credential_theft"):
    return parse_report(SAMPLE_REPORTS / f"{name}.txt")


class FakeGeminiResponse:
    def __init__(self, text: str):
        self.text = text


class FakeGeminiClient:
    def __init__(self, response_text: str = '{"techniques": [{"id": "T1530", "evidence": "stolen keys to read a bucket."}]}'):
        self.response_text = response_text
        self.captured_calls = []

        class _Models:
            def __init__(self, parent):
                self.parent = parent

            def generate_content(self, *, model, contents, config=None):
                self.parent.captured_calls.append({"model": model, "contents": contents, "config": config})
                return FakeGeminiResponse(self.parent.response_text)

        self.models = _Models(self)


class Fake429Error(Exception):
    def __init__(self, message="RESOURCE_EXHAUSTED"):
        self.code = 429
        super().__init__(f"429 {message}")


class RetryGeminiClient:
    def __init__(self, fail_count: int = 1):
        self.fail_count = fail_count
        self.attempts = 0

        class _Models:
            def __init__(self, parent):
                self.parent = parent

            def generate_content(self, *, model, contents, config=None):
                self.parent.attempts += 1
                if self.parent.attempts <= self.parent.fail_count:
                    raise Fake429Error()
                return FakeGeminiResponse('{"techniques": [{"id": "T1190", "evidence": "Exploited app (T1190)."}]}')

        self.models = _Models(self)


def test_gemini_get_provider(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "gemini")
    assert get_provider() == "gemini"
    monkeypatch.delenv("LLM_PROVIDER", raising=False)
    assert get_provider() == "anthropic"


def test_gemini_get_client_none_without_key(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "gemini")
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    assert get_client() is None


def test_gemini_get_client_with_fake_key(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "gemini")
    monkeypatch.setenv("GEMINI_API_KEY", "test-dummy-gemini-key")
    client = get_client()
    assert client is not None
    assert hasattr(client, "models")


def test_gemini_complete_success(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "gemini")
    monkeypatch.setenv("CTI_LLM_MODEL", "gemini-2.0-flash")
    client = FakeGeminiClient("hello world")
    res = complete(client, system="sys instruction", user="user prompt", max_tokens=100)
    assert res == "hello world"
    assert len(client.captured_calls) == 1
    assert client.captured_calls[0]["model"] == "gemini-2.0-flash"
    assert client.captured_calls[0]["contents"] == "user prompt"


def test_gemini_missing_model_raises_clearly(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "gemini")
    monkeypatch.delenv("CTI_LLM_MODEL", raising=False)
    client = FakeGeminiClient("hello")
    with pytest.raises(ValueError, match="CTI_LLM_MODEL must be set for Gemini"):
        complete(client, system="sys", user="user")


def test_gemini_retry_on_429_success(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "gemini")
    monkeypatch.setenv("CTI_LLM_MODEL", "gemini-2.0-flash")
    monkeypatch.setenv("CSPM_RETRY_BACKOFF", "0.001")
    client = RetryGeminiClient(fail_count=1)
    res = complete(client, system="sys", user="user")
    assert "T1190" in res
    assert client.attempts == 2


def test_gemini_429_exhausted_falls_back_to_offline(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "gemini")
    monkeypatch.setenv("CTI_LLM_MODEL", "gemini-2.0-flash")
    monkeypatch.setenv("CSPM_RETRY_BACKOFF", "0.001")
    client = RetryGeminiClient(fail_count=5)
    res = extract_report(rep("R3_exposed_services"), client=client)
    assert res["method"].startswith("offline (llm fallback)")
    assert any("429" in r or "Fake429Error" in r for r in res["rejected"])


def test_anthropic_path_still_works_with_fake(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "anthropic")
    monkeypatch.setenv("CTI_LLM_MODEL", "claude-sonnet-5-5")

    class FakeAnthropicMessage:
        class Content:
            type = "text"
            text = "anthropic response"
        content = [Content()]

    class FakeAnthropicClient:
        class messages:
            @staticmethod
            def create(model, max_tokens, system, messages):
                return FakeAnthropicMessage()

    res = complete(FakeAnthropicClient(), system="sys", user="user")
    assert res == "anthropic response"


def test_rate_limit_helper():
    from cspm.llm import _is_rate_limit
    assert _is_rate_limit(Fake429Error())
    assert _is_rate_limit(RuntimeError("error 429 quota"))
    assert _is_rate_limit(RuntimeError("Resource_Exhausted error"))
    assert not _is_rate_limit(RuntimeError("connection refused"))


def test_llm_check_gemini_missing_model(monkeypatch, capsys):
    monkeypatch.setenv("LLM_PROVIDER", "gemini")
    monkeypatch.delenv("CTI_LLM_MODEL", raising=False)
    monkeypatch.setattr("sys.argv", ["run.py", "llm-check"])
    import run
    ret = run.main()
    out = capsys.readouterr().out
    assert ret == 1
    assert "Provider: gemini" in out
    assert "CTI_LLM_MODEL must be set" in out


def test_llm_check_gemini_missing_key(monkeypatch, capsys):
    monkeypatch.setenv("LLM_PROVIDER", "gemini")
    monkeypatch.setenv("CTI_LLM_MODEL", "gemini-2.0-flash")
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.setattr("sys.argv", ["run.py", "llm-check"])
    import run
    ret = run.main()
    out = capsys.readouterr().out
    assert ret == 1
    assert "Provider: gemini | Model: gemini-2.0-flash" in out
    assert "set GEMINI_API_KEY" in out
    assert "google-genai" in out


def test_llm_check_anthropic_default(monkeypatch, capsys):
    monkeypatch.setenv("LLM_PROVIDER", "anthropic")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setattr("sys.argv", ["run.py", "llm-check"])
    import run
    ret = run.main()
    out = capsys.readouterr().out
    assert ret == 1
    assert "Provider: anthropic | Model: claude-sonnet-5-5" in out
    assert "set ANTHROPIC_API_KEY" in out
    assert "anthropic" in out


def test_gemini_token_floors_and_flash_thinking_budget(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "gemini")
    monkeypatch.setenv("CTI_LLM_MODEL", "gemini-2.0-flash")

    client = FakeGeminiClient("OK")
    # Small check floor (at least 256)
    complete(client, system="sys", user="ping", max_tokens=10)
    cfg1 = client.captured_calls[-1]["config"]
    assert cfg1.max_output_tokens == 256
    assert cfg1.thinking_config.thinking_budget == 0

    # Extraction floor (at least 4096)
    complete(client, system="sys", user="ping", max_tokens=1500)
    cfg2 = client.captured_calls[-1]["config"]
    assert cfg2.max_output_tokens == 4096
    assert cfg2.thinking_config.thinking_budget == 0


def test_gemini_non_flash_model_no_thinking_budget_override(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "gemini")
    monkeypatch.setenv("CTI_LLM_MODEL", "gemini-1.5-pro")

    client = FakeGeminiClient("OK")
    complete(client, system="sys", user="ping", max_tokens=10)
    cfg = client.captured_calls[-1]["config"]
    assert cfg.max_output_tokens == 256
    assert cfg.thinking_config is None



