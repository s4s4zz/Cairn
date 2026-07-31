import base64
import json
import stat

import pytest

from cairn.model_provider import (
    ModelProvider,
    ModelProviderConfigError,
    ModelProviderConfigStore,
    load_model_config_key,
    normalize_provider_base_url,
    provider_endpoint,
)


API_KEY = "sk-test-provider-secret-7b9c"


def test_provider_configuration_is_encrypted_and_atomically_private(tmp_path) -> None:
    path = tmp_path / "llm" / "provider.json"
    store = ModelProviderConfigStore(path, b"k" * 32)

    metadata = store.write(
        provider=ModelProvider.OPENAI,
        base_url="https://api.openai.com/",
        model="gpt-5",
        api_key=API_KEY,
    )

    raw = path.read_text(encoding="utf-8")
    assert API_KEY not in raw
    assert json.loads(raw)["metadata"]["model"] == "gpt-5"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    assert ModelProviderConfigStore(path).read_metadata() == metadata
    configuration = store.read()
    assert configuration.metadata.base_url == "https://api.openai.com"
    assert configuration.api_key.get_secret_value() == API_KEY


def test_wrong_key_and_authenticated_metadata_tampering_fail_closed(tmp_path) -> None:
    path = tmp_path / "provider.json"
    ModelProviderConfigStore(path, b"a" * 32).write(
        provider=ModelProvider.ANTHROPIC,
        base_url="https://api.anthropic.com",
        model="claude-opus-4-1",
        api_key=API_KEY,
    )

    with pytest.raises(ModelProviderConfigError):
        ModelProviderConfigStore(path, b"b" * 32).read()

    envelope = json.loads(path.read_text(encoding="utf-8"))
    envelope["metadata"]["model"] = "claude-tampered"
    path.write_text(json.dumps(envelope), encoding="utf-8")
    with pytest.raises(ModelProviderConfigError):
        ModelProviderConfigStore(path, b"a" * 32).read()


def test_master_key_loader_accepts_raw_or_base64_and_rejects_short_keys(tmp_path) -> None:
    raw_path = tmp_path / "raw.key"
    raw_path.write_bytes(b"r" * 32)
    encoded_path = tmp_path / "encoded.key"
    encoded_path.write_bytes(base64.b64encode(b"e" * 32) + b"\n")
    short_path = tmp_path / "short.key"
    short_path.write_bytes(b"short")

    assert load_model_config_key(raw_path) == b"r" * 32
    assert load_model_config_key(encoded_path) == b"e" * 32
    with pytest.raises(ModelProviderConfigError):
        load_model_config_key(short_path)


def test_provider_urls_support_service_origins_and_existing_v1_prefixes() -> None:
    assert normalize_provider_base_url(" https://example.invalid/v1/ ") == (
        "https://example.invalid/v1"
    )
    assert provider_endpoint("https://example.invalid", "/v1/models") == (
        "https://example.invalid/v1/models"
    )
    assert provider_endpoint("https://example.invalid/v1", "/v1/models") == (
        "https://example.invalid/v1/models"
    )
    # A self-hosted gateway on a LAN address rarely carries a certificate, so
    # plaintext is accepted and the operator owns the transport decision.
    assert normalize_provider_base_url("http://192.168.1.9:3000/") == (
        "http://192.168.1.9:3000"
    )


@pytest.mark.parametrize(
    "url",
    [
        "https://user:secret@example.invalid",
        "https://example.invalid/path?query=yes",
        "file:///tmp/provider",
    ],
)
def test_provider_urls_reject_credential_leaks_and_unsafe_transports(url: str) -> None:
    with pytest.raises(ValueError):
        normalize_provider_base_url(url)
