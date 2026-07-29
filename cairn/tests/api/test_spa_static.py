from pathlib import Path

from fastapi.testclient import TestClient
import pytest

from cairn.server.config import ServerSettings


def _settings(tmp_path: Path, static_root: Path) -> ServerSettings:
    return ServerSettings(
        database_url="sqlite+pysqlite:///:memory:",
        artifact_root=tmp_path / "artifacts",
        ingestion_work_root=tmp_path / "ingestion",
        static_root=static_root,
        session_cookie_secure=False,
    )


def test_workbench_static_files_and_client_routes_are_served(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CAIRN_DATABASE_URL", "sqlite+pysqlite:///:memory:")
    from cairn.server.app import create_app

    static_root = tmp_path / "static"
    assets = static_root / "assets"
    assets.mkdir(parents=True)
    (static_root / "index.html").write_text(
        "<!doctype html><title>Cairn Workbench</title>",
        encoding="utf-8",
    )
    (assets / "app.js").write_text("console.log('cairn')", encoding="utf-8")

    with TestClient(create_app(_settings(tmp_path, static_root))) as client:
        root = client.get("/")
        client_route = client.get("/audit-runs/1234")
        asset = client.get("/assets/app.js")

    assert root.status_code == 200
    assert root.headers["content-type"].startswith("text/html")
    assert root.headers["cache-control"] == "no-cache, no-store, must-revalidate"
    assert "Cairn Workbench" in root.text
    assert client_route.status_code == 200
    assert (
        client_route.headers["cache-control"]
        == "no-cache, no-store, must-revalidate"
    )
    assert "Cairn Workbench" in client_route.text
    assert asset.status_code == 200
    assert asset.headers["cache-control"] == "public, max-age=31536000, immutable"
    assert asset.text == "console.log('cairn')"


def test_spa_fallback_does_not_shadow_service_namespaces(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CAIRN_DATABASE_URL", "sqlite+pysqlite:///:memory:")
    from cairn.server.app import create_app

    static_root = tmp_path / "static"
    static_root.mkdir()
    (static_root / "index.html").write_text("workbench", encoding="utf-8")

    with TestClient(create_app(_settings(tmp_path, static_root))) as client:
        assert client.get("/api").status_code == 404
        assert client.get("/api/").status_code == 404
        assert client.get("/api/v1/not-a-route").status_code == 404
        assert client.get("/api/v2/not-a-route").status_code == 404
        assert client.get("/apiary").text == "workbench"
        assert client.get("/health/not-a-route").status_code == 404
        assert client.get("/docs/not-a-route").status_code == 404
        assert client.get("/missing.js").status_code == 404
        assert client.get("/openapi.json").status_code == 200
        assert client.get("/docs").status_code == 200
