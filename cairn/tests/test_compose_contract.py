from pathlib import Path

import yaml


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def load_compose() -> dict[str, object]:
    return yaml.safe_load((REPOSITORY_ROOT / "docker-compose.yaml").read_text())


def test_compose_contains_only_postgres_and_audit_server() -> None:
    compose = load_compose()
    services = compose["services"]

    assert set(services) == {"cairn-postgres", "cairn-server"}
    assert services["cairn-postgres"]["image"] == "postgres:16-alpine"
    assert "cairn-postgres-data" in compose["volumes"]


def test_server_is_localhost_only_and_has_no_host_control_mounts() -> None:
    server = load_compose()["services"]["cairn-server"]

    assert server["ports"] == ["127.0.0.1:8000:8000"]
    assert not server.get("privileged", False)
    assert server.get("network_mode") != "host"
    mounts = "\n".join(str(item) for item in server.get("volumes", []))
    assert "/var/run/docker.sock" not in mounts


def test_postgres_is_persistent_and_server_waits_for_readiness() -> None:
    compose = load_compose()
    postgres = compose["services"]["cairn-postgres"]
    server = compose["services"]["cairn-server"]

    assert postgres["volumes"] == [
        "cairn-postgres-data:/var/lib/postgresql/data"
    ]
    assert "pg_isready" in " ".join(postgres["healthcheck"]["test"])
    assert server["depends_on"] == {
        "cairn-postgres": {"condition": "service_healthy"}
    }
    assert "/health/ready" in " ".join(server["healthcheck"]["test"])


def test_server_migrates_before_starting_and_uses_database_url() -> None:
    server = load_compose()["services"]["cairn-server"]
    command = " ".join(server["command"])

    assert "alembic -c alembic.ini upgrade head" in command
    assert "cairn serve --host 0.0.0.0" in command
    assert "CAIRN_DATABASE_URL" in server["environment"]
    assert "postgresql+psycopg://" in server["environment"]["CAIRN_DATABASE_URL"]


def test_no_service_is_privileged_or_uses_host_networking() -> None:
    for service in load_compose()["services"].values():
        assert not service.get("privileged", False)
        assert service.get("network_mode") != "host"


def test_application_image_uses_supported_python_and_non_root_user() -> None:
    dockerfile = (REPOSITORY_ROOT / "Dockerfile").read_text()

    assert "python3.12" in dockerfile
    assert "USER cairn" in dockerfile
    assert "--no-dev" in dockerfile
