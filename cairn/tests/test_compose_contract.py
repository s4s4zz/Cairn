import json
from pathlib import Path

import yaml


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def load_compose() -> dict[str, object]:
    return yaml.safe_load((REPOSITORY_ROOT / "docker-compose.yaml").read_text())


def test_compose_contains_control_plane_and_sandbox_manager() -> None:
    compose = load_compose()
    services = compose["services"]

    assert set(services) == {
        "cairn-orchestrator",
        "cairn-postgres",
        "cairn-server",
        "cairn-sandbox-manager",
    }
    assert services["cairn-postgres"]["image"] == "postgres:16-alpine"
    assert "cairn-postgres-data" in compose["volumes"]
    assert "cairn-artifact-data" in compose["volumes"]
    assert "cairn-ingestion-data" in compose["volumes"]
    assert "cairn-sandbox-state" in compose["volumes"]


def test_server_is_localhost_only_and_has_no_host_control_mounts() -> None:
    server = load_compose()["services"]["cairn-server"]

    assert server["ports"] == ["127.0.0.1:8000:8000"]
    assert not server.get("privileged", False)
    assert server.get("network_mode") != "host"
    mounts = "\n".join(str(item) for item in server.get("volumes", []))
    assert "docker.sock" not in mounts


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
    assert server["environment"]["CAIRN_ARTIFACT_ROOT"] == "/var/lib/cairn/artifacts"
    assert (
        server["environment"]["CAIRN_INGESTION_WORK_ROOT"]
        == "/var/lib/cairn/ingestion"
    )
    assert server["volumes"] == [
        "cairn-artifact-data:/var/lib/cairn/artifacts",
        "cairn-ingestion-data:/var/lib/cairn/ingestion",
    ]


def test_no_service_is_privileged_or_uses_host_networking() -> None:
    for service in load_compose()["services"].values():
        assert not service.get("privileged", False)
        assert service.get("network_mode") != "host"


def test_sandbox_manager_is_internal_and_is_the_only_daemon_client() -> None:
    compose = load_compose()
    manager = compose["services"]["cairn-sandbox-manager"]
    server = compose["services"]["cairn-server"]
    orchestrator = compose["services"]["cairn-orchestrator"]

    assert "ports" not in manager
    assert manager["build"]["dockerfile"] == "Dockerfile.sandbox-manager"
    assert manager["image"] == "cairn-sandbox-manager:local"
    assert manager["networks"] == ["cairn-sandbox-api"]
    assert compose["networks"]["cairn-sandbox-api"]["internal"] is True
    assert "cairn-sandbox-api" not in server["networks"]
    assert "cairn-sandbox-api" in orchestrator["networks"]
    mounts = manager["volumes"]
    rendered = "\n".join(str(item) for item in mounts)
    assert "/run/cairn-rootless-docker.sock" in rendered
    assert "/var/run/docker.sock" not in rendered
    assert "/var/lib/cairn/sandbox-work" in rendered
    assert "/run/secrets/cairn_sandbox_token" in rendered
    assert manager["environment"]["CAIRN_SANDBOX_REQUIRE_ROOTLESS"] == "true"
    assert "CAIRN_DATABASE_URL" not in manager["environment"]
    assert manager["environment"]["CAIRN_SANDBOX_DOCKER_HOST"].startswith(
        "unix:///run/cairn-rootless"
    )
    assert (
        manager["environment"]["CAIRN_SANDBOX_HELPER_IMAGE"]
        == "${CAIRN_SANDBOX_HELPER_IMAGE:-cairn-sandbox-helper:local}"
    )
    orchestrator_mounts = "\n".join(
        str(item) for item in orchestrator.get("volumes", [])
    )
    assert "docker.sock" not in orchestrator_mounts
    assert orchestrator["environment"]["CAIRN_SANDBOX_API_URL"] == (
        "http://cairn-sandbox-manager:8001"
    )


def test_orchestrator_is_hardened_and_owns_sandbox_credentials() -> None:
    orchestrator = load_compose()["services"]["cairn-orchestrator"]

    assert "ports" not in orchestrator
    assert orchestrator["command"] == ["uv", "run", "cairn", "orchestrate"]
    assert orchestrator["read_only"] is True
    assert orchestrator["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in orchestrator["security_opt"]
    assert orchestrator["networks"] == ["cairn-control", "cairn-sandbox-api"]
    assert (
        orchestrator["environment"]["CAIRN_SANDBOX_AUTH_TOKEN_FILE"]
        == "/run/secrets/cairn_sandbox_token"
    )
    server = load_compose()["services"]["cairn-server"]
    assert "CAIRN_SANDBOX_AUTH_TOKEN_FILE" not in server["environment"]


def test_sandbox_manager_has_hardened_service_container() -> None:
    manager = load_compose()["services"]["cairn-sandbox-manager"]
    command = " ".join(manager["command"])

    assert "sandbox-serve" in command
    assert manager["read_only"] is True
    assert manager["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in manager["security_opt"]
    assert "/health/ready" in " ".join(manager["healthcheck"]["test"])


def test_application_image_uses_supported_python_and_non_root_user() -> None:
    dockerfile = (REPOSITORY_ROOT / "Dockerfile").read_text()

    assert "python3.12" in dockerfile
    assert "USER cairn" in dockerfile
    assert "--no-dev" in dockerfile
    assert "git" in dockerfile
    assert "openssh-client" in dockerfile
    assert "/var/lib/cairn/sandbox-state" in dockerfile


def test_sandbox_template_image_is_non_root_and_has_fixed_toolchain() -> None:
    dockerfile = (REPOSITORY_ROOT / "sandbox-images" / "Dockerfile").read_text()
    runner = (REPOSITORY_ROOT / "sandbox-images" / "runner.py").read_text()
    helper = (
        REPOSITORY_ROOT / "sandbox-images" / "normalize_permissions.py"
    ).read_text()

    assert "USER 65532:65532" in dockerfile
    assert "run-analysis" in dockerfile
    assert "run-build" in dockerfile
    assert "run-validation" in dockerfile
    assert "normalize-workspace-permissions" in dockerfile
    assert "openjdk-17-jdk-headless" in dockerfile
    assert "MAVEN_VERSION=3.9.11" in dockerfile
    assert "GRADLE_VERSION=8.14.3" in dockerfile
    assert "SEMGREP_VERSION=1.130.0" in dockerfile
    assert "sha512sum --check --strict" in dockerfile
    assert "sha256sum --check --strict" in dockerfile
    assert "rules/semgrep" in dockerfile
    assert "toolchain.json" in dockerfile
    assert "subprocess" not in runner
    assert "os.system" not in runner
    assert "subprocess" not in helper
    assert "followlinks=False" in helper

    toolchain = json.loads(
        (REPOSITORY_ROOT / "sandbox-images" / "toolchain.json").read_text()
    )
    assert toolchain["contract"] == "cairn-sandbox-toolchain-v1"
    assert toolchain["runtime_downloads_allowed"] is False
    assert toolchain["bundled"]["jdk"]["major_version"] == "17"
    assert toolchain["bundled"]["semgrep"]["version"] == "1.130.0"
    assert toolchain["bundled"]["semgrep"]["setuptools_version"] == "80.9.0"
    assert set(toolchain["administrator_provisioned"]) == {
        "codeql",
        "dependency-check",
        "findsecbugs",
        "gitleaks",
        "trivy",
    }

    semgrep_rules = yaml.safe_load(
        (
            REPOSITORY_ROOT
            / "sandbox-images"
            / "rules"
            / "semgrep"
            / "java-security.yml"
        ).read_text()
    )["rules"]
    assert len(semgrep_rules) >= 5
    assert all(rule["languages"] == ["java"] for rule in semgrep_rules)


def test_sandbox_manager_image_is_separate_and_has_no_git_clients() -> None:
    dockerfile = (
        REPOSITORY_ROOT / "Dockerfile.sandbox-manager"
    ).read_text()

    assert "USER cairn" in dockerfile
    assert "sandbox-serve" in dockerfile
    assert "EXPOSE 8001" in dockerfile
    assert "openssh-client" not in dockerfile
    assert "apt-get" not in dockerfile
