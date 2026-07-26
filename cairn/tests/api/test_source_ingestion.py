from io import BytesIO
import tarfile
from uuid import UUID
import zipfile

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker

from cairn.server.domain.enums import GitCredentialKind
from cairn.server.ingestion.git import GitFetcher
from cairn.server.persistence.models import EncryptedSecret
from cairn.server.secret_store import DatabaseSecretStore


def _archive(
    *,
    java_source: bytes = b"public class Demo {}\n",
    timestamp: tuple[int, int, int, int, int, int] = (2020, 1, 1, 0, 0, 0),
) -> bytes:
    output = BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        java = zipfile.ZipInfo("src/main/java/Demo.java", timestamp)
        pom = zipfile.ZipInfo("pom.xml", timestamp)
        archive.writestr(java, java_source)
        archive.writestr(pom, b"<project />\n")
    return output.getvalue()


def _repository(
    client: TestClient,
    *,
    name: str,
    source_type: str,
    remote_url: str | None = None,
    credential_ref: str | None = None,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "name": name,
        "source_type": source_type,
    }
    if remote_url is not None:
        payload["remote_url"] = remote_url
    if credential_ref is not None:
        payload["credential_ref"] = credential_ref
    response = client.post("/api/v1/repositories", json=payload)
    assert response.status_code == 201, response.text
    return response.json()


def _upload(
    client: TestClient,
    content: bytes,
    *,
    source_type: str = "zip",
) -> dict[str, object]:
    response = client.post(
        "/api/v1/uploads",
        params={"source_type": source_type},
        headers={
            "Content-Type": "application/zip",
            "X-Filename": "demo.zip",
        },
        content=content,
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_zip_upload_creates_read_only_snapshot_and_downloadable_artifact(
    client: TestClient,
) -> None:
    repository = _repository(client, name="zip-demo", source_type="zip")
    upload = _upload(client, _archive())

    response = client.post(
        f"/api/v1/repositories/{repository['id']}/snapshots",
        json={"type": "upload", "upload_id": upload["id"]},
    )

    assert response.status_code == 201, response.text
    snapshot = response.json()
    assert snapshot["status"] == "ready"
    assert snapshot["java_file_count"] == 1
    assert snapshot["file_count"] == 2
    assert snapshot["build_system"] == "maven"
    assert len(snapshot["content_sha256"]) == 64
    assert client.get(f"/api/v1/snapshots/{snapshot['id']}").json() == snapshot

    artifact = client.get(f"/api/v1/artifacts/{snapshot['artifact_id']}")
    assert artifact.status_code == 200
    assert artifact.headers["x-content-sha256"]
    with tarfile.open(fileobj=BytesIO(artifact.content)) as archive:
        assert archive.getnames() == ["pom.xml", "src/main/java/Demo.java"]
        assert all(member.mode in {0o444, 0o555} for member in archive.getmembers())


def test_same_source_with_different_zip_metadata_has_same_content_identity(
    client: TestClient,
) -> None:
    repository = _repository(client, name="dedupe", source_type="zip")
    first_upload = _upload(client, _archive())
    second_upload = _upload(
        client,
        _archive(timestamp=(2026, 7, 26, 1, 2, 4)),
    )

    first = client.post(
        f"/api/v1/repositories/{repository['id']}/snapshots",
        json={"type": "upload", "upload_id": first_upload["id"]},
    )
    second = client.post(
        f"/api/v1/repositories/{repository['id']}/snapshots",
        json={"type": "upload", "upload_id": second_upload["id"]},
    )

    assert first.status_code == second.status_code == 201
    assert first.json()["id"] != second.json()["id"]
    assert first.json()["artifact_id"] != second.json()["artifact_id"]
    assert first.json()["content_sha256"] == second.json()["content_sha256"]
    first_artifact = client.get(
        f"/api/v1/artifacts/{first.json()['artifact_id']}"
    )
    second_artifact = client.get(
        f"/api/v1/artifacts/{second.json()['artifact_id']}"
    )
    assert first_artifact.headers["x-content-sha256"] == (
        second_artifact.headers["x-content-sha256"]
    )


def test_repository_with_snapshot_cannot_be_deleted(
    client: TestClient,
) -> None:
    repository = _repository(client, name="retained-source", source_type="zip")
    upload = _upload(client, _archive())
    snapshot = client.post(
        f"/api/v1/repositories/{repository['id']}/snapshots",
        json={"type": "upload", "upload_id": upload["id"]},
    )
    assert snapshot.status_code == 201

    response = client.delete(f"/api/v1/repositories/{repository['id']}")

    assert response.status_code == 409
    assert response.json()["error_code"] == "repository_has_snapshots"


def test_zip_slip_and_no_java_archives_return_stable_errors(
    client: TestClient,
) -> None:
    repository = _repository(client, name="unsafe", source_type="zip")
    archive = BytesIO()
    with zipfile.ZipFile(archive, "w") as output:
        output.writestr("../Escape.java", b"class Escape {}")
    upload = _upload(client, archive.getvalue())

    response = client.post(
        f"/api/v1/repositories/{repository['id']}/snapshots",
        json={"type": "upload", "upload_id": upload["id"]},
    )
    assert response.status_code == 422
    assert response.json()["error_code"] == "SNAPSHOT_ARCHIVE_PATH_ESCAPE"

    no_java = BytesIO()
    with zipfile.ZipFile(no_java, "w") as output:
        output.writestr("README.md", b"hello")
    upload = _upload(client, no_java.getvalue())
    response = client.post(
        f"/api/v1/repositories/{repository['id']}/snapshots",
        json={"type": "upload", "upload_id": upload["id"]},
    )
    assert response.status_code == 422
    assert response.json()["error_code"] == "NO_JAVA_SOURCE"


def test_local_directory_transport_uses_the_same_snapshot_pipeline(
    client: TestClient,
) -> None:
    repository = _repository(
        client,
        name="directory-demo",
        source_type="local_upload",
    )
    upload = _upload(client, _archive(), source_type="local_upload")

    response = client.post(
        f"/api/v1/repositories/{repository['id']}/snapshots",
        json={"type": "upload", "upload_id": upload["id"]},
    )

    assert response.status_code == 201
    assert response.json()["status"] == "ready"


def test_audit_run_accepts_only_a_completed_matching_upload(
    client: TestClient,
) -> None:
    repository = _repository(client, name="run-upload", source_type="zip")
    upload = _upload(client, _archive())
    policy_response = client.post(
        "/api/v1/audit-policies",
        json={"name": "upload-policy"},
    )
    assert policy_response.status_code == 201
    policy = policy_response.json()

    response = client.post(
        "/api/v1/audit-runs",
        json={
            "repository_id": repository["id"],
            "policy_id": policy["id"],
            "source_request": {
                "type": "upload",
                "upload_id": upload["id"],
            },
        },
    )

    assert response.status_code == 201
    assert response.json()["source_request"]["upload_id"] == upload["id"]


def test_git_snapshot_records_commit_and_never_archives_credentials(
    client: TestClient,
    monkeypatch,
) -> None:
    credential_response = client.post(
        "/api/v1/git-credentials",
        json={
            "type": "https_token",
            "username": "audit-bot",
            "token": "never-archive-this-token",
        },
    )
    assert credential_response.status_code == 201
    credential = credential_response.json()
    repository = _repository(
        client,
        name="private-git",
        source_type="git",
        remote_url="https://example.invalid/team/private.git",
        credential_ref=credential["reference"],
    )
    captured: dict[str, object] = {}

    def fake_fetch(
        self,
        remote_url,
        ref,
        destination,
        supplied_credential,
    ):
        del self
        captured.update(
            remote_url=remote_url,
            ref=ref,
            credential=supplied_credential,
        )
        destination.mkdir(parents=True)
        (destination / "Demo.java").write_text("class Demo {}")
        return "a" * 40

    monkeypatch.setattr(GitFetcher, "fetch_into", fake_fetch)
    response = client.post(
        f"/api/v1/repositories/{repository['id']}/snapshots",
        json={"type": "git_ref", "ref": "main"},
    )

    assert response.status_code == 201, response.text
    snapshot = response.json()
    assert snapshot["commit_sha"] == "a" * 40
    assert snapshot["branch_or_tag"] == "main"
    assert captured["credential"] == (
        GitCredentialKind.HTTPS_TOKEN,
        {"token": "never-archive-this-token", "username": "audit-bot"},
    )
    artifact = client.get(f"/api/v1/artifacts/{snapshot['artifact_id']}")
    assert b"never-archive-this-token" not in artifact.content


def test_git_credential_is_encrypted_and_has_no_public_read_route(
    client: TestClient,
    session_factory: sessionmaker[Session],
) -> None:
    response = client.post(
        "/api/v1/git-credentials",
        json={"type": "https_token", "token": "ABC-super-secret"},
    )
    assert response.status_code == 201
    body = response.json()
    assert set(body) == {"id", "reference", "kind", "created_at"}

    with session_factory() as session:
        stored = session.get(EncryptedSecret, UUID(body["id"]))
        assert b"ABC-super-secret" not in stored.ciphertext
        kind, payload = DatabaseSecretStore(session, b"k" * 32).read(
            body["reference"]
        )
        assert kind is GitCredentialKind.HTTPS_TOKEN
        assert payload["token"] == "ABC-super-secret"

    assert client.get(f"/api/v1/git-credentials/{body['reference']}").status_code == 405
