from typing import Annotated

from fastapi import Depends, Request

from cairn.server.artifacts.base import ArtifactStore


def get_artifact_store(request: Request) -> ArtifactStore:
    return request.app.state.artifact_store


ArtifactStoreDependency = Annotated[ArtifactStore, Depends(get_artifact_store)]
