"""Runtime settings: PERISKOPE_* variables and the instance registry the chart renders into a ConfigMap."""
from __future__ import annotations

import json
import os
from pathlib import Path

from pydantic import BaseModel, Field


class Instance(BaseModel):
    slug: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,40}$")
    name: str
    url: str
    rate_per_min: int = 600
    sonar_url: str | None = None
    # CE instances lack Ultimate fields; the checks that need them say unknown.
    enterprise: bool = True
    tracked_namespaces: list[str] = []
    excluded_namespaces: list[str] = []
    # Private CA bundle to trust, or None for the system store.
    ca_file: str | None = None


def env(name: str, default: str | None = None) -> str:
    value = os.environ.get(f"PERISKOPE_{name}", default)
    if value is None:
        raise RuntimeError(f"PERISKOPE_{name} is required")
    return value


def instances() -> dict[str, Instance]:
    path = Path(env("INSTANCES_FILE", "/etc/periskope/instances.json"))
    return {i.slug: i for i in (Instance(**x) for x in json.loads(path.read_text()))}


def secret(name: str) -> Path:
    """A mounted secret file: <SECRETS_DIR>/<secret name>/<key>, e.g. gitlab-token-gl-prod/token."""
    return Path(env("SECRETS_DIR", "/var/run/secrets/periskope")) / name


def queue(instance: str) -> str:
    """The ARQ queue of an instance's collectors."""
    return f"collect:{instance}"
