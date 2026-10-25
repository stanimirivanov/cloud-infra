"""Find repository configuration independently of editable-install locations."""

import tomllib
from pathlib import Path


def find_repository(start: Path | None = None) -> Path:
    current = (start or Path.cwd()).resolve()
    for candidate in (current, *current.parents):
        manifest = candidate / "pyproject.toml"
        if manifest.is_file():
            with manifest.open("rb") as stream:
                config = tomllib.load(stream)
            if config.get("project", {}).get("name") == "oci-oke-infrastructure":
                return candidate
    raise RuntimeError("Run inside the infrastructure checkout or pass infra --root PATH")
