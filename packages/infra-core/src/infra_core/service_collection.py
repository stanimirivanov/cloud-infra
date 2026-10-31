"""Explicit read-only collection and fresh private evidence publication; no authority."""

import json
import os
import re
import stat
import tempfile
import tomllib
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from infra_core.evidence import MAX_ARTIFACT_BYTES
from infra_core.governance.contracts import fields, timestamp
from infra_core.inventory.cloudflare import collect_zone
from infra_core.service_evidence import capture_cloudflare_evidence, reviewed_commit
from infra_core.services.governance import DNS, validate_resource

MESSAGE = "COLLECT001: collection failed; inspect private inputs, scope and destination"


def _require(condition: bool) -> None:
    if not condition:
        raise ValueError(MESSAGE)


def _private(root: Path, value: Path) -> Path:
    path = root / value
    _require(not any(p.is_symlink() for p in (path, *path.parents)))
    path = path.resolve()
    _require(path.is_relative_to(root / ".infra") and path != root / ".infra")
    return path


def _read(path: Path, *, credential: bool = False) -> bytes:
    limit = 4098 if credential else MAX_ARTIFACT_BYTES
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as stream:
        info = os.fstat(stream.fileno())
        _require(stat.S_ISREG(info.st_mode) and info.st_size <= limit)
        if credential:
            _require(
                info.st_uid == os.geteuid() and info.st_mode & 0o077 == 0 and info.st_nlink == 1
            )
        value = stream.read(limit + 1)
    _require(0 < len(value) <= limit)
    return value


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        _require(key not in result)
        result[key] = value
    return result


def _json(raw: bytes) -> dict[str, Any]:
    value = json.loads(raw, object_pairs_hook=_object)
    json.dumps(value, allow_nan=False)
    _require(type(value) is dict)
    assert isinstance(value, dict)
    return value


def _review(config: dict[str, Any], review: dict[str, Any], profile: dict[str, Any]) -> None:
    """Check independent scope/entitlement before reading credentials or contacting the API."""
    fields(
        config,
        {"schema_version", "provider", "unit", "account_id", "scope_id", "resources", "growth"},
        "proposal",
    )
    fields(
        review,
        {
            "schema_version",
            "account_id",
            "scope_id",
            "scope_name",
            "profile_revision",
            "verified",
            "verified_at",
            "plan",
            "other_services_reviewed",
            "source",
        },
        "review",
    )
    _require(type(config["schema_version"]) is int and config["schema_version"] == 2)
    _require(config["provider"] == "cloudflare" and config["unit"] == "cloudflare-edge")
    _require(type(review["schema_version"]) is int and review["schema_version"] == 1)
    for key in ("account_id", "scope_id"):
        _require(
            type(config[key]) is str and re.fullmatch(r"[a-f0-9]{32}", config[key]) is not None
        )
        _require(config[key] == review[key])
    _require(
        type(review["scope_name"]) is str
        and re.fullmatch(
            r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?",
            review["scope_name"],
        )
        is not None
    )
    _require(
        review["verified"] is True
        and review["other_services_reviewed"] is True
        and review["plan"] == "free"
    )
    _require(type(review["source"]) is str and bool(review["source"].strip()))
    _require(
        type(review["profile_revision"]) is int
        and review["profile_revision"] == profile["revision"]
    )
    _require(
        profile["id"] == "cloudflare-free"
        and profile["provider"] == "cloudflare"
        and profile["enabled"] is True
    )
    now = datetime.now(UTC)
    _require(now - timedelta(days=30) <= timestamp(review["verified_at"], "review") <= now)
    _require(now - timedelta(days=90) <= timestamp(profile["reviewed_at"], "profile") <= now)
    _require(
        type(config["resources"]) is list and bool(config["resources"]) and config["growth"] == {}
    )
    for resource in config["resources"]:
        fields(resource, {"key", "type", "props"}, "resource")
        _require(resource["type"] == DNS)
        validate_resource(resource["type"], resource["props"])
        props = resource["props"]
        _require(props["zoneId"] == config["scope_id"])
        _require(
            props["name"] == review["scope_name"]
            or props["name"].endswith("." + review["scope_name"])
        )


def _publish(destination: Path, payload: bytes, envelope: bytes) -> None:
    """No-clobber publication: sidecar first, payload last; failed pairs are removed.

    A crash may leave a sidecar alone. It is unusable and requires operator inspection;
    an existing file is never automatically removed on a subsequent invocation.
    """
    sidecar = destination.with_name(destination.name + ".envelope.json")
    with tempfile.TemporaryDirectory(prefix=".collection-", dir=destination.parent) as temporary:
        published: list[tuple[Path, Path]] = []
        try:
            for index, (target, content) in enumerate(
                ((sidecar, envelope), (destination, payload))
            ):
                staged = Path(temporary) / str(index)
                with os.fdopen(
                    os.open(staged, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), "wb"
                ) as stream:
                    stream.write(content)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.link(staged, target)  # Unlike rename/replace, never overwrites a racing writer.
                published.append((staged, target))
        except BaseException:
            for staged, target in reversed(published):
                if target.exists() and not target.is_symlink() and target.samefile(staged):
                    target.unlink()
            raise


def collect_cloudflare(
    root: Path, config_path: Path, review_path: Path, token_file: Path, output: Path
) -> None:
    """Collect one explicitly authorized zone; preserve original clocks and closed schemas."""
    try:
        root = root.resolve()
        commit = reviewed_commit(root)
        inputs = tuple(_private(root, path) for path in (config_path, review_path, token_file))
        destination = _private(root, output)
        sidecar = destination.with_name(destination.name + ".envelope.json")
        _require(destination.suffix == ".json" and destination.parent.is_dir())
        _require(len(set((*inputs, destination, sidecar))) == 5)
        _require(not destination.exists() and not sidecar.exists() and not sidecar.is_symlink())
        profile_path = root / "config/quotas/profiles.toml"
        proposal_raw, review_raw = (_read(path) for path in inputs[:2])
        profiles_raw = _read(profile_path)
        config, review = _json(proposal_raw), _json(review_raw)
        profile = tomllib.loads(profiles_raw.decode())["profiles"]["cloudflare-free"]
        _review(config, review, profile)
        token_raw = _read(inputs[2], credential=True)
        token = token_raw.decode("ascii").removesuffix("\n").removesuffix("\r")
        _require(re.fullmatch(r"[!-~]{1,4096}", token) is not None)
        collection = collect_zone(
            config["account_id"], config["scope_id"], review["scope_name"], token=token
        )
        payload, envelope = capture_cloudflare_evidence(
            config, profile, collection, review, commit=commit
        )
        _require(reviewed_commit(root) == commit)
        _require(tuple(_read(path) for path in inputs[:2]) == (proposal_raw, review_raw))
        _require(
            _read(profile_path) == profiles_raw and _read(inputs[2], credential=True) == token_raw
        )
        # Recheck private paths after the network boundary before publishing anything.
        _require(_private(root, output) == destination)
        _publish(destination, payload, envelope)
    except Exception:
        raise ValueError(MESSAGE) from None
