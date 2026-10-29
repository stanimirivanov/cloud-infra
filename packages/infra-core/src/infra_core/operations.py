"""Offline operation contracts and a local evidence journal; never authorize execution."""

import fcntl
import hashlib
import json
import os
import re
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID

MAX_BYTES = 1024 * 1024
STATES = {
    "prepared": {"admitted", "failed"},
    "admitted": {"running", "failed"},
    "running": {"succeeded", "failed", "indeterminate"},
    "succeeded": set(),
    "failed": set(),
    "indeterminate": set(),
}
FIELDS = {
    "schema_version",
    "operation_id",
    "operation",
    "unit",
    "commit",
    "configuration_sha256",
    "checkpoint_sha256",
    "expires_at",
    "expected_predecessor",
}


def require(condition: bool) -> None:
    if not condition:
        raise ValueError("OPS001: invalid operation evidence or journal transition")


def encoded(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def digest(value: object) -> str:
    return hashlib.sha256(encoded(value)).hexdigest()


def _time(value: object) -> datetime:
    require(type(value) is str)
    try:
        result = datetime.fromisoformat(str(value))
        require(result.utcoffset() == timedelta(0))
        return result
    except (ValueError, OverflowError):
        raise ValueError("OPS001: invalid UTC timestamp") from None


def _hash(value: object) -> bool:
    return type(value) is str and re.fullmatch("[a-f0-9]{64}", str(value)) is not None


def request(value: object) -> dict[str, Any]:
    """Validate a closed schema; return a detached copy with no authority attached."""
    require(type(value) is dict and set(value) == FIELDS)
    assert isinstance(value, dict)
    require(type(value["schema_version"]) is int and value["schema_version"] == 1)
    try:
        require(str(UUID(value["operation_id"])) == value["operation_id"])
    except (ValueError, TypeError, AttributeError):
        raise ValueError("OPS001: invalid operation identity") from None
    require(value["operation"] in ("apply", "import", "recovery", "monitor"))
    require(value["unit"] in ("oci-network", "oci-oke", "cloudflare-edge", "supabase-database"))
    require(
        type(value["commit"]) is str and re.fullmatch("[a-f0-9]{40}", value["commit"]) is not None
    )
    for field in ("configuration_sha256", "checkpoint_sha256"):
        require(_hash(value[field]))
    require(value["expected_predecessor"] is None or _hash(value["expected_predecessor"]))
    _time(value["expires_at"])
    return dict(value)


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    require(len(dict(pairs)) == len(pairs))
    return dict(pairs)


def read_json(path: Path) -> Any:
    try:
        with path.open("rb") as stream:
            raw = stream.read(MAX_BYTES + 1)
        require(len(raw) <= MAX_BYTES)
        return json.loads(raw, object_pairs_hook=_pairs)
    except (OSError, ValueError, UnicodeError):
        raise ValueError("OPS001: cannot read bounded operation evidence") from None


def inspect(path: Path, *, now: datetime | None = None) -> dict[str, object]:
    value = request(read_json(path))
    return {
        "schema_version": 1,
        "operation_id": value["operation_id"],
        "operation": value["operation"],
        "unit": value["unit"],
        "request_sha256": digest(value),
        "expired": _time(value["expires_at"]) <= (now or datetime.now(UTC)),
        "execution_authorized": False,
    }


def _validate(entries: object) -> list[dict[str, Any]]:
    require(type(entries) is list)
    assert isinstance(entries, list)
    seen: set[str] = set()
    previous: dict[str, Any] | None = None
    for entry in entries:
        require(type(entry) is dict and set(entry) == {"request", "state", "previous", "at"})
        value = request(entry["request"])
        state = entry["state"]
        require(type(state) is str and state in STATES)
        require(entry["previous"] == (digest(previous) if previous else None))
        at = _time(entry["at"])
        require(previous is None or at >= _time(previous["at"]))
        if state == "prepared":
            require(value["operation_id"] not in seen)
            require(previous is None or not STATES[previous["state"]])
            require(value["expected_predecessor"] == entry["previous"])
            seen.add(value["operation_id"])
        else:
            require(previous is not None)
            assert previous is not None
            require(value == previous["request"] and state in STATES[previous["state"]])
        if state in ("prepared", "admitted", "running"):
            require(at < _time(value["expires_at"]))
        previous = entry
    return entries


def journal(
    root: Path,
    path: Path,
    value: object,
    state: str,
    *,
    predecessor: str | None,
    now: datetime | None = None,
) -> str:
    """Append using a local lock and compare-and-swap; this is not a writer fence.

    admitted/running record caller assertions, never verified operational permission.
    Indeterminate is terminal: reconciliation requires a separately reviewed new request.
    """
    value = request(value)
    private = root.absolute() / ".infra"
    path = Path(os.path.abspath(root / path))
    require(path.is_relative_to(private) and path != private)
    require(not any(p.is_symlink() for p in (path, *path.parents)))
    path.parent.mkdir(parents=True, exist_ok=True)
    lock = path.with_name(path.name + ".lock")
    try:
        with os.fdopen(os.open(lock, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600), "a") as guard:
            fcntl.flock(guard, fcntl.LOCK_EX)
            entries = _validate(read_json(path)) if path.exists() else []
            require(predecessor == (digest(entries[-1]) if entries else None))
            entry = {
                "request": value,
                "state": state,
                "previous": predecessor,
                "at": (now or datetime.now(UTC)).isoformat(),
            }
            entries = _validate([*entries, entry])
            payload = encoded(entries)
            require(len(payload) <= MAX_BYTES)
            temporary: str | None = None
            try:
                with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as stream:
                    temporary = stream.name
                    stream.write(payload)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temporary, path)
                directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
            finally:
                if temporary is not None:
                    Path(temporary).unlink(missing_ok=True)
            return digest(entry)
    except OSError:
        raise RuntimeError(
            "OPS002: journal persistence uncertain; inspect before retrying"
        ) from None


def inspect_journal(path: Path) -> dict[str, object]:
    entries = _validate(read_json(path))
    return {
        "schema_version": 1,
        "entries": len(entries),
        "head": digest(entries[-1]) if entries else None,
        "state": entries[-1]["state"] if entries else None,
        "execution_authorized": False,
    }
