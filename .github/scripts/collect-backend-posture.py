"""Protected CI adapter: ephemeral signing credentials, private evidence, safe summary."""

import configparser
import hashlib
import io
import json
import os
import sys
import tempfile
from collections.abc import Mapping
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from typing import Any

from infra_core import cli
from infra_core.backend_posture import envelope_path, read_posture_pair, validate_posture_evidence
from infra_core.cutover import repository_state
from infra_core.foundation import load_foundation


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    if len(dict(pairs)) != len(pairs):
        raise ValueError("AUDIT001")
    return dict(pairs)


def _private_file(path: Path, content: bytes) -> None:
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as stream:
        stream.write(content)


def collect(root: Path, source: Mapping[str, str]) -> None:
    output = root / ".infra/backend-posture.json"
    report = root / ".infra/backend-audit.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    paths = (output, envelope_path(output), report)
    for path in paths:
        path.unlink(missing_ok=True)
    complete = False
    try:
        encoded = source.get("OCI_BACKEND_AUDIT_CREDENTIALS", "")
        if len(encoded.encode("utf-8")) > 64 * 1024:
            raise ValueError("AUDIT001")
        data = json.loads(encoded, object_pairs_hook=_object)
        required = {"tenancy", "user", "fingerprint", "key_content"}
        if not isinstance(data, dict) or not required <= data.keys() <= required | {"pass_phrase"}:
            raise ValueError("AUDIT001")
        if any(not isinstance(value, str) or not value.strip() for value in data.values()):
            raise ValueError("AUDIT001")
        if any(
            any(char in value for char in "\r\n\0")
            for key, value in data.items()
            if key != "key_content"
        ):
            raise ValueError("AUDIT001")
        account = source.get("BACKEND_POSTURE_ACCOUNT_ID", "")
        if not account or data["tenancy"] != account:
            raise ValueError("AUDIT001")
        config = load_foundation(root)
        with tempfile.TemporaryDirectory(prefix="backend-audit-") as directory:
            private = Path(directory)
            key = private / "signing-key.pem"
            _private_file(key, data.pop("key_content").encode("utf-8"))
            ini = configparser.ConfigParser(interpolation=None)
            ini["DEFAULT"] = data | {"key_file": str(key), "region": config.backend.region}
            buffer = io.StringIO()
            ini.write(buffer)
            credentials = private / "config"
            _private_file(credentials, buffer.getvalue().encode("utf-8"))
            if (
                cli.main(
                    [
                        "--root",
                        str(root),
                        "backend",
                        "collect-posture",
                        "--account-id",
                        account,
                        "--oci-config",
                        str(credentials),
                        "--output",
                        str(output),
                    ]
                )
                != 0
            ):
                raise ValueError("AUDIT001")
        payload, envelope = read_posture_pair(output)
        commit, clean = repository_state(root)
        if not clean:
            raise ValueError("AUDIT001")
        result = validate_posture_evidence(
            config, payload, envelope, account_id=account, commit=commit
        )
        predicate = json.loads(envelope)["predicate"]
        summary = dict(
            schema_version=1,
            **result,
            commit=commit,
            configuration_sha256=config.digest,
            payload_sha256=hashlib.sha256(payload).hexdigest(),
            envelope_sha256=hashlib.sha256(envelope).hexdigest(),
            collection_started_at=predicate["collection_started_at"],
            collection_completed_at=predicate["collection_completed_at"],
        )
        report.write_bytes((json.dumps(summary, sort_keys=True, indent=2) + "\n").encode("utf-8"))
        complete = True
    finally:
        if not complete:
            for path in paths:
                path.unlink(missing_ok=True)


def main(root: Path | None = None, source: Mapping[str, str] | None = None) -> int:
    try:
        # SDK warnings and errors may contain private configuration; never relay them.
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            collect(
                root or Path(__file__).resolve().parents[2],
                os.environ if source is None else source,
            )
    except Exception:
        print(
            "FAIL: AUDIT001: backend audit failed; no usable report; inspect setup privately",
            file=sys.stderr,
        )
        return 1
    print("PASS: read-only backend audit; sanitized report saved; deployment disabled")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
