"""Protected preview handoff; raw inputs/credentials/events must never reach logs."""

import configparser
import io
import json
import os
import re
import shutil
import sys
import tempfile
import tomllib
from collections.abc import Mapping
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

MESSAGE = "PREVIEW007: protected service preview failed; inspect prerequisites privately"
OCI_MESSAGE = "PREVIEW008: protected OCI preview failed; inspect prerequisites privately"


def require(condition: bool) -> None:
    if not condition:
        raise ValueError(MESSAGE)


def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    require(len(dict(pairs)) == len(pairs))
    return dict(pairs)


def document(raw: str) -> dict[str, Any]:
    require(0 < len(raw.encode()) <= 1024 * 1024)
    value = json.loads(raw, object_pairs_hook=unique)
    require(isinstance(value, dict))
    json.dumps(value, allow_nan=False)
    assert isinstance(value, dict)
    return value


def gate(root: Path, source: Mapping[str, str], *, oci: bool = False) -> str:
    from infra_core.cutover import repository_state
    from infra_core.foundation import load_foundation
    from infra_core.preview_contracts import describe_preview

    unit, commit = source["PREVIEW_UNIT"], source["PREVIEW_COMMIT"]
    require(
        unit in ({"oci-network", "oci-oke"} if oci else {"cloudflare-edge", "supabase-database"})
    )
    require(
        source["GITHUB_EVENT_NAME"] == "workflow_dispatch"
        and source["GITHUB_REF"] == "refs/heads/main"
    )
    require(
        bool(source["GITHUB_ACTOR"]) and source["GITHUB_ACTOR"] == source["GITHUB_REPOSITORY_OWNER"]
    )
    require(source["GITHUB_SHA"] == commit and repository_state(root) == (commit, True))
    require(describe_preview(load_foundation(root), unit, commit).preview_enabled)
    return unit


def private_root(root: Path) -> Path:
    private = root / ".infra"
    require(not private.is_symlink())
    return private


def cleanup(root: Path, *, oci: bool = False) -> None:
    private = private_root(root)
    name = "oci-preview" if oci else "service-preview"
    (private / (name + ".json")).unlink(missing_ok=True)
    for path in private.glob(name + "-*"):
        require(not path.is_symlink())
        if re.fullmatch(name + r"-[a-z0-9_]{8}", path.name):
            require(path.resolve().parent == private.resolve())
            shutil.rmtree(path)


def run(root: Path, source: Mapping[str, str], *, oci: bool = False) -> None:
    from infra_core.foundation import load_foundation
    from infra_program.cli import main as preview

    unit = gate(root, source, oci=oci)
    private = private_root(root)
    private.mkdir(exist_ok=True)
    name = "oci-preview" if oci else "service-preview"
    output = private / (name + ".json")
    require(not output.exists() and not output.is_symlink())
    bundle = document(source["OCI_PREVIEW_INPUTS" if oci else "SERVICE_PREVIEW_INPUTS"])
    extra = {"review"} if unit == "cloudflare-edge" else {"supplement", "organizations"}
    if oci:
        extra = {"account", "usage", "usage_cutoff"}
        if unit == "oci-oke":
            extra.add("dependency_outputs")
    files = {"configuration", "encrypted_configuration", "qualification"} | (
        extra - {"organizations", "usage_cutoff"}
    )
    require(set(bundle) == {"schema_version", "unit"} | files | extra)
    require(
        type(bundle["schema_version"]) is int
        and bundle["schema_version"] == 1
        and bundle["unit"] == unit
    )
    signer = document(source["OCI_BACKEND_AUDIT_CREDENTIALS"])
    require(
        {"tenancy", "user", "fingerprint", "key_content"}
        <= signer.keys()
        <= {"tenancy", "user", "fingerprint", "key_content", "pass_phrase"}
    )
    require(signer["tenancy"] == source["BACKEND_POSTURE_ACCOUNT_ID"])
    require(all(isinstance(v, str) and bool(v.strip()) for v in signer.values()))
    require(all(not any(c in v for c in "\r\n\0") for k, v in signer.items() if k != "key_content"))
    resource_signer = None
    if oci:
        account = tomllib.loads(bundle["account"])
        resource_signer = document(source["OCI_RESOURCE_PREVIEW_CREDENTIALS"])
        require(set(resource_signer) == {"tenancy", "user", "fingerprint", "key_content"})
        require(
            resource_signer["tenancy"] == account["account_id"] and account["provider"] == "oci"
        )
        require(all(isinstance(v, str) and bool(v.strip()) for v in resource_signer.values()))
        require(
            all(
                not any(c in v for c in "\r\n\0")
                for k, v in resource_signer.items()
                if k != "key_content"
            )
        )
        require(
            isinstance(account["home_region"], str)
            and re.fullmatch(r"[a-z]{2}-[a-z]+-[1-9][0-9]*", account["home_region"]) is not None
        )
    pins = json.loads((root / "config/toolchain.json").read_text())
    filename = Path(urlsplit(pins["tools"]["pulumi"]["assets"]["linux-x64"]["url"]).path).name
    archives = list((private / "tools").glob("*/" + filename))
    require(len(archives) == 1)
    with tempfile.TemporaryDirectory(prefix=name + "-", dir=private) as directory:
        work = Path(directory)

        def write(name: str, raw: str) -> str:
            require(isinstance(raw, str) and 0 < len(raw.encode()) <= 1024 * 1024)
            path = work / name
            with os.fdopen(
                os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb"
            ) as stream:
                stream.write(raw.encode())
            return str(path)

        request: dict[str, Any] = {key: write(key + ".json", bundle[key]) for key in files}
        key_file = write("signing-key.pem", signer.pop("key_content"))
        ini = configparser.ConfigParser(interpolation=None)
        ini["DEFAULT"] = signer | {
            "key_file": key_file,
            "region": load_foundation(root).backend.region,
        }
        buffer = io.StringIO()
        ini.write(buffer)
        request.update(
            schema_version=1,
            backend_account_id=source["BACKEND_POSTURE_ACCOUNT_ID"],
            backend_oci_config=write("config", buffer.getvalue()),
            cli_archive=str(archives[0]),
            provider_home=str(private / "provider-home"),
            output=str(work / "result.json"),
        )
        if unit == "supabase-database":
            request["organizations"] = bundle["organizations"]
        if resource_signer is not None:
            resource_key = write("resource-signing-key.pem", resource_signer.pop("key_content"))
            ini = configparser.ConfigParser(interpolation=None)
            ini["DEFAULT"] = resource_signer | {
                "key_file": resource_key,
                "region": account["home_region"],
            }
            buffer = io.StringIO()
            ini.write(buffer)
            request.update(
                oci_config=write("resource-config", buffer.getvalue()),
                usage_cutoff=bundle["usage_cutoff"],
            )
        path = write("request.json", json.dumps(request))
        require(
            preview(
                [
                    "--root",
                    str(root),
                    "preview",
                    "--unit",
                    unit,
                    "--commit",
                    source["PREVIEW_COMMIT"],
                    "--request",
                    path,
                ]
            )
            == 0
        )
        require(gate(root, source, oci=oci) == unit)
        with (work / "result.json").open("rb") as result_stream:
            report = result_stream.read(65537)
        require(0 < len(report) <= 65536)
        # The only source is the trusted CLI's sanitized wrapper, never raw events.
        result = document(report.decode())
        require(
            result["kind"] == "preview-orchestration"
            and result["deployment_authorized"] is False
            and result["cutover_authorized"] is False
        )
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(report)
    except BaseException:
        output.unlink(missing_ok=True)
        raise


def main(root: Path | None = None, source: Mapping[str, str] | None = None) -> int:
    root = root or Path(__file__).resolve().parents[2]
    source = os.environ if source is None else source
    oci = sys.argv[1:2] == ["--oci"]
    args = sys.argv[2:] if oci else sys.argv[1:]
    try:
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            if args == ["--cleanup"]:
                cleanup(root, oci=oci)
            elif args == ["--check"]:
                gate(root, source, oci=oci)
            else:
                require(not args)
                run(root, source, oci=oci)
    except Exception:
        print("FAIL: " + (OCI_MESSAGE if oci else MESSAGE), file=sys.stderr)
        return 1
    print("PASS: protected preview step; deployment and cutover remain disabled")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
