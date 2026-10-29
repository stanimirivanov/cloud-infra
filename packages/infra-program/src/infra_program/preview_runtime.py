"""Pinned Automation SDK adapter: closed commands, private wire capture and process cleanup."""

import hashlib
import json
import os
import platform
import shutil
import signal
import subprocess
import sys
import tarfile
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import IO, Any

from infra_core.evidence import MAX_TOTAL_BYTES
from infra_core.preview_results import MAX_EVENT_BYTES, MAX_EVENTS
from pulumi import automation as auto
from pulumi._version import version as sdk_version
from pulumi.automation import _stack as sdk

MESSAGE = "PREVIEW005: constrained preview failed; private diagnostics withheld"
POLICY = Path(__file__).resolve().parents[4] / "policies"
__all__ = ["CliRuntime", "Command", "Stack", "Wire", "MESSAGE", "require", "cli_runtime"]
_PERMIT = object()


# SDK-private transport objects, deliberately confined to this pinned adapter boundary.
def _sdk_object(name: str) -> Any:
    """SDK-private, unexported transport types; signatures are pinned and tested here."""
    return getattr(sdk, name)


_grpc = _sdk_object("grpc")
_futures = _sdk_object("futures")
_events = _sdk_object("events_pb2_grpc")
_empty = _sdk_object("empty_pb2")


def require(condition: bool) -> None:
    if not condition:
        raise RuntimeError(MESSAGE)


@dataclass(frozen=True)
class CliRuntime:
    binary: Path
    files: tuple[tuple[str, int, str], ...]
    _permit: object = field(repr=False)

    def verify(self) -> None:
        require(self._permit is _PERMIT and not self.binary.parent.is_symlink())
        require(
            {p.name for p in self.binary.parent.iterdir()} == {name for name, _, _ in self.files}
        )
        for name, size, digest in self.files:
            path = self.binary.parent / name
            require(path.is_file() and not path.is_symlink() and path.stat().st_size == size)
            with path.open("rb") as stream:
                require(hashlib.file_digest(stream, "sha256").hexdigest() == digest)


def cli_runtime(root: Path, archive: Path, target: Path) -> CliRuntime:
    try:
        return _cli_runtime(root, archive, target)
    except Exception:
        raise RuntimeError(MESSAGE) from None


def _cli_runtime(root: Path, archive: Path, target: Path) -> CliRuntime:
    """Verify the original release before copying CLI/companion files; never download."""
    require(platform.system() == "Linux" and platform.machine().lower() in {"amd64", "x86_64"})
    pin = json.loads((root / "config/toolchain.json").read_bytes())["tools"]["pulumi"]
    asset = pin["assets"]["linux-x64"]
    require(str(sdk_version) == pin["version"] and archive.stat().st_size <= 512 * 1024**2)

    def digest() -> str:
        with archive.open("rb") as stream:
            return hashlib.file_digest(stream, "sha256").hexdigest()

    require(digest() == asset["sha256"])
    prefix = PurePosixPath(asset["binary"]).parent
    target.mkdir()
    count, total = 0, 0

    def save(name: str, size: int, source: IO[bytes]) -> None:
        nonlocal count, total
        path = PurePosixPath(name)
        require("\\" not in name and path.name not in {".", ".."})
        if path.parent != prefix:
            return
        count, total = count + 1, total + size
        require(count <= 128 and total <= 4 * 1024**3)
        with (target / path.name).open("xb") as output:
            shutil.copyfileobj(source, output)
        (target / path.name).chmod(0o755)

    with tarfile.open(archive, "r|gz") as tar:
        for entry in tar:
            if entry.isdir():
                continue
            require(entry.isfile())
            tar_member = tar.extractfile(entry)
            require(tar_member is not None)
            assert tar_member is not None
            with tar_member:
                save(entry.name, entry.size, tar_member)
    require(digest() == asset["sha256"])
    binary = target / PurePosixPath(asset["binary"]).name
    require(binary.is_file() and (target / "pulumi-language-python").is_file())
    files = []
    for path in sorted(target.iterdir()):
        with path.open("rb") as stream:
            files.append(
                (path.name, path.stat().st_size, hashlib.file_digest(stream, "sha256").hexdigest())
            )
    runtime = CliRuntime(binary, tuple(files), _PERMIT)
    runtime.verify()
    return runtime


class Command(auto.PulumiCommand):
    def __init__(
        self, runtime: CliRuntime, work: Path, env: dict[str, str], stack: str, policy: Path
    ) -> None:
        # Deliberately do not call SDK init: it inherits env and runs an unbounded version command.
        runtime.verify()
        require(policy.resolve() == POLICY and POLICY.is_dir())
        require(
            stack
            in {
                "organization/free-infrastructure/" + name
                for name in ("oci-network", "oci-oke", "cloudflare-edge", "supabase-database")
            }
        )
        self.runtime = runtime
        self.command, self.version = str(runtime.binary), sdk_version
        self.work, self.env, self.stack, self.policy = work, dict(env), stack, str(policy)
        allowed = set(
            (
                "HOME TMP TEMP TMPDIR PATH PULUMI_HOME "
                "PULUMI_BACKEND_URL PULUMI_SKIP_UPDATE_CHECK PULUMI_DEBUG_COMMANDS "
                "PULUMI_IGNORE_AMBIENT_PLUGINS PULUMI_DISABLE_AUTOMATIC_PLUGIN_ACQUISITION "
                "PULUMI_CONFIG_PASSPHRASE AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY "
                "AWS_SESSION_TOKEN "
                "AWS_EC2_METADATA_DISABLED OCI_USER_OCID OCI_FINGERPRINT OCI_PRIVATE_KEY_PATH "
                "PULUMI_DYNAMIC_TF_PLUGIN_CACHE_DIR PULUMI_BRIDGE_REATTACH_PROVIDERS "
                "TF_REATTACH_PROVIDERS"
            ).split()
        )
        require(set(env) <= allowed and all(type(v) is str for v in env.values()))
        for key in (
            "PULUMI_IGNORE_AMBIENT_PLUGINS",
            "PULUMI_DISABLE_AUTOMATIC_PLUGIN_ACQUISITION",
            "PULUMI_SKIP_UPDATE_CHECK",
            "PULUMI_DEBUG_COMMANDS",
            "AWS_EC2_METADATA_DISABLED",
        ):
            require(env.get(key) == "true")
        require(
            all(
                env.get(k, "") == ""
                for k in ("PULUMI_BRIDGE_REATTACH_PROVIDERS", "TF_REATTACH_PROVIDERS")
            )
        )
        require(
            env.get("PATH")
            == os.pathsep.join((str(Path(sys.executable).parent), str(runtime.binary.parent)))
        )
        require(
            runtime.binary.parent == work / "bin" and env.get("PULUMI_HOME") == str(work / "home")
        )
        require(all(env.get(k) == str(work) for k in ("HOME", "TMP", "TEMP", "TMPDIR")))
        require(
            all(
                bool(env.get(k))
                for k in (
                    "PULUMI_BACKEND_URL",
                    "PULUMI_CONFIG_PASSPHRASE",
                    "AWS_ACCESS_KEY_ID",
                    "AWS_SECRET_ACCESS_KEY",
                )
            )
        )
        if "PULUMI_DYNAMIC_TF_PLUGIN_CACHE_DIR" in env:
            require(
                env["PULUMI_DYNAMIC_TF_PLUGIN_CACHE_DIR"] == str(work / "home/dynamic_tf_plugins")
            )
        self.deadline = time.monotonic() + 300
        self.uri = ""

    def run(
        self,
        args: list[str],
        cwd: str,
        additional_env: Mapping[str, str],
        on_output: Callable[[str], Any] | None = None,
        on_error: Callable[[str], Any] | None = None,
    ) -> auto.CommandResult:
        try:
            return self._run(args, cwd, additional_env, on_output, on_error)
        except Exception:
            raise RuntimeError(MESSAGE) from None

    def _run(
        self,
        args: list[str],
        cwd: str,
        additional_env: Mapping[str, str],
        on_output: Callable[[str], Any] | None,
        on_error: Callable[[str], Any] | None,
    ) -> auto.CommandResult:
        self.runtime.verify()
        select = ["stack", "select", "--stack", self.stack]
        preview = [
            "preview",
            "--policy-pack",
            self.policy,
            "--parallel",
            "1",
            "--color",
            "never",
            "--suppress-outputs",
            "--suppress-progress",
            "--config-file",
            str(self.work / "stack.yaml"),
            "--exec-kind",
            "auto.local",
            "--event-log",
            self.uri,
            "--stack",
            self.stack,
        ]
        require(args == select or (bool(self.uri) and args == preview))
        require(
            Path(cwd).resolve() == self.work.resolve() and on_output is None and on_error is None
        )
        require(
            all(
                (k == "PULUMI_HOME" and v == self.env[k])
                or (k == "PULUMI_DEBUG_COMMANDS" and v == "true")
                for k, v in additional_env.items()
            )
        )
        remaining = self.deadline - time.monotonic()
        require(remaining > 0)
        argv = [self.command, *args, "--non-interactive"]
        if args[0] == "preview":
            argv.append("--refresh=false")
        process = subprocess.Popen(
            argv,
            cwd=self.work,
            env=self.env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        try:
            require(process.wait(timeout=remaining) == 0)
        finally:
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                finally:
                    # A denied/failed tree-kill must still reap the owned process
                    # through its existing handle. Descendants remain OS-governed.
                    if process.poll() is None:
                        process.kill()
                    process.wait(timeout=5)
        self.runtime.verify()
        return auto.CommandResult("", "", 0)


class Wire(sdk._EventsServicer):
    def __init__(self, callback: Callable[[auto.EngineEvent], Any]) -> None:
        self.callback, self.total = callback, 0
        self.records: list[bytes] = []

    def StreamEvents(self, requests: Iterable[Any], context: Any) -> Any:
        try:
            for request in requests:
                raw = request.event.encode("utf-8")
                self.total += len(raw)
                require(
                    len(raw) <= MAX_EVENT_BYTES
                    and self.total <= MAX_TOTAL_BYTES
                    and len(self.records) < MAX_EVENTS
                )
                self.records.append(raw)
                value = json.loads(raw)
                if "summaryEvent" in value:
                    # Only SDK-required summary parsing; never call its raw-event warning path.
                    self.callback(auto.EngineEvent.from_json(value))
            return _empty.Empty()
        except Exception:
            context.abort(_grpc.StatusCode.INVALID_ARGUMENT, MESSAGE)


class Stack(auto.Stack):
    wire: Wire

    def preview(self, *args: Any, **kwargs: Any) -> auto.PreviewResult:
        require(
            not args
            and set(kwargs)
            == {
                "policy_packs",
                "parallel",
                "color",
                "suppress_outputs",
                "suppress_progress",
                "refresh",
                "config_file",
            }
        )
        require(kwargs["refresh"] is False)
        return super().preview(**kwargs)

    @classmethod
    def select(cls, stack_name: str, workspace: auto.Workspace) -> "Stack":
        # The SDK factory constructs its base class, losing this raw-event hook.
        return cls(stack_name, workspace, sdk.StackInitMode.SELECT)

    def _setup_event_log(
        self, command: str, on_event: Callable[[auto.EngineEvent], Any], pulumi_version: str
    ) -> Any:
        require(command == "preview" and pulumi_version == str(sdk_version))
        server = _grpc.server(
            _futures.ThreadPoolExecutor(max_workers=1),
            options=[("grpc.max_receive_message_length", MAX_EVENT_BYTES + 256)],
        )
        self.wire = Wire(on_event)
        _events.add_EventsServicer_to_server(self.wire, server)
        port = server.add_insecure_port("127.0.0.1:0")
        server.start()
        uri = f"tcp://127.0.0.1:{port}"
        adapter = self.workspace.pulumi_command
        require(isinstance(adapter, Command))
        assert isinstance(adapter, Command)
        adapter.uri = uri
        return uri, None, None, None, server
