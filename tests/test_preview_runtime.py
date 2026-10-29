"""Synthetic runtime assets and process/RPC spies; no CLI/provider execution or credentials."""

import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
from pathlib import Path
from types import SimpleNamespace

import pytest
import test_provider_tools
import test_supabase_provider_cache
from infra_core import provider_tools as pt
from infra_program import preview_runtime as runtime

ROOT = Path(__file__).resolve().parents[1]
fixture = test_provider_tools.fixture
cache = test_supabase_provider_cache.cache


@pytest.fixture
def prepared(tmp_path, monkeypatch):
    monkeypatch.setattr(runtime.platform, "system", lambda: "Linux")
    monkeypatch.setattr(runtime.platform, "machine", lambda: "x86_64")
    root = tmp_path
    (root / "config").mkdir()
    pins = json.loads((ROOT / "config/toolchain.json").read_bytes())
    asset = pins["tools"]["pulumi"]["assets"]["linux-x64"]
    prefix = str(Path(asset["binary"]).parent).replace("\\", "/")
    names = [asset["binary"], prefix + "/pulumi-language-python"]
    archive = root / "cli.tar.gz"
    with tarfile.open(archive, "w:gz") as package:
        for name in names:
            member = tarfile.TarInfo(name)
            member.size = len(b"synthetic executable")
            package.addfile(member, io.BytesIO(b"synthetic executable"))
    asset["sha256"] = hashlib.sha256(archive.read_bytes()).hexdigest()
    (root / "config/toolchain.json").write_text(json.dumps(pins))
    work = root / "work"
    work.mkdir()
    return root, archive, work


def environment(work):
    return dict(
        HOME=str(work),
        TMP=str(work),
        TEMP=str(work),
        TMPDIR=str(work),
        PATH=os.pathsep.join((str(Path(sys.executable).parent), str(work / "bin"))),
        PULUMI_HOME=str(work / "home"),
        PULUMI_BACKEND_URL="file:///synthetic",
        PULUMI_CONFIG_PASSPHRASE="synthetic",
        AWS_ACCESS_KEY_ID="synthetic",
        AWS_SECRET_ACCESS_KEY="synthetic",
        PULUMI_IGNORE_AMBIENT_PLUGINS="true",
        PULUMI_DISABLE_AUTOMATIC_PLUGIN_ACQUISITION="true",
        PULUMI_SKIP_UPDATE_CHECK="true",
        PULUMI_DEBUG_COMMANDS="true",
        AWS_EC2_METADATA_DISABLED="true",
    )


def test_archive_and_all_companions_are_reverified(prepared):
    root, archive, work = prepared
    cli = runtime.cli_runtime(root, archive, work / "bin")
    cli.verify()
    companion = next(p for p in cli.binary.parent.iterdir() if p != cli.binary)
    companion.write_bytes(b"altered")
    with pytest.raises(RuntimeError, match="PREVIEW005"):
        cli.verify()
    archive.write_bytes(b"altered archive")
    with pytest.raises(RuntimeError, match="PREVIEW005"):
        runtime.cli_runtime(root, archive, work / "untouched")
    assert not (work / "untouched").exists()


@pytest.mark.parametrize(
    "key",
    [
        "PYTHONPATH",
        "HTTPS_PROXY",
        "PULUMI_ACCESS_TOKEN",
        "PULUMI_DEBUG_PROVIDERS",
        "PULUMI_BRIDGE_REATTACH_PROVIDERS",
        "TF_REATTACH_PROVIDERS",
        "PATH",
    ],
)
def test_environment_injection_is_rejected(prepared, key):
    root, archive, work = prepared
    cli = runtime.cli_runtime(root, archive, work / "bin")
    with pytest.raises(RuntimeError, match="PREVIEW005"):
        runtime.Command(
            cli,
            work,
            dict(environment(work), **{key: "injected"}),
            "organization/free-infrastructure/cloudflare-edge",
            ROOT / "policies",
        )


@pytest.mark.parametrize(
    "operation",
    [
        "up",
        "destroy",
        "refresh",
        "import",
        "config",
        "stack-init",
        "stack-export",
        "missing-policy",
    ],
)
def test_command_gate_rejects_every_non_preview_operation(prepared, monkeypatch, operation):
    root, archive, work = prepared
    cli = runtime.cli_runtime(root, archive, work / "bin")
    command = runtime.Command(
        cli,
        work,
        environment(work),
        "organization/free-infrastructure/oci-network",
        ROOT / "policies",
    )
    monkeypatch.setattr(runtime.subprocess, "Popen", lambda *a, **kw: pytest.fail("executed"))
    args = (
        ["stack", operation.removeprefix("stack-")]
        if operation.startswith("stack-")
        else [operation]
    )
    with pytest.raises(RuntimeError, match="PREVIEW005"):
        command.run(args, str(work), {})


def test_select_and_sdk_preview_arguments_without_execution(prepared, monkeypatch):
    root, archive, work = prepared
    cli = runtime.cli_runtime(root, archive, work / "bin")
    env = environment(work)
    command = runtime.Command(
        cli, work, env, "organization/free-infrastructure/oci-network", ROOT / "policies"
    )
    calls = []

    def launch(args, **options):
        calls.append((args, options))
        return SimpleNamespace(wait=lambda **kw: 0, poll=lambda: 0)

    monkeypatch.setattr(runtime.subprocess, "Popen", launch)
    workspace = runtime.auto.LocalWorkspace(
        work_dir=str(work), pulumi_home=env["PULUMI_HOME"], pulumi_command=command
    )
    stack = runtime.Stack.select(command.stack, workspace)

    def setup(self, name, callback, version):
        assert name == "preview"
        command.uri = "tcp://127.0.0.1:12345"
        self.wire = runtime.Wire(callback)
        self.wire.StreamEvents(
            iter(
                [
                    SimpleNamespace(
                        event=json.dumps({"summaryEvent": {"resourceChanges": {"same": 1}}})
                    )
                ]
            ),
            SimpleNamespace(abort=lambda *a: pytest.fail("RPC abort")),
        )
        return command.uri, None, None, None, None

    monkeypatch.setattr(runtime.Stack, "_setup_event_log", setup)
    preview = dict(
        policy_packs=[str(ROOT / "policies")],
        parallel=1,
        color="never",
        suppress_outputs=True,
        suppress_progress=True,
        refresh=False,
        config_file=str(work / "stack.yaml"),
    )
    stack.preview(**preview)
    with pytest.raises(RuntimeError, match="PREVIEW005"):
        stack.preview(**preview, on_event=lambda event: pytest.fail("untrusted callback"))
    assert len(calls) == 2 and calls[-1][0][-1] == "--refresh=false"
    assert calls[0][0][1:3] == ["stack", "select"]
    assert all(
        options["env"] == env
        and options["stdout"] == subprocess.DEVNULL
        and options["stderr"] == subprocess.DEVNULL
        for _, options in calls
    )


def test_timeout_terminates_owned_process_and_redacts_error(prepared, monkeypatch):
    root, archive, work = prepared
    cli = runtime.cli_runtime(root, archive, work / "bin")
    command = runtime.Command(
        cli,
        work,
        environment(work),
        "organization/free-infrastructure/oci-network",
        ROOT / "policies",
    )
    actions = []

    def wait(**kwargs):
        if not actions:
            raise subprocess.TimeoutExpired("private-diagnostic", 1)
        return 0

    monkeypatch.setattr(
        runtime.subprocess,
        "Popen",
        lambda *a, **kw: SimpleNamespace(
            wait=wait, poll=lambda: None, pid=12345, kill=lambda: actions.append("direct-kill")
        ),
    )
    monkeypatch.setattr(runtime.os, "killpg", lambda *args: actions.append(args))
    with pytest.raises(RuntimeError, match="PREVIEW005") as error:
        command.run(["stack", "select", "--stack", command.stack], str(work), {})
    assert actions and "private-diagnostic" not in str(error.value)


def test_wire_retains_sdk_omitted_events_and_limits_private_data(monkeypatch):
    summaries = []
    wire = runtime.Wire(summaries.append)
    raw = '{"policyAnalyzeSummaryEvent":{"passed":["reviewed-resource-costs"]}}'
    context = SimpleNamespace(abort=lambda *a: (_ for _ in ()).throw(RuntimeError(runtime.MESSAGE)))
    wire.StreamEvents(iter([SimpleNamespace(event=raw)]), context)
    assert wire.records == [raw.encode()] and not summaries
    monkeypatch.setattr(runtime, "MAX_EVENT_BYTES", 8)
    with pytest.raises(RuntimeError, match="PREVIEW005"):
        wire.StreamEvents(iter([SimpleNamespace(event="private-message-too-large")]), context)
    assert wire.records == [raw.encode()]


@pytest.mark.parametrize("failure", ["denied", "ineffective"])
def test_tree_kill_failure_still_reaps_owned_process(prepared, monkeypatch, failure):
    root, archive, work = prepared
    cli = runtime.cli_runtime(root, archive, work / "bin")
    command = runtime.Command(
        cli,
        work,
        environment(work),
        "organization/free-infrastructure/oci-network",
        ROOT / "policies",
    )
    state = SimpleNamespace(alive=True, waits=0, killed=False)

    def wait(**kwargs):
        state.waits += 1
        if state.alive:
            raise subprocess.TimeoutExpired("synthetic", 1)
        return 0

    def kill():
        state.killed, state.alive = True, False

    def tree(*args, **kwargs):
        if failure == "denied":
            raise PermissionError("private-tree-diagnostic")
        return SimpleNamespace(returncode=1)

    process = SimpleNamespace(
        pid=12345, wait=wait, kill=kill, poll=lambda: None if state.alive else 0
    )
    monkeypatch.setattr(runtime.subprocess, "Popen", lambda *a, **kw: process)
    monkeypatch.setattr(runtime.os, "killpg", tree)
    with pytest.raises(RuntimeError, match="PREVIEW005"):
        command.run(["stack", "select", "--stack", command.stack], str(work), {})
    assert state.killed and not state.alive and state.waits == 2


def test_materialize_native_home_uses_reverified_local_archives(fixture):
    root, home, archives, _ = fixture
    for name, source in archives.items():
        pt.install_provider(root, name, source, home)
    target = home.parent / "fresh"
    assert pt.materialize_home(root, home, target, supabase=False)["PULUMI_HOME"] == str(target)
    pt.verified_environment(root, target)


def test_materialize_supabase_home_preserves_cache_and_parameterization(cache):
    root, home, archive, _ = cache
    pt.install_supabase(root, archive, home)
    target = home.parent / "fresh-supabase"
    settings = pt.materialize_home(root, home, target, supabase=True)
    assert settings["PULUMI_DYNAMIC_TF_PLUGIN_CACHE_DIR"] == str(target / "dynamic_tf_plugins")
    pt.verified_supabase_environment(root, target)
