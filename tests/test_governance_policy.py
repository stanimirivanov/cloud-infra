"""Mandatory policy enforcement with no provider plugins or cloud resources."""

import json
import os
import signal
import subprocess
import sys
import tempfile
import tomllib
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace

import grpc
import pytest
from google.protobuf import struct_pb2
from infra_core.backend import qualification_environment
from infra_program import governance
from pulumi.runtime import proto
from pulumi_policy import EnforcementLevel

ROOT = Path(__file__).resolve().parents[1]


def test_policy_pack_is_mandatory(monkeypatch):
    monkeypatch.setattr(governance, "PolicyPack", lambda **kwargs: kwargs)
    pack = governance.policy_pack()
    assert pack["enforcement_level"] == EnforcementLevel.MANDATORY
    assert pack["policies"][0].enforcement_level == EnforcementLevel.MANDATORY
    violations = []
    pack["policies"][0].validate(
        SimpleNamespace(
            resource_type="infrastructure:oci:Network",
            props={},
            get_config=lambda: {},
        ),
        lambda message, urn: violations.append(message),
    )
    assert any("GOV031" in message for message in violations)


@pytest.mark.backend_integration
@pytest.mark.skipif(
    os.environ.get("RUN_PULUMI_LOCAL_QUALIFICATION") != "1", reason="explicit local-backend opt-in"
)
def test_real_pulumi_preview_blocks_unclassified_resource():
    # Match qualification isolation with an invocation-specific temporary backend.
    with tempfile.TemporaryDirectory(prefix="gov-") as directory:
        _preview(Path(directory))


def _preview(tmp_path):
    env = qualification_environment(dict(os.environ), tmp_path / "home", local=True)
    # Policy-host handshake/output must not depend on redirected stream buffering.
    env["PYTHONUNBUFFERED"] = "1"
    project = tmp_path / "project"
    project.mkdir()
    (project / "Pulumi.yaml").write_text(
        json.dumps(
            {
                "name": "governance-synthetic-test",
                "runtime": {"name": "python", "options": {"virtualenv": sys.prefix}},
            }
        )
    )
    # ComponentResource needs no provider and cannot create a cloud resource.
    (project / "__main__.py").write_text(
        "import pulumi\n"
        'component = pulumi.ComponentResource("synthetic:index:Unreviewed", "blocked")\n'
        "component.register_outputs({})\n"
    )
    backend = tmp_path / "backend"
    backend.mkdir()

    def run(args, *, success=True):
        process = subprocess.Popen(
            ["pulumi", *args, "--non-interactive", "--color=never"],
            cwd=project,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            start_new_session=True,
        )
        try:
            stdout, stderr = process.communicate(timeout=120)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            stdout, stderr = process.communicate(timeout=15)
            pytest.fail("Synthetic Pulumi command timed out:\n" + stdout + stderr)
        result = subprocess.CompletedProcess(process.args, process.returncode, stdout, stderr)
        if success:
            assert result.returncode == 0, result.stdout + result.stderr
        return result

    run(["login", backend.as_uri()])
    run(["stack", "init", "synthetic", "--secrets-provider", "passphrase"])
    run(["preview", "--stack", "synthetic"])
    result = run(
        [
            "preview",
            "--stack",
            "synthetic",
            "--policy-pack",
            str(ROOT / "policies"),
        ],
        success=False,
    )
    assert result.returncode != 0
    output = result.stdout + result.stderr
    assert "GOV022" in output, output
    assert "mandatory" in output.lower(), output
    # A reviewed component needs no cloud provider, but must receive explicit OCI context.
    (project / "__main__.py").write_text(
        'import pulumi\npulumi.ComponentResource("infrastructure:oci:Network", "network")\n'
    )
    args = ["preview", "--stack", "synthetic", "--policy-pack", str(ROOT / "policies")]
    denied = run(args, success=False)
    assert denied.returncode != 0 and "GOV031" in denied.stdout + denied.stderr
    config = project / "policy.json"
    profile = _profile("oci-free")
    config.write_text(
        json.dumps(
            governance.policy_configuration(
                {"profile": profile["id"], "profile_revision": profile["revision"]}, profile
            )
        )
    )
    run([*args, "--policy-pack-config", str(config)])


@pytest.mark.backend_integration
@pytest.mark.skipif(
    os.environ.get("RUN_PULUMI_LOCAL_QUALIFICATION") != "1",
    reason="explicit local policy-host opt-in",
)
def test_real_policy_protocol_accepts_controls_and_denies_loadbalancer(
    tmp_path, kube_config, workload
):
    from infra_core.kubernetes.resources import render

    env = qualification_environment(dict(os.environ), tmp_path / "home", local=True)
    host = subprocess.Popen(
        [sys.executable, "-u", str(ROOT / "policies/__main__.py")],
        cwd=ROOT / "policies",
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        encoding="utf-8",
    )
    reader = ThreadPoolExecutor(max_workers=1)
    try:
        assert host.stdout is not None
        line = reader.submit(host.stdout.readline).result(timeout=20)
        port = int(line.strip())
        assert 0 < port < 65536
        with grpc.insecure_channel(f"127.0.0.1:{port}") as channel:
            grpc.channel_ready_future(channel).result(timeout=15)
            stub = proto.AnalyzerStub(channel)
            props = {
                "metadata": {"name": "app", "namespace": "applications"},
                "spec": {
                    "type": "ClusterIP",
                    "selector": {"app": "app"},
                    "ports": [{"port": 80, "targetPort": 8080, "protocol": "TCP"}],
                },
            }

            def analyze(resource_type="kubernetes:core/v1:Service", values=None):
                payload = struct_pb2.Struct()
                payload.update(props if values is None else values)
                return stub.Analyze(
                    proto.AnalyzeRequest(
                        type=resource_type,
                        name="app",
                        urn=f"urn:pulumi:test::offline::{resource_type}::app",
                        properties=payload,
                    ),
                    timeout=15,
                )

            assert not analyze().diagnostics
            props["spec"]["ports"].append({"port": 81, "targetPort": 8081, "protocol": "TCP"})
            assert "K8S010" in analyze().diagnostics[0].message
            props["spec"]["ports"].pop()
            for item in render(kube_config)["items"] + [workload]:
                group = "core/v1" if item["apiVersion"] == "v1" else item["apiVersion"]
                response = analyze(f"kubernetes:{group}:{item['kind']}", item)
                assert not response.diagnostics, response
            pool = {
                "nodeShape": "VM.Standard.A1.Flex",
                "nodeShapeConfig": {"ocpus": 1, "memoryInGbs": 6},
                "nodeSourceDetails": {
                    "sourceType": "IMAGE",
                    "imageId": "ocid1.image.oc1..fixture",
                    "bootVolumeSizeInGbs": "50",
                },
                "nodeConfigDetails": {
                    "size": 2,
                    "isPvEncryptionInTransitEnabled": True,
                    "placementConfigs": [{"availabilityDomain": "fixture", "subnetId": "fixture"}],
                    "nsgIds": ["fixture"],
                    "nodePoolPodNetworkOptionDetails": {
                        "cniType": "OCI_VCN_IP_NATIVE",
                        "podSubnetIds": ["fixture"],
                        "podNsgIds": ["fixture"],
                    },
                },
            }
            assert (
                "GOV031"
                in analyze("oci:ContainerEngine/nodePool:NodePool", pool).diagnostics[0].message
            )
            profile = _profile("oci-free")
            properties = struct_pb2.Struct()
            properties.update({"ociProfile": governance._profile_settings(profile)})
            stub.Configure(
                proto.ConfigureAnalyzerRequest(
                    policyConfig={
                        "reviewed-resource-costs": proto.PolicyConfig(
                            enforcementLevel=proto.MANDATORY, properties=properties
                        ),
                    }
                ),
                timeout=15,
            )
            response = analyze("oci:ContainerEngine/nodePool:NodePool", pool)
            assert not response.diagnostics, response
            pool["nodeShapeConfig"] = {"ocpus": 2, "memoryInGbs": 12}
            assert (
                "GOV030"
                in analyze("oci:ContainerEngine/nodePool:NodePool", pool).diagnostics[0].message
            )
            properties = struct_pb2.Struct()
            properties.update({"ociProfile": governance._profile_settings(_profile("oci-paid-a1"))})
            stub.Configure(
                proto.ConfigureAnalyzerRequest(
                    policyConfig={
                        "reviewed-resource-costs": proto.PolicyConfig(
                            enforcementLevel=proto.MANDATORY, properties=properties
                        ),
                    }
                ),
                timeout=15,
            )
            assert not analyze("oci:ContainerEngine/nodePool:NodePool", pool).diagnostics
            external = [
                (
                    "cloudflare:index/dnsRecord:DnsRecord",
                    {
                        "zoneId": "a" * 32,
                        "name": "app.example.com",
                        "type": "A",
                        "ttl": 300,
                        "content": "192.0.2.1",
                        "proxied": False,
                    },
                ),
                (
                    "supabase:index/project:Project",
                    {
                        "organizationId": "example-org",
                        "name": "example-db",
                        "region": "eu-central-1",
                        "instanceSize": "nano",
                        "legacyApiKeysEnabled": False,
                        "databasePassword": "synthetic-password",
                    },
                ),
            ]
            for kind, values in external:
                assert not analyze(kind, values).diagnostics
                denied = analyze(kind, {**values, "paidAddon": True}).diagnostics
                assert len(denied) == 1 and denied[0].enforcementLevel == proto.MANDATORY
            for kind in (
                "cloudflare:index/workersScript:WorkersScript",
                "supabase:index/branch:Branch",
            ):
                assert analyze(kind, {}).diagnostics
            props["spec"]["type"] = "LoadBalancer"
            diagnostics = analyze().diagnostics
            assert len(diagnostics) == 1
            assert "K8S010" in diagnostics[0].message
            assert diagnostics[0].enforcementLevel == proto.MANDATORY
    finally:
        host.terminate()
        try:
            host.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            host.kill()
            host.communicate(timeout=10)
        reader.shutdown(wait=True)


def _profile(name):
    return tomllib.loads((ROOT / "config/quotas/profiles.toml").read_text())["profiles"][name]


@pytest.mark.parametrize("name,denied", [("oci-free", True), ("oci-paid-a1", False)])
def test_mandatory_callback_uses_selected_capacity(name, denied):
    import test_oci
    from infra_core.oci.graph import foundation_graph, wire

    cfg = test_oci.config.__wrapped__()
    pool = next(
        r for r in foundation_graph(cfg) if r.kind == "oci:ContainerEngine/nodePool:NodePool"
    )
    props = wire(pool.props)
    props["nodeShapeConfig"] = {"ocpus": 2, "memoryInGbs": 12}
    violations = []
    governance.validate_profiled_resource(
        SimpleNamespace(
            resource_type=pool.kind,
            props=props,
            get_config=lambda: {"ociProfile": governance._profile_settings(_profile(name))},
        ),
        lambda message, urn: violations.append(message),
    )
    assert bool(violations) is denied
    assert not violations or "GOV030" in violations[0]


@pytest.mark.parametrize("fault", ["missing", "unknown", "revision", "digest", "extra", "boolean"])
def test_missing_or_mismatched_profile_context_fails_closed(fault):
    settings = governance._profile_settings(_profile("oci-free"))
    if fault == "unknown":
        settings["id"] = "gcp-free"
    elif fault == "revision":
        settings["revision"] += 1
    elif fault == "boolean":
        settings["revision"] = True
    elif fault == "digest":
        settings["sha256"] = "0" * 64
    elif fault == "extra":
        settings["capacity"] = {"ocpus": 100}
    violations = []
    governance.validate_profiled_resource(
        SimpleNamespace(
            resource_type="infrastructure:oci:Network",
            props={},
            get_config=lambda: {} if fault == "missing" else {"ociProfile": settings},
        ),
        lambda message, urn: violations.append(message),
    )
    assert any("GOV031" in message for message in violations)


def test_policy_configuration_requires_independent_account_selection():
    profile = _profile("oci-free")
    for account in (
        {},
        {"profile": "oci-paid-a1", "profile_revision": 1},
        {"profile": "oci-free", "profile_revision": 99},
    ):
        with pytest.raises(ValueError, match="GOV031"):
            governance.policy_configuration(account, profile)


def test_rehashed_profile_with_raised_limits_is_rejected():
    profile = _profile("oci-free")
    profile["capacity"]["ocpus"] = 100
    settings = governance._profile_settings(profile)
    violations = []
    governance.validate_profiled_resource(
        SimpleNamespace(
            resource_type="infrastructure:oci:Network",
            props={},
            get_config=lambda: {"ociProfile": settings},
        ),
        lambda message, urn: violations.append(message),
    )
    assert any("GOV031" in message for message in violations)
