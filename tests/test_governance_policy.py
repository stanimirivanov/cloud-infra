"""Mandatory policy enforcement with no provider plugins or cloud resources."""

import json
import os
import signal
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

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
            response = analyze("oci:ContainerEngine/nodePool:NodePool", pool)
            assert not response.diagnostics, response
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
