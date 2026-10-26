"""Configured-key authentication, DSSE interoperability and trust-policy regressions."""

import base64
import json
import tomllib
from copy import deepcopy

import pytest
import test_cutover as fixtures
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from infra_core import cutover
from infra_core.cutover_evidence import REPORTS
from infra_core.review_signatures import (
    MAX_POLICY_BYTES,
    MAX_SIGNATURE_BYTES,
    parse_policy,
    preauth,
    verify_review,
)

review = fixtures.review


def policy_bytes(data):
    values = {key: value for key, value in data.items() if key != "reviewers"}
    result = fixtures.table("policy", values).removeprefix("[policy]\n")
    if not data["reviewers"]:
        return (result + "reviewers = []\n").encode()
    return (
        result
        + "".join(
            fixtures.table("reviewers", item).replace("[reviewers]", "[[reviewers]]")
            for item in data["reviewers"]
        )
    ).encode()


def test_pae_uses_the_specified_domain_and_byte_lengths():
    assert preauth(b"hello") == b"DSSEv1 28 application/vnd.in-toto+json 5 hello"
    assert preauth("\u00e9".encode()) == b"DSSEv1 28 application/vnd.in-toto+json 2 \xc3\xa9"


@pytest.mark.parametrize("role", sorted(REPORTS))
@pytest.mark.parametrize("fault", ["missing", "alias", "oversize", "unsigned"])
def test_signatures_are_mandatory_bounded_and_distinct(review, role, fault):
    root, document, _, write = review
    name = role + "_signature"
    if fault == "missing":
        document["artifacts"].pop(name)
    elif fault == "alias":
        document["artifacts"][name] = document["artifacts"][role + "_envelope"]
    elif fault == "oversize":
        write(name, b" " * (MAX_SIGNATURE_BYTES + 1), rebind=False)
    else:
        write(name, b"{}", rebind=False)
    with pytest.raises(ValueError, match="GOV003|CUT002|CUT010"):
        cutover.check(root, document)


@pytest.mark.parametrize(
    "fault", ["signature", "payload", "type", "key", "role", "extra", "duplicate", "encoding"]
)
def test_matching_outer_hashes_do_not_authenticate_forged_dsse(review, fault):
    root, document, artifacts, write = review
    name = "health_signature"
    value = json.loads(artifacts[name])
    if fault == "signature":
        value["signatures"][0]["sig"] = base64.b64encode(b"x" * 64).decode()
    elif fault == "payload":
        value["payload"] = base64.b64encode(b"other").decode()
    elif fault == "type":
        value["payloadType"] = "application/json"
    elif fault == "key":
        value = json.loads(
            fixtures.sign_review(Ed25519PrivateKey.generate(), artifacts["health_envelope"])
        )
    elif fault == "role":
        value = json.loads(artifacts["preview_signature"])
    elif fault == "extra":
        value["signatures"].append(deepcopy(value["signatures"][0]))
    elif fault == "encoding":
        value["signatures"][0]["sig"] = "PRIVATE!"
    encoded = json.dumps(value).encode()
    if fault == "duplicate":
        encoded = b'{"payloadType":"other",' + encoded[1:]
    write(name, encoded, rebind=False)
    with pytest.raises(ValueError, match="CUT010") as error:
        cutover.check(root, document)
    assert "PRIVATE" not in str(error.value)


@pytest.mark.parametrize("hint", [None, "another-reviewer"])
@pytest.mark.parametrize("urlsafe", [False, True])
def test_base64_variants_and_untrusted_keyid_never_select_reviewer_identity(review, urlsafe, hint):
    root, document, artifacts, write = review
    value = json.loads(artifacts["health_signature"])
    encode = base64.urlsafe_b64encode if urlsafe else base64.b64encode
    value["payload"] = encode(artifacts["health_envelope"]).decode()
    value["signatures"][0]["sig"] = encode(base64.b64decode(value["signatures"][0]["sig"])).decode()
    if hint is None:
        value["signatures"][0].pop("keyid")
    else:
        value["signatures"][0]["keyid"] = hint
    write("health_signature", json.dumps(value).encode(), rebind=False)
    reviewers = parse_policy((root / "config/cutover-reviewers.toml").read_bytes())
    assert (
        verify_review("health", artifacts["health_envelope"], json.dumps(value).encode(), reviewers)
        == "synthetic-reviewer"
    )
    assert cutover.check(root, document)["cutover_authorized"] is False
    artifacts["health"]["reviewed_by"] = "another-reviewer"
    write("health", artifacts["health"])
    with pytest.raises(ValueError, match="CUT010"):
        cutover.check(root, document)


@pytest.mark.parametrize(
    "fault",
    ["disabled", "empty", "version", "extra", "key-size", "duplicate-key", "role", "principal"],
)
def test_trust_policy_is_closed_enabled_and_unambiguous(review, fault):
    root, _, _, _ = review
    data = tomllib.loads((root / "config/cutover-reviewers.toml").read_text())
    if fault == "disabled":
        data["enabled"] = False
    elif fault == "empty":
        data["reviewers"] = []
    elif fault == "version":
        data["schema_version"] = True
    elif fault == "extra":
        data["extra"] = "PRIVATE"
    elif fault == "key-size":
        data["reviewers"][0]["public_key"] = base64.b64encode(b"x" * 31).decode()
    elif fault == "duplicate-key":
        data["reviewers"].append(deepcopy(data["reviewers"][0]))
        data["reviewers"][1]["principal"] = "another-reviewer"
    elif fault == "role":
        data["reviewers"][0]["roles"] = ["admin"]
    else:
        data["reviewers"][0]["principal"] = "PRIVATE\ninvalid"
    with pytest.raises(ValueError, match="CUT009") as error:
        parse_policy(policy_bytes(data))
    assert "PRIVATE" not in str(error.value)


@pytest.mark.parametrize("fault", ["missing", "oversize", "role-permission", "rotation"])
def test_current_policy_is_required_and_authorizes_the_verified_key_for_the_role(review, fault):
    root, document, artifacts, write = review
    path = root / "config/cutover-reviewers.toml"
    code = "CUT010"
    if fault == "missing":
        path.unlink()
        code = "CUT009"
    elif fault == "oversize":
        path.write_bytes(b" " * (MAX_POLICY_BYTES + 1))
        code = "CUT002"
    else:
        data = tomllib.loads(path.read_text())
        if fault == "role-permission":
            data["reviewers"][0]["roles"].remove("health")
        else:
            data["reviewers"][0]["public_key"] = base64.b64encode(
                Ed25519PrivateKey.generate().public_key().public_bytes_raw()
            ).decode()
        path.write_bytes(policy_bytes(data))
        # Rebind/re-sign all subjects using the original test key; policy must still deny it.
        write("health", artifacts["health"])
    with pytest.raises(ValueError, match=code):
        cutover.check(root, document)


def test_policy_byte_changes_invalidate_old_bindings_even_when_keys_are_unchanged(review):
    root, document, _, _ = review
    path = root / "config/cutover-reviewers.toml"
    path.write_bytes(path.read_bytes() + b"\n# rotation review\n")
    with pytest.raises(ValueError, match="EVID002"):
        cutover.check(root, document)
