"""Mutation tests establish that policy sensors reject architectural regressions."""

import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from policy import check, load  # noqa: E402


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.docs = {p.name: load(p) for p in (ROOT / "terraform/01-infrastructure").glob("*.tf")}
        self.baseline = json.loads((ROOT / "tests/public_ingress_baseline.json").read_text())

    def resource(self, kind):
        return next(
            body
            for doc in self.docs.values()
            for group in doc.get("resource", [])
            for resource_type, named in group.items()
            if resource_type == kind
            for body in named.values()
        )

    def rejects(self, rule):
        self.assertTrue(any(e.startswith(rule + ":") for e in check(self.docs, self.baseline)))

    def test_repository_baseline(self):
        self.assertEqual(check(self.docs, self.baseline), [])

    def test_paid_cluster(self):
        self.resource("oci_containerengine_cluster")["type"] = "ENHANCED_CLUSTER"
        self.rejects("COST001")

    def test_aggregate_capacity(self):
        self.resource("oci_containerengine_node_pool")["node_config_details"][0]["size"] = 5
        self.rejects("COST004")

    def test_multiple_pools_aggregate(self):
        pool = copy.deepcopy(self.resource("oci_containerengine_node_pool"))
        self.docs["oke.tf"]["resource"].append({"oci_containerengine_node_pool": {"extra": pool}})
        self.rejects("COST004")

    def test_expression_capacity_fails_closed(self):
        self.resource("oci_containerengine_node_pool")["node_config_details"][0]["size"] = (
            "${var.n}"
        )
        self.rejects("COST003")

    def test_resource_multiplication(self):
        self.resource("oci_containerengine_node_pool")["count"] = 2
        self.rejects("ARCH007")

    def test_wrong_shape(self):
        self.resource("oci_containerengine_node_pool")["node_shape"] = "VM.Standard.E4.Flex"
        self.rejects("COST002")

    def test_unknown_resource(self):
        self.docs["oke.tf"]["resource"].append({"oci_core_nat_gateway": {"paid": {}}})
        self.rejects("ARCH006")

    def test_network_cannot_depend_on_cluster(self):
        self.docs["vcn.tf"]["locals"][0]["invalid"] = (
            "${oci_containerengine_cluster.oke_cluster.id}"
        )
        self.rejects("ARCH005")

    def test_backend_duplication(self):
        self.docs["main.tf"]["terraform"][0]["backend"] = [{"local": {}}]
        self.rejects("ARCH003")

    def test_provisioner(self):
        self.resource("oci_containerengine_cluster")["provisioner"] = [{"local-exec": {}}]
        self.rejects("ARCH003")

    def test_subnet_overlap(self):
        self.resource("oci_core_subnet")["cidr_block"] = "10.0.0.0/16"
        self.rejects("NET002")

    def test_new_public_ingress(self):
        self.docs["vcn.tf"]["resource"].append(
            {
                "oci_core_network_security_group_security_rule": {
                    "unreviewed": {"direction": "INGRESS", "source": "0.0.0.0/0", "protocol": "all"}
                }
            }
        )
        self.rejects("NET003")

    def test_changed_public_ingress(self):
        for group in self.docs["vcn.tf"]["resource"]:
            rule = group.get("oci_core_network_security_group_security_rule", {}).get(
                "api_ingress_public_6443"
            )
            if rule:
                rule["protocol"] = "all"
        self.rejects("NET003")

    def test_secret_output(self):
        self.docs["outputs.tf"]["output"].append({"bad": {"value": "${var.private_key}"}})
        self.rejects("SECRET001")


if __name__ == "__main__":
    unittest.main()
