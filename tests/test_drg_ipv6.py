"""DRG route distribution, IPv6 rules/routes, and stateless return-path checks."""
import copy
import json
import unittest
from pathlib import Path

from oci_blast_radius import adapter, exposure, findings, model, reach

ROOT = Path(__file__).resolve().parents[1]


def load_drg():
    return model.load_file(str(ROOT / "examples" / "drg-ipv6.json"))


class IPv6Tests(unittest.TestCase):
    def test_ipv6_model_loads_and_versions_never_match(self):
        m = load_drg()
        edge_c = m.instances["edge-c"]
        self.assertEqual(edge_c.ip, "fd00:1::10")
        # a v4 rule cidr never matches a v6 peer and vice versa (no TypeError, no match)
        v4_rule = model.Rule("ingress", "tcp", cidr="0.0.0.0/0")
        v6_rule = model.Rule("ingress", "tcp", cidr="::/0")
        v4_inst = m.instances["app-a"]
        self.assertFalse(reach._peer_matches(m, v4_rule, edge_c))
        self.assertFalse(reach._peer_matches(m, v6_rule, v4_inst))
        self.assertTrue(reach._peer_matches(m, v6_rule, edge_c))

    def test_ipv6_world_route_and_ingress_flagged(self):
        m = load_drg()
        edge_c = m.instances["edge-c"]
        self.assertTrue(exposure.internet_reachable(m, edge_c))
        wo = exposure.world_open_ingress(m, edge_c)
        self.assertEqual(wo.get("tcp"), [(443, 443)])
        br001 = [f for f in findings.analyze(m) if f.rule == "BR001" and f.subject == "edge-c"]
        self.assertEqual(len(br001), 1)

    def test_v4_route_does_not_cover_v6_world(self):
        # a 0.0.0.0/0 route must not count as a v6 internet route
        d = json.loads((ROOT / "examples" / "drg-ipv6.json").read_text())
        d["route_tables"][2]["routes"] = [{"cidr": "0.0.0.0/0", "target": "igw-c"}]
        m = model.load(d)
        self.assertFalse(exposure.internet_reachable(m, m.instances["edge-c"]))


class DRGTests(unittest.TestCase):
    def test_propagated_drg_routes_allow_cross_vcn_edge(self):
        m = load_drg()
        e = reach.edge(m, m.instances["app-a"], m.instances["db-b"])
        self.assertIsNotNone(e)
        self.assertIn(("tcp", ((5432, 5432),)), e.spans)

    def test_missing_propagation_blocks_edge(self):
        d = json.loads((ROOT / "examples" / "drg-ipv6.json").read_text())
        d["gateways"][0]["propagations"] = [{"from": "vcn-b", "to": "vcn-a", "cidr": "10.2.0.0/16"}]
        m = model.load(d)
        # forward route exists (a->b propagated) but b->a return is not: no edge either way
        self.assertIsNone(reach.edge(m, m.instances["app-a"], m.instances["db-b"]))
        self.assertIsNone(reach.edge(m, m.instances["db-b"], m.instances["app-a"]))

    def test_no_propagations_at_all(self):
        d = json.loads((ROOT / "examples" / "drg-ipv6.json").read_text())
        d["gateways"][0]["propagations"] = []
        m = model.load(d)
        self.assertIsNone(reach.edge(m, m.instances["app-a"], m.instances["db-b"]))

    def test_propagation_endpoint_must_be_attachment(self):
        d = json.loads((ROOT / "examples" / "drg-ipv6.json").read_text())
        d["gateways"][0]["propagations"][0]["to"] = "vcn-nowhere"
        with self.assertRaises(model.ModelError):
            model.load(d)
        d = json.loads((ROOT / "examples" / "drg-ipv6.json").read_text())
        d["gateways"][0]["propagations"][0]["cidr"] = "10.9.0.0/99"
        with self.assertRaises(model.ModelError):
            model.load(d)

    def test_route_to_drg_requires_attachment(self):
        d = json.loads((ROOT / "examples" / "drg-ipv6.json").read_text())
        d["subnets"][0]["vcn"] = "vcn-unattached"
        with self.assertRaises(model.ModelError):
            model.load(d)

    def test_adapter_maps_drgs(self):
        export = {"drgs": [{"id": "ocid1.drg.oc1..d1", "attachments": ["vcn-a", "vcn-b"],
                            "propagations": [{"from": "vcn-a", "to": "vcn-b", "cidr": "10.1.0.0/16"}]}]}
        out = adapter.convert(export)
        drg = [g for g in out["gateways"] if g["type"] == "drg"][0]
        self.assertEqual(drg["attachments"], ["vcn-a", "vcn-b"])
        self.assertEqual(drg["propagations"][0]["cidr"], "10.1.0.0/16")


class StatelessReturnPathTests(unittest.TestCase):
    def test_stateless_forward_without_return_flagged(self):
        m = load_drg()
        br009 = [f for f in findings.analyze(m) if f.rule == "BR009"]
        self.assertEqual(len(br009), 1)
        self.assertEqual(br009[0].subject, "app-a")
        self.assertIn("db-b", br009[0].message)

    def test_return_rule_clears_br009(self):
        d = json.loads((ROOT / "examples" / "drg-ipv6.json").read_text())
        d["security_lists"][1]["rules"].append(
            {"direction": "egress", "protocol": "tcp", "cidr": "10.1.1.0/24", "stateless": True})
        d["security_lists"][0]["rules"].append(
            {"direction": "ingress", "protocol": "tcp", "cidr": "10.2.1.0/24", "stateless": True})
        m = model.load(d)
        self.assertIsNotNone(reach.edge(m, m.instances["db-b"], m.instances["app-a"]))
        self.assertEqual([f for f in findings.analyze(m) if f.rule == "BR009"], [])

    def test_stateful_flow_never_flagged(self):
        d = json.loads((ROOT / "examples" / "drg-ipv6.json").read_text())
        for r in d["security_lists"][0]["rules"] + d["security_lists"][1]["rules"]:
            r.pop("stateless", None)
        m = model.load(d)
        self.assertIsNotNone(reach.edge(m, m.instances["app-a"], m.instances["db-b"]))
        self.assertEqual([f for f in findings.analyze(m) if f.rule == "BR009"], [])


class BaselineUnchangedTests(unittest.TestCase):
    def test_synthetic_example_unchanged(self):
        m = model.load_file(str(ROOT / "examples" / "synthetic.json"))
        s = findings.summary(m)
        self.assertEqual(s["edges"], 7)
        self.assertEqual(s["internet_reachable"], ["web-1"])
        self.assertEqual([f for f in findings.analyze(m) if f.rule == "BR009"], [])


if __name__ == "__main__":
    unittest.main()
