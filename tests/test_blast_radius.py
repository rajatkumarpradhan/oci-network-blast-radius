import copy
import json
import os
import tempfile
import unittest

from oci_blast_radius import exposure, findings, model, reach
from oci_blast_radius.cli import main

HERE = os.path.dirname(__file__)
with open(os.path.join(HERE, "..", "examples", "synthetic.json"), encoding="utf-8") as f:
    BASE = json.load(f)


def load(mut=None):
    d = copy.deepcopy(BASE)
    if mut:
        mut(d)
    return model.load(d)


class ModelTests(unittest.TestCase):
    def test_loads(self):
        m = load()
        self.assertEqual(len(m.instances), 4)

    def test_ip_outside_subnet(self):
        def mut(d): d["instances"][0]["ip"] = "10.9.9.9"
        with self.assertRaises(model.ModelError):
            load(mut)

    def test_unknown_gateway(self):
        def mut(d): d["route_tables"][0]["routes"][0]["target"] = "nope"
        with self.assertRaises(model.ModelError):
            load(mut)

    def test_bad_port_range(self):
        def mut(d): d["security_lists"][0]["rules"][0]["ports"] = [500, 100]
        with self.assertRaises(model.ModelError):
            load(mut)

    def test_bad_cidr(self):
        def mut(d): d["security_lists"][0]["rules"][0]["cidr"] = "10.0.0.0/99"
        with self.assertRaises(model.ModelError):
            load(mut)


class ReachTests(unittest.TestCase):
    def test_edges_and_hops(self):
        m = load()
        g = reach.build_edges(m)
        dist = reach.blast_radius(m, "web-1", g)
        self.assertEqual(dist, {"app-1": 1, "app-2": 1, "db-1": 2})

    def test_db_not_directly_reachable_from_web(self):
        m = load()
        self.assertIsNone(reach.edge(m, m.instances["web-1"], m.instances["db-1"]))

    def test_port_intersection(self):
        m = load()
        e = reach.edge(m, m.instances["app-1"], m.instances["db-1"])
        self.assertEqual(reach.fmt_spans(e.spans), "tcp/1521")

    def test_missing_egress_blocks(self):
        def mut(d):
            d["security_lists"][1]["rules"] = [r for r in d["security_lists"][1]["rules"] if r["direction"] == "ingress"]
        m = load(mut)
        self.assertIsNone(reach.edge(m, m.instances["app-1"], m.instances["db-1"]))

    def test_nsg_source_rule(self):
        def mut(d):
            d["nsgs"] = [{"id": "nsg-a", "rules": [{"direction": "ingress", "protocol": "tcp", "nsg": "nsg-b", "ports": [9000, 9000]}]},
                         {"id": "nsg-b", "rules": []}]
            d["instances"][1]["nsgs"] = ["nsg-a"]
            d["instances"][2]["nsgs"] = ["nsg-b"]
        m = load(mut)
        e = reach.edge(m, m.instances["app-2"], m.instances["app-1"])
        self.assertIsNotNone(e)
        self.assertIn("tcp/9000", reach.fmt_spans(e.spans))

    def test_cross_vcn_needs_routes_both_ways(self):
        def mut(d):
            d["subnets"][2]["vcn"] = "vcn-b"
        m = load(mut)
        self.assertIsNone(reach.edge(m, m.instances["app-1"], m.instances["db-1"]))

        def mut2(d):
            mut(d)
            d["route_tables"][1]["routes"].append({"cidr": "10.0.3.0/24", "target": "lpg-ab"})
            d["route_tables"].append({"id": "rt-b", "routes": [{"cidr": "10.0.2.0/24", "target": "lpg-ab"}]})
            d["subnets"][2]["route_table"] = "rt-b"
        m2 = load(mut2)
        self.assertIsNotNone(reach.edge(m2, m2.instances["app-1"], m2.instances["db-1"]))

    def test_interval_merge(self):
        self.assertEqual(reach._merge([(1, 5), (6, 9), (20, 30)]), [(1, 9), (20, 30)])
        self.assertEqual(reach._intersect([(0, 10)], [(5, 20)]), [(5, 10)])


class ExposureTests(unittest.TestCase):
    def test_internet_reachable(self):
        m = load()
        self.assertTrue(exposure.internet_reachable(m, m.instances["web-1"]))
        self.assertFalse(exposure.internet_reachable(m, m.instances["app-1"]))

    def test_public_ip_without_igw_route_is_not_exposed(self):
        def mut(d): d["subnets"][0]["route_table"] = "rt-isolated"
        m = load(mut)
        self.assertFalse(exposure.internet_reachable(m, m.instances["web-1"]))

    def test_isolated_subnet_has_no_egress(self):
        def mut(d): d["subnets"][2]["route_table"] = "rt-isolated"
        m = load(mut)
        self.assertFalse(exposure.egress_to_internet(m, m.instances["db-1"]))


class FindingTests(unittest.TestCase):
    def rules(self, m):
        return [(f.rule, f.severity, f.subject) for f in findings.analyze(m)]

    def test_baseline(self):
        r = self.rules(load())
        self.assertIn(("BR001", "high", "web-1"), r)
        self.assertIn(("BR003", "high", "web-1"), r)
        self.assertIn(("BR005", "medium", "db-1"), r)

    def test_closing_ssh_drops_br001_high(self):
        def mut(d):
            d["security_lists"][0]["rules"] = [x for x in d["security_lists"][0]["rules"] if x.get("ports") != [22, 22]]
        r = self.rules(load(mut))
        self.assertNotIn(("BR001", "high", "web-1"), r)
        self.assertIn(("BR001", "medium", "web-1"), r)

    def test_all_ports_open(self):
        def mut(d):
            d["security_lists"][0]["rules"].append({"direction": "ingress", "protocol": "all", "cidr": "0.0.0.0/0"})
        r = self.rules(load(mut))
        self.assertIn(("BR002", "high", "web-1"), r)

    def test_no_internet_exposure_no_blast_findings(self):
        def mut(d): d["instances"][0]["public_ip"] = False
        r = self.rules(load(mut))
        self.assertFalse([x for x in r if x[0] in ("BR001", "BR002", "BR003")])

    def test_broad_all_protocol_and_stateless(self):
        def mut(d):
            d["security_lists"][2]["rules"].append({"direction": "ingress", "protocol": "all", "cidr": "10.0.0.0/8", "stateless": True})
        r = self.rules(load(mut))
        self.assertIn(("BR006", "low", "sl-db"), r)
        self.assertIn(("BR007", "low", "sl-db"), r)

    def test_sorted_by_severity(self):
        sev = [f.severity for f in findings.analyze(load())]
        self.assertEqual(sev, sorted(sev, key=findings.SEV_ORDER.get))


class CliTests(unittest.TestCase):
    def test_cli_report(self):
        with tempfile.TemporaryDirectory() as t:
            out = os.path.join(t, "r.json")
            rc = main([os.path.join(HERE, "..", "examples", "synthetic.json"), "--output", out])
            self.assertEqual(rc, 0)
            rep = json.load(open(out))
            self.assertEqual(rep["summary"]["internet_reachable"], ["web-1"])

    def test_fail_on_high(self):
        rc = main([os.path.join(HERE, "..", "examples", "synthetic.json"), "--fail-on-high"])
        self.assertEqual(rc, 2)

    def test_bad_input(self):
        self.assertEqual(main(["/nonexistent.json"]), 1)


if __name__ == "__main__":
    unittest.main()
