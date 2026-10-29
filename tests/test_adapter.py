"""Adapter tests: OCI-style export -> simplified model, service gateway paths, NSG-to-NSG."""
import json
import tempfile
import unittest
from pathlib import Path

from oci_blast_radius import adapter, exposure, findings, model, reach
from oci_blast_radius.cli import main

ROOT = Path(__file__).resolve().parents[1]


def load_example():
    return model.load(adapter.convert(json.loads((ROOT / "examples" / "oci-export.json").read_text())))


class AdapterMappingTests(unittest.TestCase):
    def test_example_converts_and_loads(self):
        m = load_example()
        self.assertEqual(len(m.instances), 3)
        self.assertEqual(len(m.subnets), 2)
        self.assertIn("ocid1.servicegateway.oc1..sgw", m.gateways)
        self.assertEqual(m.gateways["ocid1.servicegateway.oc1..sgw"]["type"], "sgw")

    def test_protocol_numbers_and_port_ranges(self):
        m = load_example()
        web_rules = m.security_lists["ocid1.securitylist.oc1..slweb"]
        self.assertEqual(web_rules[0].protocol, "tcp")
        self.assertEqual(web_rules[0].ports, (443, 443))

    def test_nsg_to_nsg_path_maps_and_flows(self):
        m = load_example()
        db_rules = m.nsgs["ocid1.networksecuritygroup.oc1..nsgdb"]
        self.assertEqual(db_rules[0].nsg, "ocid1.networksecuritygroup.oc1..nsgapp")
        app, db = m.instances["ocid1.vnic.oc1..app1"], m.instances["ocid1.vnic.oc1..db1"]
        e = reach.edge(m, app, db)
        self.assertIsNotNone(e)
        self.assertIn(("tcp", ((1521, 1521),)), e.spans)
        # reverse direction has no rules -> no edge
        self.assertIsNone(reach.edge(m, db, app))

    def test_service_gateway_is_not_internet_exposure(self):
        m = load_example()
        app = m.instances["ocid1.vnic.oc1..app1"]
        self.assertFalse(exposure.internet_reachable(m, app))
        # NAT egress to 0.0.0.0/0 exists in this export and stays flagged as internet egress;
        # the service-gateway path is classified separately and never counts as exposure.
        self.assertTrue(exposure.egress_to_internet(m, app))
        self.assertTrue(exposure.egress_to_oci_services(m, app))
        s = findings.summary(m)
        # app-1 and db-1 share the app subnet + security list with the service egress rule
        self.assertEqual(s["service_gateway_paths"], ["ocid1.vnic.oc1..app1", "ocid1.vnic.oc1..db1"])
        self.assertEqual(s["internet_reachable"], ["ocid1.vnic.oc1..web1"])
        br008 = [f for f in findings.analyze(m) if f.rule == "BR008"]
        self.assertEqual(len(br008), 2)
        self.assertTrue(all("not internet exposure" in f.message for f in br008))

    def test_service_rule_maps_to_service_peer(self):
        m = load_example()
        app_rules = m.security_lists["ocid1.securitylist.oc1..slapp"]
        svc = [r for r in app_rules if r.service]
        self.assertEqual(len(svc), 1)
        self.assertEqual(svc[0].service, "all-bom-services-in-oracle-services-network")


class AdapterValidationTests(unittest.TestCase):
    def _convert(self, export):
        return model.load(adapter.convert(export))

    def test_unknown_gateway_reference(self):
        m = load_example()
        bad = json.loads((ROOT / "examples" / "oci-export.json").read_text())
        bad["service-gateways"] = []
        with self.assertRaises(model.ModelError):
            self._convert(bad)

    def test_unknown_nsg_rule_target(self):
        bad = json.loads((ROOT / "examples" / "oci-export.json").read_text())
        bad["nsg-rules"][0]["nsg-id"] = "ocid1.networksecuritygroup.oc1..missing"
        with self.assertRaises(model.ModelError):
            self._convert(bad)

    def test_malformed_rule_rejected(self):
        bad = json.loads((ROOT / "examples" / "oci-export.json").read_text())
        bad["security-lists"][0]["ingress-security-rules"][0]["protocol"] = "47"
        with self.assertRaises(model.ModelError):
            self._convert(bad)
        bad2 = json.loads((ROOT / "examples" / "oci-export.json").read_text())
        bad2["security-lists"][0]["ingress-security-rules"][0]["source-type"] = "GUESS_ME"
        with self.assertRaises(model.ModelError):
            self._convert(bad2)

    def test_partial_export_missing_sections(self):
        partial = {"subnets": [], "vnics": []}
        out = adapter.convert(partial)
        self.assertEqual(out["instances"], [])
        # missing source on a rule still errors clearly
        broken = {"security-lists": [{"id": "sl", "ingress-security-rules": [{"protocol": "6"}]}]}
        with self.assertRaises(model.ModelError):
            adapter.convert(broken)

    def test_convert_cli(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "model.json"
            self.assertEqual(main(["convert", str(ROOT / "examples" / "oci-export.json"), "--output", str(out)]), 0)
            converted = json.loads(out.read_text())
            m = model.load(converted)
            self.assertEqual(len(m.instances), 3)
            # converted model then analyzes end to end
            self.assertEqual(main([str(out), "--output", str(Path(d) / "report.json")]), 0)

    def test_convert_cli_bad_input(self):
        with tempfile.TemporaryDirectory() as d:
            bad = Path(d) / "bad.json"
            bad.write_text('{"security-lists": [{"id": "sl", "ingress-security-rules": [{"protocol": "6"}]}]}')
            self.assertEqual(main(["convert", str(bad)]), 1)


class BaselineUnchangedTests(unittest.TestCase):
    def test_synthetic_example_still_baseline(self):
        m = model.load_file(str(ROOT / "examples" / "synthetic.json"))
        s = findings.summary(m)
        self.assertEqual(s["edges"], 7)
        self.assertEqual(s["internet_reachable"], ["web-1"])
        self.assertEqual(s["service_gateway_paths"], [])


if __name__ == "__main__":
    unittest.main()
