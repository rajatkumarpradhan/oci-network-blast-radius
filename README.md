# oci-network-blast-radius

Offline review of an OCI-style network layout: which instances can the internet reach, and if one of them were compromised, how far could an attacker move according to the modeled security rules?

**Scope, stated plainly.** This is a portfolio project. It runs on a *simplified JSON model* and one synthetic example. It has not been run against a real tenancy, does not call any OCI API, and spends nothing. Findings are rule-level review priorities, not confirmed vulnerabilities.

## What it does

- Loads a simplified network model: subnets, route tables, gateways (igw / nat / lpg / drg), security lists, NSGs, instances.
- Validates references (unknown gateways, IPs outside their subnet, bad CIDRs or port ranges fail loudly).
- Builds a directed "permitted flow" graph between instances: an egress rule at the source plus an ingress rule at the destination, with port-interval intersection and routing checks (cross-VCN needs an lpg/drg route both ways).
- Computes the blast radius of each internet-reachable instance by breadth-first search, with hop counts.
- Reports findings:

| Rule | Meaning |
|---|---|
| BR001 | Internet-routed instance accepts world-open ingress (high for ssh/rdp/db ports, else medium) |
| BR002 | Internet-routed instance accepts all TCP/UDP ports from 0.0.0.0/0 |
| BR003 | Lateral reach from an internet-exposed instance (high if a `sensitivity=high` instance is reachable) |
| BR005 | High-sensitivity instance has a modeled outbound path to 0.0.0.0/0 |
| BR006 | Security list allows all protocols from a broad private range (/16 or wider) |
| BR007 | Stateless rule present; return traffic is not modeled |
| BR008 | Instance has a modeled path to OCI services via a service gateway (informational; not internet exposure) |

## Converting an OCI-style export

`examples/oci-export.json` is an OCI-shaped network export (VCN, internet/NAT/service gateways, route tables, security lists with protocol numbers and port ranges, NSGs with NSG-to-NSG rules, subnets, VNICs). The adapter converts it to the simplified model offline - no OCI credentials, SDK, or tenancy are involved; the input is a local JSON file you supply.

```
python -m oci_blast_radius.cli convert examples/oci-export.json --output model.json
python -m oci_blast_radius.cli model.json --output report.json
```

Mapping notes:

- Protocol numbers 6/17/1/`all` map to tcp/udp/icmp/all; `tcp-options`/`udp-options` destination port ranges become port spans.
- `source-type`/`destination-type` `CIDR_BLOCK` -> `cidr`, `NETWORK_SECURITY_GROUP` -> `nsg`, `SERVICE_CIDR_BLOCK` -> `service`.
- Each rule must name exactly one peer (cidr, NSG, or service CIDR); anything else is rejected with a clear error.
- Unknown gateway, NSG, subnet, or security-list references fail loudly instead of being silently dropped.
- A service-gateway route plus a service-CIDR egress rule is reported as a service-gateway path (BR008), which is not internet exposure.

## Usage

```
python -m pip install -e .
oci-blast-radius examples/synthetic.json --output report.json
oci-blast-radius examples/synthetic.json --fail-on-high   # exit code 2 on any high finding
python -m unittest discover -s tests -v
```

Example output on the synthetic model:

```
[HIGH  ] BR001 web-1: web-1 permits internet ingress on admin/data ports: 22/ssh.
[HIGH  ] BR003 web-1: ... lateral reach to 3 of 3 other instances (max 2 hops). Includes high-sensitivity: db-1.
[MEDIUM] BR005 db-1: db-1 (high sensitivity) has a modeled outbound path to 0.0.0.0/0 ...
```

## Modeling assumptions and limits

- Effective rules for an instance are the union of its subnet security lists and its NSGs.
- A rule that says a port is permitted does not mean a service listens there.
- Lateral movement is an over-approximation: any permitted port counts as a pivot.
- Stateless rules are treated as allowing the direction they are on; return traffic is not checked (BR007 flags them).
- Internet ingress is modeled only for a public IP in a public subnet with an internet-gateway route and a world-open CIDR rule. NSG-sourced rules and service gateways are not treated as internet paths.
- IPv4 only. No DRG route distribution, no load balancers, no network firewall, no OS-level firewalls.
- The export adapter consumes a local OCI-style JSON file (`examples/oci-export.json` shows the shape). Fetching that file from a real tenancy is out of scope here: no OCI credentials are used and nothing in this repo talks to OCI.

## Tests

24 unit tests cover model validation, interval maths, NSG-source rules, cross-VCN routing, exposure logic, each finding rule and the CLI. CI runs them on Python 3.10, 3.11 and 3.12 and runs a CLI smoke test.

## License

MIT
