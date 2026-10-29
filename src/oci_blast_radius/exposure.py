"""Internet exposure and egress checks."""
from __future__ import annotations

import ipaddress

from .model import Instance, Model
from .reach import _merge, effective_rules

WORLD = ipaddress.ip_network("0.0.0.0/0")
SENSITIVE_PORTS = {22: "ssh", 3389: "rdp", 3306: "mysql", 5432: "postgres", 1521: "oracle-db",
                   1433: "mssql", 6379: "redis", 27017: "mongodb", 9200: "elasticsearch"}


def _has_route(m: Model, inst: Instance, kinds) -> bool:
    for r in m.route_tables[m.subnets[inst.subnet].route_table]:
        if m.gateways[r["target"]].get("type") in kinds and \
                WORLD.subnet_of(ipaddress.ip_network(r["cidr"])):
            return True
    return False


def internet_reachable(m: Model, inst: Instance) -> bool:
    """Inbound internet path is modeled only for a public IP on a public subnet routed to an igw."""
    sn = m.subnets[inst.subnet]
    return inst.public_ip and sn.public and _has_route(m, inst, ("igw",))


def world_open_ingress(m: Model, inst: Instance) -> dict[str, list[tuple[int, int]]]:
    """Ports open to 0.0.0.0/0 (cidr rules only; NSG-sourced rules are ignored)."""
    out: dict[str, list[tuple[int, int]]] = {}
    from .reach import _rule_spans
    for rule, _ in effective_rules(m, inst):
        if rule.direction != "ingress" or rule.cidr is None:
            continue
        if ipaddress.ip_network(rule.cidr).prefixlen != 0:
            continue
        for p, iv in _rule_spans(rule).items():
            out.setdefault(p, []).extend(iv)
    return {p: _merge(iv) for p, iv in out.items()}


def sensitive_ports_hit(spans: dict[str, list[tuple[int, int]]]) -> list[int]:
    hit = []
    for port in SENSITIVE_PORTS:
        for lo, hi in spans.get("tcp", []):
            if lo <= port <= hi:
                hit.append(port)
                break
    return hit


def egress_to_internet(m: Model, inst: Instance) -> bool:
    if not _has_route(m, inst, ("igw", "nat")):
        return False
    if _has_route(m, inst, ("igw",)) and not (inst.public_ip and m.subnets[inst.subnet].public):
        # igw route without a public IP does not give a usable path
        if not _has_route(m, inst, ("nat",)):
            return False
    for rule, _ in effective_rules(m, inst):
        if rule.direction == "egress" and rule.cidr and ipaddress.ip_network(rule.cidr).prefixlen == 0:
            return True
    return False


def egress_to_oci_services(m: Model, inst: Instance) -> bool:
    """Service-gateway path: route to an sgw plus a service-CIDR egress rule.

    This is a path to OCI services (e.g. Object Storage), NOT internet
    exposure; findings surface it separately as informational.
    """
    has_sgw_route = False
    for r in m.route_tables[m.subnets[inst.subnet].route_table]:
        if m.gateways[r["target"]].get("type") == "sgw":
            has_sgw_route = True
            break
    if not has_sgw_route:
        return False
    for rule, _ in effective_rules(m, inst):
        if rule.direction == "egress" and rule.service:
            return True
    return False
