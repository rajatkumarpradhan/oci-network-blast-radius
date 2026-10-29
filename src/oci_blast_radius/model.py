"""Load and validate a simplified network export.

The input is a simplified JSON model, not the raw OCI API shape. See README.
"""
from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass, field


class ModelError(ValueError):
    pass


@dataclass
class Rule:
    direction: str            # "ingress" | "egress"
    protocol: str             # "tcp" | "udp" | "icmp" | "all"
    cidr: str | None = None   # peer CIDR
    nsg: str | None = None    # peer NSG id (NSG rules only)
    service: str | None = None  # OCI service CIDR label (service-gateway paths only)
    ports: tuple[int, int] | None = None  # None = all ports
    stateless: bool = False

    def covers_port(self, port: int) -> bool:
        return self.ports is None or self.ports[0] <= port <= self.ports[1]


@dataclass
class Subnet:
    id: str
    name: str
    cidr: str
    public: bool
    route_table: str
    security_lists: list[str]
    vcn: str = "vcn-main"


@dataclass
class Instance:
    id: str
    name: str
    subnet: str
    ip: str
    public_ip: bool = False
    nsgs: list[str] = field(default_factory=list)
    tags: dict = field(default_factory=dict)


@dataclass
class Model:
    subnets: dict[str, Subnet]
    instances: dict[str, Instance]
    route_tables: dict[str, list[dict]]
    security_lists: dict[str, list[Rule]]
    nsgs: dict[str, list[Rule]]
    gateways: dict[str, dict]


def _rule(raw: dict) -> Rule:
    d = raw.get("direction")
    if d not in ("ingress", "egress"):
        raise ModelError(f"bad rule direction: {raw!r}")
    proto = raw.get("protocol", "all")
    if proto not in ("tcp", "udp", "icmp", "all"):
        raise ModelError(f"bad protocol: {raw!r}")
    ports = None
    if "ports" in raw and raw["ports"] is not None:
        lo, hi = raw["ports"]
        if not (0 <= lo <= hi <= 65535):
            raise ModelError(f"bad port range: {raw!r}")
        ports = (lo, hi)
    cidr = raw.get("cidr")
    if cidr is not None:
        try:
            ipaddress.ip_network(cidr)
        except ValueError as e:
            raise ModelError(f"bad cidr {cidr!r}") from e
    service = raw.get("service")
    if service is not None and not str(service).strip():
        raise ModelError(f"empty service label: {raw!r}")
    kinds = sum(x is not None for x in (cidr, raw.get("nsg"), service))
    if kinds != 1:
        raise ModelError(f"rule needs exactly one of cidr, nsg or service: {raw!r}")
    return Rule(d, proto, cidr, raw.get("nsg"), service, ports, bool(raw.get("stateless", False)))


def load(data: dict) -> Model:
    try:
        gateways = {g["id"]: g for g in data.get("gateways", [])}
        route_tables = {r["id"]: r.get("routes", []) for r in data.get("route_tables", [])}
        sls = {s["id"]: [_rule(r) for r in s.get("rules", [])] for s in data.get("security_lists", [])}
        nsgs = {s["id"]: [_rule(r) for r in s.get("rules", [])] for s in data.get("nsgs", [])}
        subnets = {}
        for s in data.get("subnets", []):
            ipaddress.ip_network(s["cidr"])
            subnets[s["id"]] = Subnet(s["id"], s.get("name", s["id"]), s["cidr"],
                                      bool(s.get("public", False)), s["route_table"],
                                      list(s.get("security_lists", [])), s.get("vcn", "vcn-main"))
        instances = {}
        for i in data.get("instances", []):
            ipaddress.ip_address(i["ip"])
            instances[i["id"]] = Instance(i["id"], i.get("name", i["id"]), i["subnet"], i["ip"],
                                          bool(i.get("public_ip", False)), list(i.get("nsgs", [])),
                                          dict(i.get("tags", {})))
    except (KeyError, TypeError, ValueError) as e:
        if isinstance(e, ModelError):
            raise
        raise ModelError(f"invalid model: {e!r}") from e
    m = Model(subnets, instances, route_tables, sls, nsgs, gateways)
    _check_refs(m)
    return m


def _check_refs(m: Model) -> None:
    for s in m.subnets.values():
        if s.route_table not in m.route_tables:
            raise ModelError(f"subnet {s.id}: unknown route table {s.route_table}")
        for sl in s.security_lists:
            if sl not in m.security_lists:
                raise ModelError(f"subnet {s.id}: unknown security list {sl}")
    for i in m.instances.values():
        if i.subnet not in m.subnets:
            raise ModelError(f"instance {i.id}: unknown subnet {i.subnet}")
        sn = ipaddress.ip_network(m.subnets[i.subnet].cidr)
        if ipaddress.ip_address(i.ip) not in sn:
            raise ModelError(f"instance {i.id}: ip {i.ip} outside subnet {sn}")
        for n in i.nsgs:
            if n not in m.nsgs:
                raise ModelError(f"instance {i.id}: unknown nsg {n}")
    for rid, routes in m.route_tables.items():
        for r in routes:
            if r.get("target") not in m.gateways:
                raise ModelError(f"route table {rid}: unknown gateway {r.get('target')}")


def load_file(path: str) -> Model:
    with open(path, encoding="utf-8") as f:
        return load(json.load(f))
