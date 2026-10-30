"""Adapter: map a local OCI-style network export onto the simplified model.

Input is an OFFLINE JSON file shaped like OCI list-command output subsets -
no OCI SDK calls, no live tenancy. Supported sections (all optional, but
references must resolve): internet-gateways, nat-gateways, service-gateways,
local-peering-gateways, route-tables, security-lists, network-security-groups,
nsg-rules, subnets, vnics, vcns.

Field names follow the OCI API (cidr-block, route-rules, network-entity-id,
ingress-security-rules, source-type, ...). Protocol numbers 6/17/1 map to
tcp/udp/icmp; "all" stays all. Source/destination types CIDR_BLOCK,
NETWORK_SECURITY_GROUP and SERVICE_CIDR_BLOCK map to cidr / nsg / service
peers. Anything else is rejected with a clear error, never guessed.
"""
from __future__ import annotations

import ipaddress

from .model import ModelError

_PROTOCOLS = {"6": "tcp", "17": "udp", "1": "icmp", "all": "all", "tcp": "tcp", "udp": "udp", "icmp": "icmp"}
_GATEWAY_SECTIONS = {
    "internet-gateways": "igw",
    "nat-gateways": "nat",
    "service-gateways": "sgw",
    "local-peering-gateways": "lpg",
}


def _need(obj: dict, key: str, where: str):
    v = obj.get(key)
    if v is None or (isinstance(v, str) and not v.strip()):
        raise ModelError(f"{where}: missing {key}")
    return v


def _port_range(rule: dict, where: str) -> list[int] | None:
    for opt_key in ("tcp-options", "udp-options"):
        opts = rule.get(opt_key)
        if not opts:
            continue
        rng = opts.get("destination-port-range")
        if rng is None:
            return None
        lo, hi = rng.get("min"), rng.get("max")
        if not isinstance(lo, int) or not isinstance(hi, int) or not (0 <= lo <= hi <= 65535):
            raise ModelError(f"{where}: bad {opt_key} destination-port-range {rng!r}")
        return [lo, hi]
    return None


def _peer(rule: dict, direction: str, where: str) -> dict:
    """Map source/destination + type onto cidr / nsg / service peer keys."""
    if direction == "ingress":
        value, vtype = rule.get("source"), rule.get("source-type", "CIDR_BLOCK")
    else:
        value, vtype = rule.get("destination"), rule.get("destination-type", "CIDR_BLOCK")
    if not value or not isinstance(value, str):
        raise ModelError(f"{where}: missing {'source' if direction == 'ingress' else 'destination'}")
    if vtype == "CIDR_BLOCK":
        try:
            ipaddress.ip_network(value)
        except ValueError as e:
            raise ModelError(f"{where}: bad CIDR {value!r}") from e
        return {"cidr": value}
    if vtype == "NETWORK_SECURITY_GROUP":
        return {"nsg": value}
    if vtype == "SERVICE_CIDR_BLOCK":
        return {"service": value}
    raise ModelError(f"{where}: unsupported {'source' if direction == 'ingress' else 'destination'}-type {vtype!r}")


def _rules(raw_rules, direction: str, where: str) -> list[dict]:
    out = []
    for i, r in enumerate(raw_rules or [], 1):
        w = f"{where} rule {i}"
        proto_raw = str(r.get("protocol", "all"))
        if proto_raw not in _PROTOCOLS:
            raise ModelError(f"{w}: unsupported protocol {proto_raw!r} (use 6/17/1/all)")
        proto = _PROTOCOLS[proto_raw]
        entry = {"direction": direction, "protocol": proto,
                 **_peer(r, direction, w)}
        ports = _port_range(r, w)
        if ports is not None and proto in ("tcp", "udp"):
            entry["ports"] = ports
        if r.get("stateless"):
            entry["stateless"] = True
        out.append(entry)
    return out


def convert(export: dict) -> dict:
    """Convert an OCI-style export dict to the simplified model dict."""
    if not isinstance(export, dict):
        raise ModelError("export must be a JSON object")
    model = {"gateways": [], "route_tables": [], "security_lists": [], "nsgs": [],
             "subnets": [], "instances": []}

    for section, gtype in _GATEWAY_SECTIONS.items():
        for g in export.get(section, []) or []:
            gid = _need(g, "id", section)
            model["gateways"].append({"id": gid, "type": gtype})

    for g in export.get("drgs", []) or []:
        gid = _need(g, "id", "drgs")
        model["gateways"].append({
            "id": gid, "type": "drg",
            "attachments": list(g.get("attachments", []) or []),
            "propagations": [dict(pr) for pr in (g.get("propagations", []) or [])],
        })

    for rt in export.get("route-tables", []) or []:
        rid = _need(rt, "id", "route-tables")
        routes = []
        for j, rule in enumerate(rt.get("route-rules", []) or [], 1):
            dest = rule.get("destination", rule.get("cidr-block"))
            target = rule.get("network-entity-id")
            if not dest or not target:
                raise ModelError(f"route table {rid} rule {j}: needs destination and network-entity-id")
            routes.append({"cidr": dest, "target": target})
        model["route_tables"].append({"id": rid, "routes": routes})

    for sl in export.get("security-lists", []) or []:
        sid = _need(sl, "id", "security-lists")
        rules = _rules(sl.get("ingress-security-rules"), "ingress", f"security list {sid}") + \
                _rules(sl.get("egress-security-rules"), "egress", f"security list {sid}")
        model["security_lists"].append({"id": sid, "rules": rules})

    nsg_ids = [_need(n, "id", "network-security-groups") for n in export.get("network-security-groups", []) or []]
    rules_by_nsg: dict[str, list[dict]] = {n: [] for n in nsg_ids}
    for i, r in enumerate(export.get("nsg-rules", []) or [], 1):
        nid = r.get("nsg-id")
        if nid not in rules_by_nsg:
            raise ModelError(f"nsg-rules entry {i}: unknown nsg-id {nid!r}")
        direction = r.get("direction")
        if isinstance(direction, str):
            direction = direction.lower()
        if direction not in ("ingress", "egress"):
            raise ModelError(f"nsg-rules entry {i}: direction must be ingress or egress")
        rules_by_nsg[nid].extend(_rules([r], direction, f"nsg {nid}"))
    for nid in nsg_ids:
        model["nsgs"].append({"id": nid, "rules": rules_by_nsg[nid]})

    for s in export.get("subnets", []) or []:
        sid = _need(s, "id", "subnets")
        model["subnets"].append({
            "id": sid,
            "name": s.get("display-name", sid),
            "cidr": _need(s, "cidr-block", f"subnet {sid}"),
            "public": not bool(s.get("prohibit-public-ip-on-vnic", False)),
            "route_table": _need(s, "route-table-id", f"subnet {sid}"),
            "security_lists": list(s.get("security-list-ids", [])),
            "vcn": s.get("vcn-id", "vcn-main"),
        })

    for v in export.get("vnics", []) or []:
        vid = _need(v, "id", "vnics")
        model["instances"].append({
            "id": vid,
            "name": v.get("display-name", vid),
            "subnet": _need(v, "subnet-id", f"vnic {vid}"),
            "ip": _need(v, "private-ip", f"vnic {vid}"),
            "public_ip": bool(v.get("public-ip")),
            "nsgs": list(v.get("nsg-ids", [])),
            "tags": dict(v.get("freeform-tags", {})),
        })
    return model


def convert_file(path: str) -> dict:
    import json
    with open(path, encoding="utf-8") as f:
        return convert(json.load(f))
