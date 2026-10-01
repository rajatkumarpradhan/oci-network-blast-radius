"""Rule-level reachability between instances in the simplified model.

Conservative semantics (documented in the README):
- An instance's effective rules are the union of its subnet security lists and its NSGs.
- A flow src->dst needs an egress rule at src and an ingress rule at dst.
- Same-VCN traffic routes locally. Cross-VCN traffic needs an lpg/drg route in both
  directions (src route to dst IP, dst route back to src IP).
- Stateless flags are recorded but treated as allowing the direction they are on.
- Rules say what is *permitted*; no claim is made that a service listens on a port.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from .model import Instance, Model, Rule

Intervals = dict  # proto -> list[(lo, hi)]
PROTOS = ("tcp", "udp", "icmp")
FULL = {"tcp": (0, 65535), "udp": (0, 65535), "icmp": (0, 0)}


def _merge(iv: list[tuple[int, int]]) -> list[tuple[int, int]]:
    out: list[tuple[int, int]] = []
    for lo, hi in sorted(iv):
        if out and lo <= out[-1][1] + 1:
            out[-1] = (out[-1][0], max(out[-1][1], hi))
        else:
            out.append((lo, hi))
    return out


def _intersect(a: list[tuple[int, int]], b: list[tuple[int, int]]) -> list[tuple[int, int]]:
    out = []
    for al, ah in a:
        for bl, bh in b:
            lo, hi = max(al, bl), min(ah, bh)
            if lo <= hi:
                out.append((lo, hi))
    return _merge(out)


def _rule_spans(rule: Rule) -> Intervals:
    protos = PROTOS if rule.protocol == "all" else (rule.protocol,)
    spans: Intervals = {}
    for p in protos:
        if p == "icmp":
            spans[p] = [(0, 0)]
        elif rule.protocol == "all" or rule.ports is None:
            spans[p] = [FULL[p]]
        else:
            spans[p] = [rule.ports]
    return spans


def effective_rules(m: Model, inst: Instance) -> list[tuple[Rule, str]]:
    out = []
    for sl in m.subnets[inst.subnet].security_lists:
        out += [(r, f"security_list:{sl}") for r in m.security_lists[sl]]
    for n in inst.nsgs:
        out += [(r, f"nsg:{n}") for r in m.nsgs[n]]
    return out


def _peer_matches(m: Model, rule: Rule, peer: Instance) -> bool:
    if rule.nsg is not None and rule.nsg in peer.nsgs:
        return True
    if rule.cidr is not None:
        return ipaddress.ip_address(peer.ip) in ipaddress.ip_network(rule.cidr)
    return False


def allowed_spans(m: Model, inst: Instance, direction: str, peer: Instance) -> Intervals:
    spans: Intervals = {}
    for rule, _src in effective_rules(m, inst):
        if rule.direction != direction or not _peer_matches(m, rule, peer):
            continue
        for p, iv in _rule_spans(rule).items():
            spans.setdefault(p, []).extend(iv)
    return {p: _merge(iv) for p, iv in spans.items()}


def _routes_to(m: Model, subnet_id: str, ip: str, kinds=("lpg", "drg")) -> bool:
    addr = ipaddress.ip_address(ip)
    for r in m.route_tables[m.subnets[subnet_id].route_table]:
        gw = m.gateways[r["target"]]
        if gw.get("type") in kinds and addr in ipaddress.ip_network(r["cidr"]):
            return True
    return False


def routed(m: Model, src: Instance, dst: Instance) -> bool:
    a, b = m.subnets[src.subnet], m.subnets[dst.subnet]
    if a.vcn == b.vcn:
        return True
    return _routes_to(m, src.subnet, dst.ip) and _routes_to(m, dst.subnet, src.ip)


@dataclass(frozen=True)
class Edge:
    src: str
    dst: str
    spans: tuple  # ((proto, ((lo, hi), ...)), ...)


def edge(m: Model, src: Instance, dst: Instance) -> Edge | None:
    if src.id == dst.id or not routed(m, src, dst):
        return None
    eg = allowed_spans(m, src, "egress", dst)
    ing = allowed_spans(m, dst, "ingress", src)
    both = {}
    for p in PROTOS:
        x = _intersect(eg.get(p, []), ing.get(p, []))
        if x:
            both[p] = tuple(x)
    if not both:
        return None
    return Edge(src.id, dst.id, tuple(sorted(both.items())))


def build_edges(m: Model) -> dict[str, list[Edge]]:
    g: dict[str, list[Edge]] = {i: [] for i in m.instances}
    for s in m.instances.values():
        for d in m.instances.values():
            e = edge(m, s, d)
            if e:
                g[s.id].append(e)
    return g


def blast_radius(m: Model, start: str, graph: dict[str, list[Edge]]) -> dict[str, int]:
    """Hop distance to every instance reachable from `start` via any permitted port.

    Over-approximation: assumes an attacker can pivot through any permitted port.
    """
    dist = {start: 0}
    frontier = [start]
    while frontier:
        nxt = []
        for n in frontier:
            for e in graph[n]:
                if e.dst not in dist:
                    dist[e.dst] = dist[n] + 1
                    nxt.append(e.dst)
        frontier = nxt
    dist.pop(start)
    return dist


def fmt_spans(spans) -> str:
    parts = []
    for p, iv in spans:
        if p == "icmp":
            parts.append("icmp")
        else:
            for lo, hi in iv:
                parts.append(f"{p}/{lo}" if lo == hi else f"{p}/{lo}-{hi}")
    return ",".join(parts)
