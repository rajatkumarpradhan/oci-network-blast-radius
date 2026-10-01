"""Findings from the model. These are review priorities, not confirmed vulnerabilities."""
from __future__ import annotations

from dataclasses import asdict, dataclass

from . import exposure, reach
from .model import Model

SEV_ORDER = {"high": 0, "medium": 1, "low": 2}


@dataclass
class Finding:
    rule: str
    severity: str
    subject: str
    message: str
    evidence: list[str]

    def to_dict(self) -> dict:
        return asdict(self)


def _is_sensitive(inst) -> bool:
    return str(inst.tags.get("sensitivity", "")).lower() == "high"


def analyze(m: Model) -> list[Finding]:
    out: list[Finding] = []
    graph = reach.build_edges(m)
    exposed = [i for i in m.instances.values() if exposure.internet_reachable(m, i)]

    for inst in exposed:
        wo = exposure.world_open_ingress(m, inst)
        if not wo:
            continue
        full = all(wo.get(p) == [reach.FULL[p]] for p in ("tcp", "udp"))
        hits = exposure.sensitive_ports_hit(wo)
        if full:
            out.append(Finding("BR002", "high", inst.id,
                               f"{inst.name} accepts all TCP/UDP ports from 0.0.0.0/0 per modeled rules.",
                               [f"public subnet {inst.subnet} routed to an internet gateway", "world-open ingress rule"]))
        elif hits:
            names = ", ".join(f"{p}/{exposure.SENSITIVE_PORTS[p]}" for p in hits)
            out.append(Finding("BR001", "high", inst.id,
                               f"{inst.name} permits internet ingress on admin/data ports: {names}.",
                               [f"public IP in public subnet {inst.subnet} with igw route", f"ports {names} open to 0.0.0.0/0"]))
        else:
            out.append(Finding("BR001", "medium", inst.id,
                               f"{inst.name} permits internet ingress on {reach.fmt_spans(sorted((p, tuple(v)) for p, v in wo.items()))}.",
                               ["world-open ingress rule on an internet-routed instance"]))

    for inst in exposed:
        if not exposure.world_open_ingress(m, inst):
            continue
        dist = reach.blast_radius(m, inst.id, graph)
        if not dist:
            continue
        sens = [m.instances[i] for i in dist if _is_sensitive(m.instances[i])]
        total = len(m.instances) - 1
        msg = (f"If {inst.name} were compromised, rules permit lateral reach to {len(dist)} of {total} "
               f"other instances (max {max(dist.values())} hops).")
        ev = [f"{m.instances[i].name}: {dist[i]} hop(s)" for i in sorted(dist, key=lambda k: (dist[k], k))]
        if sens:
            out.append(Finding("BR003", "high", inst.id,
                               msg + " Includes high-sensitivity: " + ", ".join(s.name for s in sens) + ".", ev))
        elif len(dist) >= 3:
            out.append(Finding("BR003", "medium", inst.id, msg, ev))

    for inst in m.instances.values():
        if _is_sensitive(inst) and exposure.egress_to_internet(m, inst):
            out.append(Finding("BR005", "medium", inst.id,
                               f"{inst.name} (high sensitivity) has a modeled outbound path to 0.0.0.0/0 with an all-destination egress rule.",
                               ["route to nat/igw gateway", "egress rule to 0.0.0.0/0"]))

    for sl_id, rules in m.security_lists.items():
        for r in rules:
            if r.direction == "ingress" and r.protocol == "all" and r.cidr and r.cidr != "0.0.0.0/0":
                import ipaddress
                if ipaddress.ip_network(r.cidr).prefixlen <= 16:
                    out.append(Finding("BR006", "low", sl_id,
                                       f"Security list {sl_id} allows all protocols from broad range {r.cidr}.",
                                       [f"rule: ingress all from {r.cidr}"]))
            if r.stateless:
                out.append(Finding("BR007", "low", sl_id,
                                   f"Security list {sl_id} has a stateless {r.direction} rule; return traffic needs its own rule and is not modeled.",
                                   [f"stateless {r.direction} rule for {r.cidr or r.nsg}"]))

    out.sort(key=lambda f: (SEV_ORDER[f.severity], f.rule, f.subject))
    return out


def summary(m: Model) -> dict:
    graph = reach.build_edges(m)
    return {"instances": len(m.instances), "subnets": len(m.subnets),
            "edges": sum(len(v) for v in graph.values()),
            "internet_reachable": sorted(i.id for i in m.instances.values() if exposure.internet_reachable(m, i))}
