"""Supernetting / CIDR: resumir varias redes en bloques más grandes."""

from __future__ import annotations

import ipaddress

from subnetcalc.core import SubnetError
from subnetcalc.exceptions import SecurityError
from subnetcalc.limits import MAX_INPUT_LENGTH, MAX_SUPERNET_INPUTS


def summarize(networks: list[str]) -> dict:
    """Resume una lista de redes en el menor número de bloques posible.

    - ``collapsed``: resultado de ``collapse_addresses`` (solo fusiona redes
      contiguas y alineadas).
    - ``spanning``: bloque(s) mínimo(s) que cubren desde la primera hasta la
      última dirección (puede ser >1 si el rango no está alineado).
    - ``is_single_supernet``: True si todo colapsa en una sola supernet.
    """
    if not networks:
        raise SubnetError("La lista de redes está vacía")
    if len(networks) > MAX_SUPERNET_INPUTS:
        raise SecurityError(
            f"Demasiadas redes de entrada ({len(networks)} > {MAX_SUPERNET_INPUTS})"
        )

    nets: list = []
    for s in networks:
        s = s.strip()
        if not s:
            continue
        if len(s) > MAX_INPUT_LENGTH:
            raise SecurityError(f"Red demasiado larga: {s[:32]!r}…")
        try:
            nets.append(ipaddress.ip_network(s, strict=False))
        except (ValueError, TypeError) as exc:
            raise SubnetError(f"Red no válida: {s!r} ({exc})") from exc

    if not nets:
        raise SubnetError("La lista de redes está vacía")

    versions = {n.version for n in nets}
    if len(versions) != 1:
        raise SubnetError("Todas las redes deben ser de la misma versión (IPv4 o IPv6)")

    collapsed = list(ipaddress.collapse_addresses(nets))
    first = min(n.network_address for n in nets)
    last = max(n.broadcast_address for n in nets)
    spanning = list(ipaddress.summarize_address_range(first, last))

    return {
        "inputs": [str(n) for n in nets],
        "input_count": len(nets),
        "collapsed": [str(c) for c in collapsed],
        "collapsed_count": len(collapsed),
        "spanning": [str(s) for s in spanning],
        "spanning_count": len(spanning),
        "is_single_supernet": len(collapsed) == 1,
        "total_addresses_collapsed": sum(c.num_addresses for c in collapsed),
        "first_address": str(first),
        "last_address": str(last),
    }
