"""VLSM: asignación de subredes de longitud variable.

Dada una red padre y una lista de necesidades (número de hosts por subred),
asigna a cada una el bloque más pequeño posible que la cubra, siguiendo el
algoritmo voraz clásico: ordenar de mayor a menor necesidad, tomar el primer
bloque libre que admita el prefijo requerido y devolver los sobrantes al pool.
"""

from __future__ import annotations

import ipaddress

from subnetcalc.core import SubnetError, analyze
from subnetcalc.exceptions import SecurityError
from subnetcalc.limits import MAX_HOSTS_NEEDED, MAX_VLSM_NEEDS
from subnetcalc.subnets import prefix_for_hosts, usable_for_prefix


def vlsm_allocate(network_input: str, needs: list[int]) -> dict:
    """Asigna subredes VLSM y devuelve un dict con asignaciones y bloques libres."""
    if not needs:
        raise SubnetError("La lista de necesidades está vacía")
    if len(needs) > MAX_VLSM_NEEDS:
        raise SecurityError(f"Demasiadas subredes solicitadas ({len(needs)} > {MAX_VLSM_NEEDS})")
    if any(h < 1 for h in needs):
        raise SubnetError("Cada necesidad debe ser >= 1 host")
    if any(h > MAX_HOSTS_NEEDED for h in needs):
        raise SecurityError(f"Una necesidad supera el máximo permitido ({MAX_HOSTS_NEEDED})")

    net = ipaddress.ip_network(network_input, strict=False)
    is_v4 = isinstance(net, ipaddress.IPv4Network)

    # Ordenar de mayor a menor necesidad, conservando el índice original.
    order = sorted(range(len(needs)), key=lambda i: -needs[i])

    pool: list = [net]  # bloques libres
    results: list[dict | None] = [None] * len(needs)
    unmet: list[int] = []

    for i in order:
        need = needs[i]
        try:
            p = prefix_for_hosts(is_v4, need)
        except SubnetError:
            unmet.append(i)
            continue

        if p < net.prefixlen:
            unmet.append(i)
            continue

        # Elegir el bloque libre más pequeño (mayor prefixlen) que admita /p.
        candidate = None
        for j, blk in enumerate(pool):
            if blk.prefixlen <= p and (
                candidate is None or blk.prefixlen > pool[candidate].prefixlen
            ):
                candidate = j
        if candidate is None:
            unmet.append(i)
            continue

        blk = pool.pop(candidate)
        if blk.prefixlen == p:
            assigned = blk
        else:
            subs = list(blk.subnets(new_prefix=p))
            assigned = subs[0]
            pool.extend(subs[1:])  # devolver sobrantes

        info = analyze(str(assigned)).to_dict()
        info["index"] = i
        info["hosts_needed"] = need
        info["usable_hosts"] = usable_for_prefix(is_v4, assigned.prefixlen)
        results[i] = info

    pool.sort()
    free_blocks = [str(b) for b in pool]

    if unmet:
        raise SubnetError(f"No hay espacio suficiente para las necesidades con índices {unmet}")

    return {
        "input": str(net),
        "assignments": results,
        "free_blocks": free_blocks,
        "free_count": len(free_blocks),
    }
