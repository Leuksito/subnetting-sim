"""División de redes en subredes de tamaño fijo."""

from __future__ import annotations

import ipaddress

from subnetcalc.core import SubnetError, analyze
from subnetcalc.exceptions import SecurityError
from subnetcalc.limits import MAX_SUBNETS


def usable_for_prefix(is_v4: bool, prefixlen: int) -> int:
    """Número de hosts utilizables para un prefijo dado."""
    max_prefix = 32 if is_v4 else 128
    if prefixlen < 0 or prefixlen > max_prefix:
        raise SubnetError(f"Prefijo inválido: /{prefixlen}")
    if prefixlen == max_prefix:
        return 1
    if is_v4 and prefixlen == 31:
        return 2  # RFC 3021 (punto a punto)
    if not is_v4 and prefixlen == 127:
        return 2  # RFC 6164
    bits = max_prefix - prefixlen
    base = 1 << bits
    return base - 2 if is_v4 else base - 1  # IPv4: red+broadcast; IPv6: solo ::0


def prefix_for_hosts(is_v4: bool, hosts: int) -> int:
    """Mayor prefijo (subred más pequeña) cuya cantidad de hosts >= ``hosts``."""
    if hosts < 1:
        raise SubnetError("El número de hosts debe ser >= 1")
    max_prefix = 32 if is_v4 else 128
    for p in range(max_prefix, -1, -1):
        if usable_for_prefix(is_v4, p) >= hosts:
            return p
    raise SubnetError(f"No existe subred que aloje {hosts} hosts")


def split_network(network_input: str, *, count: int | None = None, hosts: int | None = None):
    """Divide una red en subredes iguales.

    - ``count``: número de subredes (debe ser potencia de 2).
    - ``hosts``: mínimo de hosts por subred; se calcula el prefijo óptimo.
    """
    net = ipaddress.ip_network(network_input, strict=False)
    is_v4 = isinstance(net, ipaddress.IPv4Network)
    max_prefix = 32 if is_v4 else 128

    if count is not None and hosts is not None:
        raise SubnetError("Especifica --count o --hosts, no ambos")
    if count is None and hosts is None:
        raise SubnetError("Falta --count o --hosts")

    if count is not None:
        if count < 1:
            raise SubnetError("El número de subredes debe ser >= 1")
        if count > MAX_SUBNETS:
            raise SecurityError(
                f"El número de subredes ({count}) supera el máximo permitido ({MAX_SUBNETS})"
            )
        if count & (count - 1) != 0:
            raise SubnetError(
                f"{count} no es potencia de 2; las subredes iguales requieren "
                f"potencia de 2 (usa el comando 'vlsm' para tamaños variables)"
            )
        k = count.bit_length() - 1  # log2(count)
        new_prefix = net.prefixlen + k
        if new_prefix > max_prefix:
            raise SubnetError(
                f"No caben {count} subredes en /{net.prefixlen} (necesitaría /{new_prefix})"
            )
        subs = list(net.subnets(new_prefix=new_prefix))
    else:
        assert hosts is not None
        if hosts < 1:
            raise SubnetError("El número de hosts debe ser >= 1")
        p = prefix_for_hosts(is_v4, hosts)
        if p < net.prefixlen:
            raise SubnetError(
                f"La red /{net.prefixlen} es más pequeña de lo necesario para {hosts} hosts"
            )
        if p > net.prefixlen:
            # Número de subredes resultantes = 2^(p - prefixlen). Acota antes de
            # materializar para evitar agotar memoria con entradas como /0 --hosts 1.
            resulting = 1 << (p - net.prefixlen)
            if resulting > MAX_SUBNETS:
                raise SecurityError(
                    f"La división generaría {resulting} subredes (máximo {MAX_SUBNETS}). "
                    f"Usa una red padre más pequeña o un --hosts mayor."
                )
        subs = [net] if p == net.prefixlen else list(net.subnets(new_prefix=p))

    return [analyze(str(s)) for s in subs]
