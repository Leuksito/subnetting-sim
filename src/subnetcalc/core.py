"""Núcleo del simulador de subnetting.

Analiza una red IPv4/IPv6 y devuelve un :class:`SubnetInfo` con todos los
campos relevantes: dirección de red, máscara, wildcard, broadcast (IPv4),
primer/último host utilizable, número de hosts, clase (IPv4), tipo (IPv6),
banderas (privada, loopback, etc.) y puntero DNS reverso.

El cálculo es analítico (sin materializar ``hosts()``) para soportar redes
enormes como ``::/0`` o ``2001:db8::/64`` sin colgar.
"""

from __future__ import annotations

import ipaddress
from dataclasses import asdict, dataclass

from subnetcalc.exceptions import SecurityError, SubnetError
from subnetcalc.limits import MAX_INPUT_LENGTH


@dataclass(frozen=True)
class SubnetInfo:
    """Resultado del análisis de una red."""

    input: str
    version: str  # "IPv4" | "IPv6"
    network: str  # "192.168.1.0/24"
    network_address: str
    netmask: str  # IPv4: dotted decimal; IPv6: dirección comprimida
    prefix_length: int
    wildcard: str | None  # IPv4 only
    broadcast: str | None  # IPv4 only; None para IPv6 y /31, /32
    first_host: str
    last_host: str
    usable_hosts: int
    total_addresses: int
    ip_class: str | None  # IPv4 only: A/B/C/D/E
    is_private: bool
    is_loopback: bool
    is_link_local: bool
    is_multicast: bool
    is_reserved: bool
    is_global: bool  # IPv6: ULA/global
    reverse_dns: str

    def to_dict(self) -> dict:
        return asdict(self)


def _ip_class(net: ipaddress.IPv4Network) -> str:
    first = int(net.network_address) >> 24
    if first <= 127:
        return "A"
    if first <= 191:
        return "B"
    if first <= 223:
        return "C"
    if first <= 239:
        return "D"  # multicast
    return "E"  # reservado (experimental)


def _wildcard(net: ipaddress.IPv4Network) -> str:
    mask = int(net.netmask)
    inv = mask ^ 0xFFFFFFFF
    return str(ipaddress.IPv4Address(inv))


def _host_range(net: ipaddress.IPv4Network | ipaddress.IPv6Network) -> tuple:
    """Devuelve (first_host, last_host, usable_count, broadcast_or_None)."""
    n = net.num_addresses

    if isinstance(net, ipaddress.IPv4Network):
        if net.prefixlen == 32:
            first = last = net[0]
            count = 1
            bcast = None  # /32: host único, sin broadcast
        elif net.prefixlen == 31:
            first = net[0]
            last = net[1]
            count = 2
            bcast = None  # /31 punto a punto (RFC 3021), sin broadcast
        else:
            first = net[1]
            last = net[-2]
            count = n - 2
            bcast = net[-1]
        bcast_str = str(bcast) if bcast is not None else None
        return str(first), str(last), count, bcast_str

    # IPv6
    if net.prefixlen == 128:
        first = last = net[0]
        count = 1
    elif net.prefixlen == 127:
        first = net[0]
        last = net[1]
        count = 2
    else:
        # hosts() excluye ::0 (subnet-router anycast); el resto es utilizable.
        first = net[1]
        last = net[-1]
        count = n - 1
    return str(first), str(last), count, None  # IPv6: sin broadcast


def analyze(network_input: str) -> SubnetInfo:
    """Analiza una entrada tipo ``IP/prefijo`` o ``IP máscara``.

    Acepta formatos como ``192.168.1.10/24``, ``10.0.0.0 255.0.0.0`` o
    ``2001:db8::/32``. Los bits de host se permiten (``strict=False``).
    """
    if not network_input or not network_input.strip():
        raise SubnetError("Entrada vacía")

    if len(network_input) > MAX_INPUT_LENGTH:
        raise SecurityError(
            f"Entrada demasiado larga ({len(network_input)} > {MAX_INPUT_LENGTH} caracteres)"
        )

    raw = network_input.strip()
    # Permitir "IP máscara" (con espacio) además de "IP/prefijo"
    normalized = raw.replace(" ", "/") if " " in raw and "/" not in raw else raw

    try:
        net = ipaddress.ip_network(normalized, strict=False)
    except (ValueError, TypeError) as exc:
        raise SubnetError(f"Red/IP no válida: {network_input!r} ({exc})") from exc

    is_v4 = isinstance(net, ipaddress.IPv4Network)
    version = "IPv4" if is_v4 else "IPv6"

    first, last, usable, bcast = _host_range(net)

    return SubnetInfo(
        input=raw,
        version=version,
        network=str(net),
        network_address=str(net.network_address),
        netmask=str(net.netmask),
        prefix_length=net.prefixlen,
        wildcard=_wildcard(net) if is_v4 else None,
        broadcast=bcast,
        first_host=first,
        last_host=last,
        usable_hosts=usable,
        total_addresses=net.num_addresses,
        ip_class=_ip_class(net) if is_v4 else None,
        is_private=net.is_private,
        is_loopback=net.is_loopback,
        is_link_local=net.is_link_local,
        is_multicast=net.is_multicast,
        is_reserved=net.is_reserved,
        is_global=net.is_global,
        reverse_dns=net.network_address.reverse_pointer,
    )
