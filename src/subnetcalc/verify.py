"""Verificación de pertenencia de una IP a una red."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from subnetcalc.core import SubnetError, _host_range, parse_network
from subnetcalc.exceptions import SecurityError
from subnetcalc.limits import MAX_INPUT_LENGTH


@dataclass(frozen=True)
class Verification:
    ip: str
    network: str
    version: str
    belongs: bool
    role: str  # "host" | "network" | "broadcast" | "none"
    is_first_host: bool
    is_last_host: bool
    note: str

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "network": self.network,
            "version": self.version,
            "belongs": self.belongs,
            "role": self.role,
            "is_first_host": self.is_first_host,
            "is_last_host": self.is_last_host,
            "note": self.note,
        }


def verify_ip(ip_input: str, network_input: str) -> Verification:
    """Devuelve si una IP pertenece a una red y qué papel juega."""
    if not ip_input or not ip_input.strip():
        raise SubnetError("IP vacía")
    if not network_input or not network_input.strip():
        raise SubnetError("Red vacía")
    if len(ip_input) > MAX_INPUT_LENGTH or len(network_input) > MAX_INPUT_LENGTH:
        raise SecurityError("Entrada demasiado larga")

    try:
        ip = ipaddress.ip_address(ip_input.strip())
    except (ValueError, TypeError) as exc:
        raise SubnetError(f"IP no válida: {ip_input!r} ({exc})") from exc

    net = parse_network(network_input)

    is_v4 = isinstance(net, ipaddress.IPv4Network)
    if ip.version != net.version:
        raise SubnetError(f"La IP {ip} es IPv{ip.version} pero la red es IPv{net.version}")

    # ¿Se infirió la máscara por clases? (IPv4 sin prefijo explícito)
    raw_net = network_input.strip()
    inferred = "/" not in raw_net and " " not in raw_net and is_v4 and net.prefixlen in (8, 16, 24)
    inferred_suffix = ""
    if inferred:
        letra = {8: "A", 16: "B", 24: "C"}[net.prefixlen]
        inferred_suffix = f" (máscara /{net.prefixlen} inferida por clase {letra})"

    belongs = ip in net
    if not belongs:
        return Verification(
            ip=str(ip),
            network=str(net),
            version="IPv4" if is_v4 else "IPv6",
            belongs=False,
            role="none",
            is_first_host=False,
            is_last_host=False,
            note=f"{ip} no pertenece a {net}{inferred_suffix}",
        )

    first, last, _usable, _bcast = _host_range(net)
    first_ip = ipaddress.ip_address(first)
    last_ip = ipaddress.ip_address(last)

    if ip == net.network_address:
        role = "network"
        note = "Dirección de red (no asignable a un host en IPv4 clásico)"
        if is_v4 and net.prefixlen in (31, 32):
            role = "host"
            note = "Red /31 o /32 (RFC 3021): la dirección de red también es de host"
        elif not is_v4 and net.prefixlen in (127, 128):
            role = "host"
            note = "Red /127 o /128: la dirección de red también es de host"
    elif is_v4 and net.prefixlen not in (31, 32) and ip == net.broadcast_address:
        role = "broadcast"
        note = "Dirección de broadcast (no asignable a un host)"
    else:
        role = "host"
        note = "Host utilizable"

    if inferred_suffix:
        note = f"{note}{inferred_suffix}"

    return Verification(
        ip=str(ip),
        network=str(net),
        version="IPv4" if is_v4 else "IPv6",
        belongs=True,
        role=role,
        is_first_host=(ip == first_ip),
        is_last_host=(ip == last_ip),
        note=note,
    )
