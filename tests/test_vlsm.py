"""Tests de VLSM."""

import ipaddress

import pytest

from subnetcalc.core import SubnetError
from subnetcalc.vlsm import vlsm_allocate


def test_vlsm_basico():
    res = vlsm_allocate("172.16.0.0/16", [100, 50, 25, 25, 2])
    assert len(res["assignments"]) == 5
    # La mayor necesidad (100 hosts) debe ir primero en el espacio
    prefixes = sorted(a["prefix_length"] for a in res["assignments"])
    # 100->/25, 50->/26, 25->/27, 25->/27, 2->/31 (RFC 3021: 2 hosts caben en /31)
    assert prefixes == [25, 26, 27, 27, 31]
    # Índices conservados en orden original
    idxs = [a["index"] for a in res["assignments"]]
    assert idxs == [0, 1, 2, 3, 4]
    # La suma de direcciones usadas + libres == total del padre
    total = 1 << 16
    used = sum(a["total_addresses"] for a in res["assignments"])
    assert used <= total
    # La primera subred debe empezar en la dirección de red del padre
    assert res["assignments"][0]["network_address"] == "172.16.0.0"
    # Las necesidades están cubiertas
    for a in res["assignments"]:
        assert a["usable_hosts"] >= a["hosts_needed"]


def test_vlsm_sin_espacio():
    with pytest.raises(SubnetError):
        vlsm_allocate("192.168.1.0/24", [200, 200])  # no caben dos /24 en un /24


def test_vlsm_necesidad_invalida():
    with pytest.raises(SubnetError):
        vlsm_allocate("10.0.0.0/24", [50, 0])
    with pytest.raises(SubnetError):
        vlsm_allocate("10.0.0.0/24", [])


def test_vlsm_asignaciones_no_solapadas():
    import ipaddress

    res = vlsm_allocate("10.0.0.0/24", [100, 50, 20, 10, 2, 2])
    nets = [ipaddress.ip_network(a["network"]) for a in res["assignments"]]
    for i in range(len(nets)):
        for j in range(i + 1, len(nets)):
            assert not nets[i].overlaps(nets[j]), f"{nets[i]} solapa {nets[j]}"


def test_vlsm_bloques_libres_coherentes():
    res = vlsm_allocate("10.0.0.0/24", [100])  # /25 usado, queda media red
    assert res["free_count"] >= 1
    # El bloque libre debe estar dentro del padre y no solaparse con la asignación
    used = ipaddress.ip_network(res["assignments"][0]["network"])
    for fb in res["free_blocks"]:
        free = ipaddress.ip_network(fb)
        assert not free.overlaps(used)
