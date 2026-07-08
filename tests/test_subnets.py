"""Tests de división en subredes."""

import pytest

from subnetcalc.core import SubnetError
from subnetcalc.subnets import (
    prefix_for_hosts,
    split_network,
    usable_for_prefix,
)


def test_split_por_count_potencia_de_2():
    subs = split_network("10.0.0.0/24", count=4)
    assert len(subs) == 4
    assert [s.network for s in subs] == [
        "10.0.0.0/26",
        "10.0.0.64/26",
        "10.0.0.128/26",
        "10.0.0.192/26",
    ]
    assert subs[0].usable_hosts == 62


def test_split_count_no_potencia_de_2_falla():
    with pytest.raises(SubnetError):
        split_network("10.0.0.0/24", count=3)


def test_split_por_hosts():
    subs = split_network("172.16.0.0/24", hosts=50)
    # 50 hosts requieren /26 (62 utilizables); en un /24 caben 4 subredes /26
    assert len(subs) == 4
    assert all(s.prefix_length == 26 for s in subs)
    assert all(s.usable_hosts >= 50 for s in subs)


def test_split_hosts_exacto_potencia():
    # 62 hosts caben en /26 exactamente
    subs = split_network("192.168.1.0/24", hosts=62)
    assert len(subs) == 4
    assert subs[0].usable_hosts == 62


def test_split_hosts_una_subred():
    # Si pides más hosts de los que caben en una subdivisión, obtienes la red completa
    subs = split_network("192.168.1.0/24", hosts=254)
    assert len(subs) == 1
    assert subs[0].network == "192.168.1.0/24"


def test_split_demasiadas_subredes_falla():
    with pytest.raises(SubnetError):
        split_network("10.0.0.0/30", count=8)  # necesitaría /33


def test_split_count_y_hosts_a_la_vez_falla():
    with pytest.raises(SubnetError):
        split_network("10.0.0.0/24", count=2, hosts=10)


def test_split_ningun_parametro_falla():
    with pytest.raises(SubnetError):
        split_network("10.0.0.0/24")


def test_split_ipv6():
    subs = split_network("2001:db8::/64", count=2)
    assert len(subs) == 2
    assert subs[0].network == "2001:db8::/65"
    assert subs[1].network == "2001:db8:0:0:8000::/65"


def test_usable_for_prefix():
    assert usable_for_prefix(True, 24) == 254
    assert usable_for_prefix(True, 31) == 2
    assert usable_for_prefix(True, 32) == 1
    assert usable_for_prefix(False, 64) == (1 << 64) - 1
    assert usable_for_prefix(False, 127) == 2
    assert usable_for_prefix(False, 128) == 1


def test_prefix_for_hosts():
    assert prefix_for_hosts(True, 1) == 32
    assert prefix_for_hosts(True, 2) == 31
    assert prefix_for_hosts(True, 50) == 26
    assert prefix_for_hosts(True, 62) == 26
    assert prefix_for_hosts(True, 63) == 25
    assert prefix_for_hosts(False, 1) == 128
    assert prefix_for_hosts(False, 2) == 127


def test_prefix_for_hosts_invalido():
    with pytest.raises(SubnetError):
        prefix_for_hosts(True, 0)
