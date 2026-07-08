"""Tests de supernetting / CIDR."""

import pytest

from subnetcalc.core import SubnetError
from subnetcalc.supernet import summarize


def test_supernet_contigua_un_bloque():
    res = summarize(["192.168.0.0/24", "192.168.1.0/24", "192.168.2.0/24", "192.168.3.0/24"])
    assert res["input_count"] == 4
    assert res["collapsed_count"] == 1
    assert res["collapsed"] == ["192.168.0.0/22"]
    assert res["is_single_supernet"] is True


def test_supernet_no_alineada_no_colapsa():
    # 192.168.0.0/24 + 192.168.2.0/24 (falta la .1) -> no forman un /23
    res = summarize(["192.168.0.0/24", "192.168.2.0/24"])
    assert res["collapsed_count"] == 2
    assert res["is_single_supernet"] is False


def test_supernet_una_red():
    res = summarize(["10.0.0.0/8"])
    assert res["collapsed"] == ["10.0.0.0/8"]
    assert res["is_single_supernet"] is True


def test_supernet_spanning_cubre_rango():
    res = summarize(["192.168.0.0/24", "192.168.5.0/24"])
    first = res["first_address"]
    last = res["last_address"]
    assert first == "192.168.0.0"
    assert last == "192.168.5.255"
    # spanning siempre cubre el rango completo
    assert res["spanning_count"] >= 1


def test_supernet_ipv6():
    res = summarize(["2001:db8:0::/48", "2001:db8:1::/48"])
    assert res["collapsed"] == ["2001:db8::/47"]


def test_supernet_version_mezclada_falla():
    with pytest.raises(SubnetError):
        summarize(["192.168.0.0/24", "2001:db8::/32"])


def test_supernet_vacia_falla():
    with pytest.raises(SubnetError):
        summarize([])


def test_supernet_red_invalida_falla():
    with pytest.raises(SubnetError):
        summarize(["no-es-una-red"])
