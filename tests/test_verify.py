"""Tests de verificación de IPs."""

import pytest

from subnetcalc.core import SubnetError
from subnetcalc.verify import verify_ip


def test_host_normal():
    v = verify_ip("192.168.1.50", "192.168.1.0/24")
    assert v.belongs is True
    assert v.role == "host"
    assert v.is_first_host is False
    assert v.is_last_host is False


def test_direccion_de_red():
    v = verify_ip("192.168.1.0", "192.168.1.0/24")
    assert v.role == "network"


def test_broadcast():
    v = verify_ip("192.168.1.255", "192.168.1.0/24")
    assert v.role == "broadcast"


def test_primer_ultimo_host():
    assert verify_ip("192.168.1.1", "192.168.1.0/24").is_first_host is True
    assert verify_ip("192.168.1.254", "192.168.1.0/24").is_last_host is True


def test_fuera_de_red():
    v = verify_ip("10.0.0.5", "192.168.1.0/24")
    assert v.belongs is False
    assert v.role == "none"


def test_punto_a_punto_31():
    # En /31 ambas direcciones son hosts
    v = verify_ip("10.0.0.0", "10.0.0.0/31")
    assert v.role == "host"
    assert verify_ip("10.0.0.1", "10.0.0.0/31").role == "host"


def test_ipv6_host():
    v = verify_ip("2001:db8::5", "2001:db8::/64")
    assert v.belongs is True
    assert v.role == "host"
    assert v.version == "IPv6"


def test_ipv6_direccion_de_red():
    v = verify_ip("2001:db8::", "2001:db8::/64")
    assert v.role == "network"


def test_ipv6_fuera():
    v = verify_ip("2001:dead::1", "2001:db8::/64")
    assert v.belongs is False
    assert v.role == "none"


def test_version_mezclada_falla():
    with pytest.raises(SubnetError):
        verify_ip("192.168.1.1", "2001:db8::/64")


@pytest.mark.parametrize(
    "bad_ip,bad_net",
    [("", "1.0.0.0/8"), ("1.1.1.1", ""), ("xx", "1.0.0.0/8")],
)
def test_entradas_invalidas(bad_ip, bad_net):
    with pytest.raises(SubnetError):
        verify_ip(bad_ip, bad_net)
