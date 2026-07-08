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


# --- Máscara obligatoria en IPv4 (sin prefijo) -----------------------------


def test_verify_red_sin_mascara_falla():
    # La máscara es obligatoria: una IPv4 suelta se rechaza con error claro.
    with pytest.raises(SubnetError) as exc:
        verify_ip("192.168.1.50", "192.168.1.0")
    assert "máscara" in str(exc.value).lower() or "prefijo" in str(exc.value).lower()


def test_verify_red_sin_mascara_clase_a_falla():
    with pytest.raises(SubnetError):
        verify_ip("10.5.0.1", "10.0.0.0")


def test_verify_red_sin_mascara_clase_b_falla():
    with pytest.raises(SubnetError):
        verify_ip("172.16.5.5", "172.16.0.0")


def test_verify_acepta_espacio_como_mascara():
    # "IP máscara" (con espacio) es una máscara explícita válida.
    v = verify_ip("192.168.1.50", "192.168.1.0 255.255.255.0")
    assert v.belongs is True
    assert v.network == "192.168.1.0/24"


def test_verify_con_mascara_explicita_funciona():
    v = verify_ip("192.168.1.50", "192.168.1.0/24")
    assert v.belongs is True
    assert v.role == "host"
    assert "inferida" not in v.note


def test_verify_ipv6_sin_prefijo_es_128():
    # IPv6 sin prefijo es /128 (dirección única, no ambigua): no se rechaza.
    v = verify_ip("2001:db8::1", "2001:db8::1")
    assert v.belongs is True
    assert v.network == "2001:db8::1/128"
