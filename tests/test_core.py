"""Tests del núcleo (análisis IPv4/IPv6)."""

import pytest

from subnetcalc.core import SubnetError, analyze


def test_ipv4_classico():
    info = analyze("192.168.1.10/24")
    assert info.version == "IPv4"
    assert info.network == "192.168.1.0/24"
    assert info.network_address == "192.168.1.0"
    assert info.netmask == "255.255.255.0"
    assert info.prefix_length == 24
    assert info.wildcard == "0.0.0.255"
    assert info.broadcast == "192.168.1.255"
    assert info.first_host == "192.168.1.1"
    assert info.last_host == "192.168.1.254"
    assert info.usable_hosts == 254
    assert info.total_addresses == 256
    assert info.ip_class == "C"
    assert info.is_private is True
    assert info.reverse_dns == "0.1.168.192.in-addr.arpa"


def test_ipv4_acepta_espacio_como_mascara():
    info = analyze("10.0.0.0 255.0.0.0")
    assert info.network == "10.0.0.0/8"
    assert info.ip_class == "A"
    assert info.usable_hosts == (1 << 24) - 2


def test_ipv4_punto_a_punto_31():
    info = analyze("10.0.0.0/31")
    assert info.usable_hosts == 2
    assert info.first_host == "10.0.0.0"
    assert info.last_host == "10.0.0.1"
    assert info.broadcast is None  # RFC 3021: sin broadcast


def test_ipv4_host_unico_32():
    info = analyze("10.0.0.5/32")
    assert info.usable_hosts == 1
    assert info.first_host == "10.0.0.5"
    assert info.last_host == "10.0.0.5"
    assert info.broadcast is None


def test_ipv6_normal():
    info = analyze("2001:db8::/64")
    assert info.version == "IPv6"
    assert info.prefix_length == 64
    assert info.broadcast is None  # IPv6 no tiene broadcast
    assert info.wildcard is None
    assert info.first_host == "2001:db8::1"
    assert info.last_host == "2001:db8::ffff:ffff:ffff:ffff"
    assert info.usable_hosts == (1 << 64) - 1
    assert info.ip_class is None
    # 2001:db8::/32 es un rango de documentación (RFC 3849): no es global.
    assert info.is_global is False


def test_ipv6_global_real():
    info = analyze("2606:4700:4700::/48")
    assert info.is_global is True
    assert info.is_private is False


def test_ipv6_link_local():
    info = analyze("fe80::/10")
    assert info.is_link_local is True
    assert info.is_global is False


def test_ipv6_127():
    info = analyze("2001:db8::/127")
    assert info.usable_hosts == 2
    assert info.first_host == "2001:db8::"
    assert info.last_host == "2001:db8::1"


def test_ipv6_128():
    info = analyze("2001:db8::1/128")
    assert info.usable_hosts == 1
    assert info.first_host == "2001:db8::1"


def test_loopback_v4():
    info = analyze("127.0.0.1/8")
    assert info.is_loopback is True
    assert info.ip_class == "A"


@pytest.mark.parametrize("bad", ["", "   ", "no-es-una-red", "999.1.1.1/24", "192.168.1.0/33"])
def test_entradas_invalidas(bad):
    with pytest.raises(SubnetError):
        analyze(bad)


def test_to_dict_contiene_todos_los_campos():
    info = analyze("192.168.1.0/24")
    d = info.to_dict()
    assert "network" in d
    assert "reverse_dns" in d
    assert len(d) == 20


# --- Máscara obligatoria en IPv4 (sin prefijo) -----------------------------


@pytest.mark.parametrize(
    "bare", ["192.168.1.0", "192.168.1.50", "10.0.0.0", "172.16.0.0", "127.0.0.0", "224.0.0.1"]
)
def test_analyze_ipv4_sin_mascara_falla(bare):
    with pytest.raises(SubnetError) as exc:
        analyze(bare)
    assert "máscara" in str(exc.value).lower() or "prefijo" in str(exc.value).lower()


def test_analyze_acepta_espacio_como_mascara():
    assert analyze("10.0.0.0 255.0.0.0").network == "10.0.0.0/8"


def test_analyze_ipv6_sin_mascara_es_128():
    # IPv6 sin prefijo es /128 (dirección única, no ambigua): no se rechaza.
    assert analyze("2001:db8::1").prefix_length == 128
