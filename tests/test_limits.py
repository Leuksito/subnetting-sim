"""Tests de los límites anti-DoS (SecurityError)."""

import pytest

from subnetcalc import SecurityError, SubnetError
from subnetcalc.core import analyze
from subnetcalc.subnets import split_network
from subnetcalc.supernet import summarize
from subnetcalc.verify import verify_ip
from subnetcalc.vlsm import vlsm_allocate


def test_analyze_input_demasiado_largo():
    with pytest.raises(SecurityError):
        analyze("x" * 300 + "/24")


def test_split_count_excede_maximo():
    # MAX_SUBNETS = 4096; pedir 8192 debe rechazarse sin materializar.
    with pytest.raises(SecurityError):
        split_network("10.0.0.0/24", count=8192)


def test_split_hosts_genera_demasiadas_subredes():
    # /0 con hosts=1 -> /32 -> 2^32 subredes: debe bloquearse antes de materializar.
    with pytest.raises(SecurityError):
        split_network("0.0.0.0/0", hosts=1)


def test_split_hosts_en_ipv6_bloqueado():
    # ::/0 con hosts=1 -> /128 -> 2^128 subredes: bloqueado.
    with pytest.raises(SecurityError):
        split_network("::/0", hosts=1)


def test_split_count_valido_no_rechazado():
    # 4 subredes sigue funcionando (regresión).
    subs = split_network("10.0.0.0/24", count=4)
    assert len(subs) == 4


def test_vlsm_demasiadas_necesidades():
    needs = [10] * 300  # MAX_VLSM_NEEDS = 256
    with pytest.raises(SecurityError):
        vlsm_allocate("10.0.0.0/8", needs)


def test_vlsm_necesidad_gigante():
    with pytest.raises(SecurityError):
        vlsm_allocate("10.0.0.0/8", [2**40])


def test_vlsm_valido_sigue_funcionando():
    res = vlsm_allocate("172.16.0.0/16", [100, 50, 25, 25, 2])
    assert len(res["assignments"]) == 5


def test_supernet_demasiadas_redes():
    nets = [f"10.{i}.0.0/24" for i in range(300)]  # MAX_SUPERNET_INPUTS = 256
    with pytest.raises(SecurityError):
        summarize(nets)


def test_supernet_cadena_demasiado_larga():
    with pytest.raises(SecurityError):
        summarize(["x" * 300])


def test_verify_input_largo():
    with pytest.raises(SecurityError):
        verify_ip("x" * 300, "10.0.0.0/8")


def test_security_error_es_subnet_error():
    # Asegura que los manejadores que capturan SubnetError también capturan
    # SecurityError (jerarquía de excepciones).
    assert issubclass(SecurityError, SubnetError)
