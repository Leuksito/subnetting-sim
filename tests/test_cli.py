"""Tests de la CLI (argparse + salida a stdout/stderr)."""

import json

import pytest

from subnetcalc.cli import main


def run(args, capsys):
    rc = main(args)
    out = capsys.readouterr()
    return rc, out.out, out.err


def test_cli_info_table(capsys):
    rc, out, err = run(["info", "192.168.1.10/24"], capsys)
    assert rc == 0
    assert "192.168.1.0/24" in out
    assert "Máscara" in out


def test_cli_info_json(capsys):
    rc, out, _ = run(["info", "192.168.1.10/24", "--format", "json"], capsys)
    assert rc == 0
    data = json.loads(out)
    assert data["network"] == "192.168.1.0/24"


def test_cli_info_csv(capsys):
    rc, out, _ = run(["info", "192.168.1.10/24", "--format", "csv"], capsys)
    assert rc == 0
    assert "network" in out.splitlines()[0]


def test_cli_info_html(capsys):
    rc, out, _ = run(["info", "192.168.1.10/24", "--format", "html"], capsys)
    assert rc == 0
    assert "<!doctype html>" in out.lower()


def test_cli_split_count(capsys):
    rc, out, _ = run(["split", "10.0.0.0/24", "--count", "4"], capsys)
    assert rc == 0
    assert "10.0.0.0/26" in out
    assert "10.0.0.192/26" in out


def test_cli_split_hosts(capsys):
    rc, out, _ = run(["split", "172.16.0.0/24", "--hosts", "50"], capsys)
    assert rc == 0
    assert out.count("/26") == 4


def test_cli_vlsm(capsys):
    rc, out, _ = run(["vlsm", "172.16.0.0/16", "--needs", "100,50,25,25,2"], capsys)
    assert rc == 0
    assert "172.16.0.0" in out


def test_cli_supernet(capsys):
    rc, out, _ = run(
        ["supernet", "192.168.0.0/24", "192.168.1.0/24", "192.168.2.0/24", "192.168.3.0/24"],
        capsys,
    )
    assert rc == 0
    assert "192.168.0.0/22" in out
    assert "sí" in out  # ¿supernet única?


def test_cli_verify_host(capsys):
    rc, out, _ = run(["verify", "192.168.1.50", "192.168.1.0/24"], capsys)
    assert rc == 0
    assert "host" in out.lower()


def test_cli_error_entrada_invalida(capsys):
    rc, out, err = run(["info", "no-es-una-red"], capsys)
    assert rc == 2
    assert "Error" in err


def test_cli_error_count_no_potencia(capsys):
    rc, out, err = run(["split", "10.0.0.0/24", "--count", "3"], capsys)
    assert rc == 2
    assert "potencia" in err.lower()


def test_cli_sin_subcomando_falla(capsys):
    with pytest.raises(SystemExit):
        main([])


def test_cli_help_epilog(capsys):
    with pytest.raises(SystemExit):
        main(["--help"])
    out = capsys.readouterr().out
    assert "subnetcalc info" in out
