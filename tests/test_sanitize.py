"""Tests del saneamiento anti-inyección en terminal."""

from subnetcalc.sanitize import sanitize_for_display


def test_sin_caracteres_control_pasa_igual():
    assert sanitize_for_display("192.168.1.0/24") == "192.168.1.0/24"


def test_strip_secuencia_ansi_csi():
    # ESC[2J borra pantalla; ESC[31m rojo. No deben llegar al terminal.
    s = "\x1b[2J\x1b[31m" + "texto" + "\x1b[0m"
    assert sanitize_for_display(s) == "texto"


def test_strip_osc_title_injection():
    # ESC]0;title\x07 cambia el título de la ventana.
    s = "\x1b]0;hacked\x07" + "payload"
    assert sanitize_for_display(s) == "payload"


def test_strip_caracteres_control_sueltos():
    assert sanitize_for_display("a\x00b\x07c\x1bd") == "abcd"


def test_multilinea_conserva_newlines():
    s = "linea1\r\nlinea2\ttab"
    out = sanitize_for_display(s, multiline=True)
    assert "\n" in out
    assert "\t" in out
    assert "\r" not in out


def test_none_devuelve_vacio():
    assert sanitize_for_display(None) == ""
