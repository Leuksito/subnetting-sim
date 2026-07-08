"""Tests de exportación (JSON/CSV/HTML/texto)."""

import json

from subnetcalc import analyze
from subnetcalc.export import (
    info_to_html_table,
    list_to_html_table,
    list_to_text,
    render_html_page,
    to_csv,
    to_json,
    to_text,
)


def test_to_json_valido_y_con_tildes():
    info = analyze("192.168.1.0/24")
    data = json.loads(to_json(info))
    assert data["network"] == "192.168.1.0/24"
    # ensure_ascii=False -> las tildes de las etiquetas no se escapan en el JSON de listas
    out = to_json([{"nota": "ación"}])
    assert "ación" in out


def test_to_csv_columnas_seleccionadas():
    rows = [{"a": 1, "b": 2, "c": 3}, {"a": 4, "b": 5, "c": 6}]
    csv_out = to_csv(rows, ["a", "c"])
    first_line = csv_out.splitlines()[0]
    assert first_line == "a,c"
    assert "4,6" in csv_out


def test_to_text_contiene_campos_clave():
    info = analyze("192.168.1.0/24")
    txt = to_text(info)
    assert "192.168.1.0/24" in txt
    assert "Máscara" in txt
    assert "Broadcast" in txt


def test_list_to_text_alineado():
    items = [analyze("10.0.0.0/30"), analyze("10.0.0.4/30")]
    txt = list_to_text(items, ["network", "usable_hosts"], ["Red", "Hosts"])
    lines = txt.splitlines()
    assert lines[0].startswith("Red")
    assert "10.0.0.0/30" in lines[2]
    assert "10.0.0.4/30" in lines[3]


def test_info_to_html_table_escape_html():
    info = analyze("192.168.1.0/24")
    html = info_to_html_table(info)
    assert "<table" in html
    assert "<code>" in html


def test_list_to_html_table_filas():
    items = [analyze("10.0.0.0/30"), analyze("10.0.0.4/30")]
    html = list_to_html_table(items, ["network"], ["Red"])
    assert html.count("<tr>") == 3  # 1 header + 2 body


def test_render_html_page_estructura():
    page = render_html_page("Título", [("Sección", "<p>hola</p>")])
    assert page.startswith("<!doctype html>")
    assert "<title>Título</title>" in page
    assert "<h2>Sección</h2>" in page
    assert "<style>" in page


def test_to_json_lista_de_dict():
    out = to_json([{"x": 1}])
    assert json.loads(out) == [{"x": 1}]
