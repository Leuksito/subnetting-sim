"""Serialización de resultados: JSON, CSV, HTML y texto para consola."""

from __future__ import annotations

import csv
import html
import io
import json
from collections.abc import Iterable


def _as_dict(obj):
    return obj.to_dict() if hasattr(obj, "to_dict") else obj


def to_json(obj) -> str:
    """Serializa a JSON (maneja objetos con ``to_dict``)."""

    def default(o):
        d = _as_dict(o)
        return d

    return json.dumps(obj, ensure_ascii=False, indent=2, default=default)


def to_csv(rows: Iterable, columns: list[str]) -> str:
    """Serializa una lista de dicts a CSV usando solo ``columns``."""
    out = io.StringIO()
    writer = csv.DictWriter(out, fieldnames=columns, extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        writer.writerow(_as_dict(row))
    return out.getvalue().rstrip("\r\n")


def _esc(value) -> str:
    return html.escape("" if value is None else str(value))


def _bool_es(value) -> str:
    return "sí" if value else "no"


def info_to_html_table(info) -> str:
    """Renderiza un SubnetInfo (o dict) como tabla clave/valor."""
    d = _as_dict(info)
    label = _LABELS
    rows = []
    for k, v in d.items():
        if isinstance(v, bool):
            v = _bool_es(v)
        if v is None:
            v = "N/A"
        name = label.get(k, k)
        rows.append(f"<tr><th>{_esc(name)}</th><td><code>{_esc(v)}</code></td></tr>")
    return f'<table class="kv">{"".join(rows)}</table>'


def list_to_html_table(items: Iterable, columns: list[str], titles: list[str] | None = None) -> str:
    """Renderiza una lista como tabla HTML con las columnas indicadas."""
    titles = titles or columns
    head = "".join(f"<th>{_esc(t)}</th>" for t in titles)
    body_rows = []
    for it in items:
        d = _as_dict(it)
        cells = "".join(f"<td>{_esc(d.get(c, ''))}</td>" for c in columns)
        body_rows.append(f"<tr>{cells}</tr>")
    return (
        f'<table class="grid"><thead><tr>{head}</tr></thead>'
        f"<tbody>{''.join(body_rows)}</tbody></table>"
    )


def render_html_page(title: str, sections: list[tuple[str, str]]) -> str:
    """Página HTML autocontenida con secciones (encabezado, contenido_html)."""
    body = ""
    for heading, content in sections:
        body += f"<section><h2>{_esc(heading)}</h2>{content}</section>"
    return (
        '<!doctype html>\n<html lang="es"><head><meta charset="utf-8">'
        f"<title>{_esc(title)}</title>\n<style>\n{_CSS}\n</style></head>\n"
        f"<body><h1>{_esc(title)}</h1>{body}</body></html>\n"
    )


def to_text(info) -> str:
    """Renderiza un SubnetInfo como bloque de texto clave/valor alineado."""
    d = _as_dict(info)
    names = [_LABELS.get(k, k) for k in d]
    width = max(len(n) for n in names)
    lines = []
    for k, name in zip(d, names, strict=False):
        v = d[k]
        if isinstance(v, bool):
            v = _bool_es(v)
        if v is None:
            v = "N/A"
        lines.append(f"  {name:<{width}}  {v}")
    return "\n".join(lines)


def list_to_text(items: list, columns: list[str], titles: list[str] | None = None) -> str:
    """Renderiza una lista como tabla de texto alineada."""
    titles = titles or columns
    rows = []
    for it in items:
        d = _as_dict(it)
        rows.append([str(d.get(c, "")) for c in columns])
    widths = [len(t) for t in titles]
    for r in rows:
        for i, cell in enumerate(r):
            widths[i] = max(widths[i], len(cell))
    header = "  ".join(t.ljust(widths[i]) for i, t in enumerate(titles))
    sep = "  ".join("-" * w for w in widths)
    body = "\n".join("  ".join(cell.ljust(widths[i]) for i, cell in enumerate(r)) for r in rows)
    return f"{header}\n{sep}\n{body}"


_LABELS = {
    "input": "Entrada",
    "version": "Versión",
    "network": "Red",
    "network_address": "Dir. de red",
    "netmask": "Máscara",
    "prefix_length": "Prefijo (CIDR)",
    "wildcard": "Wildcard",
    "broadcast": "Broadcast",
    "first_host": "Primer host",
    "last_host": "Último host",
    "usable_hosts": "Hosts utilizables",
    "total_addresses": "Total de direcciones",
    "ip_class": "Clase",
    "is_private": "Privada",
    "is_loopback": "Loopback",
    "is_link_local": "Link-local",
    "is_multicast": "Multicast",
    "is_reserved": "Reservada",
    "is_global": "Global (IPv6)",
    "reverse_dns": "DNS reverso",
    "ip": "IP",
    "belongs": "Pertenece",
    "role": "Rol",
    "is_first_host": "¿Primer host?",
    "is_last_host": "¿Último host?",
    "note": "Nota",
    "index": "#",
    "hosts_needed": "Hosts req.",
}

_CSS = """
body{font-family:system-ui,'Segoe UI',sans-serif;max-width:1000px;
     margin:2rem auto;padding:0 1rem;color:#1a1a1a}
h1{font-size:1.6rem;border-bottom:3px solid #2563eb;padding-bottom:.4rem}
h2{font-size:1.15rem;margin-top:1.6rem;color:#1e3a8a}
table{border-collapse:collapse;width:100%;margin:1rem 0;font-size:.92rem}
th,td{border:1px solid #cbd5e1;padding:.45rem .65rem;text-align:left;vertical-align:top}
th{background:#f1f5f9}
.kv th{width:34%}
code{background:#f1f5f9;padding:.05rem .3rem;border-radius:3px;font-family:Consolas,monospace}
.note{color:#475569;font-style:italic;margin:.5rem 0}
"""
