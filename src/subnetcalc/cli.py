"""Línea de comandos de subnetting-sim.

Subcomandos: info, split, vlsm, supernet, verify.
Cada uno admite ``--format table|json|csv|html``.
"""

from __future__ import annotations

import argparse
import html
import sys

from subnetcalc import (
    SubnetError,
    analyze,
    split_network,
    summarize,
    verify_ip,
    vlsm_allocate,
)
from subnetcalc.export import (
    info_to_html_table,
    list_to_html_table,
    list_to_text,
    render_html_page,
    to_csv,
    to_json,
    to_text,
)
from subnetcalc.sanitize import sanitize_for_display

FORMATS = ("table", "json", "csv", "html")

# Columnas habituales para listados de subredes.
SUBNET_COLS = [
    "network",
    "network_address",
    "prefix_length",
    "netmask",
    "broadcast",
    "first_host",
    "last_host",
    "usable_hosts",
]
SUBNET_TITLES = [
    "Red",
    "Dir. red",
    "/",
    "Máscara",
    "Broadcast",
    "Primer host",
    "Último host",
    "Hosts",
]

VLSM_COLS = ["index", "hosts_needed", "usable_hosts", "network", "first_host", "last_host"]
VLSM_TITLES = ["#", "Req.", "Disp.", "Subred", "Primer host", "Último host"]


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="subnetcalc",
        description="Simulador de subnetting IPv4/IPv6.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Ejemplos:\n"
            "  subnetcalc info 192.168.1.10/24\n"
            "  subnetcalc info 2001:db8::/32 --format json\n"
            "  subnetcalc split 10.0.0.0/24 --count 4\n"
            "  subnetcalc split 172.16.0.0/24 --hosts 50\n"
            "  subnetcalc vlsm 172.16.0.0/16 --needs 100,50,25,25,2\n"
            "  subnetcalc supernet 192.168.0.0/24 192.168.1.0/24 192.168.2.0/24\n"
            "  subnetcalc verify 192.168.1.50 192.168.1.0/24\n"
        ),
    )
    sub = p.add_subparsers(dest="command", required=True)

    sp = sub.add_parser("info", help="Analiza una red IPv4/IPv6")
    sp.add_argument("network", help="IP/prefijo o 'IP máscara' (ej. 192.168.1.10/24)")
    sp.add_argument("--format", choices=FORMATS, default="table")

    sp = sub.add_parser("split", help="Divide una red en subredes iguales")
    sp.add_argument("network", help="Red padre (ej. 10.0.0.0/24)")
    g = sp.add_mutually_exclusive_group(required=True)
    g.add_argument("--count", type=int, help="Nº de subredes (potencia de 2)")
    g.add_argument("--hosts", type=int, help="Mínimo de hosts por subred")
    sp.add_argument("--format", choices=FORMATS, default="table")

    sp = sub.add_parser("vlsm", help="Asignación de subredes de longitud variable")
    sp.add_argument("network", help="Red padre (ej. 172.16.0.0/16)")
    sp.add_argument(
        "--needs",
        required=True,
        help="Lista de hosts por subred, separados por comas (ej. 100,50,25,25,2)",
    )
    sp.add_argument("--format", choices=FORMATS, default="table")

    sp = sub.add_parser("supernet", help="Resume varias redes en supernets (CIDR)")
    sp.add_argument("networks", nargs="+", help="Redes a resumir")
    sp.add_argument("--format", choices=("table", "json", "html"), default="table")

    sp = sub.add_parser("verify", help="Verifica si una IP pertenece a una red")
    sp.add_argument("ip", help="Dirección IP a verificar")
    sp.add_argument("network", help="Red contra la que se verifica")
    sp.add_argument("--format", choices=("table", "json", "html"), default="table")

    return p


def _parse_needs(raw: str) -> list[int]:
    try:
        parts = [p.strip() for p in raw.split(",") if p.strip()]
        return [int(p) for p in parts]
    except ValueError as exc:
        raise SubnetError(f"--needs debe ser una lista de enteros: {raw!r}") from exc


# --- render por comando ------------------------------------------------------


def _render_info(info, fmt: str) -> str:
    if fmt == "table":
        return to_text(info)
    if fmt == "json":
        return to_json(info.to_dict())
    if fmt == "csv":
        cols = list(info.to_dict().keys())
        return to_csv([info.to_dict()], cols)
    # html
    return render_html_page(
        f"Análisis de {info.input}",
        [("Resultado", info_to_html_table(info))],
    )


def _render_split(results, fmt: str, title: str) -> str:
    if fmt == "table":
        return list_to_text(results, SUBNET_COLS, SUBNET_TITLES)
    if fmt == "json":
        return to_json([r.to_dict() for r in results])
    if fmt == "csv":
        return to_csv([r.to_dict() for r in results], SUBNET_COLS)
    return render_html_page(
        title,
        [("Subredes", list_to_html_table(results, SUBNET_COLS, SUBNET_TITLES))],
    )


def _render_vlsm(res: dict, fmt: str, title: str) -> str:
    if fmt == "table":
        lines = [list_to_text(res["assignments"], VLSM_COLS, VLSM_TITLES)]
        if res["free_blocks"]:
            lines.append("")
            lines.append(f"Bloques libres ({res['free_count']}):")
            lines.extend(f"  - {b}" for b in res["free_blocks"])
        return "\n".join(lines)
    if fmt == "json":
        return to_json(res)
    if fmt == "csv":
        return to_csv(res["assignments"], VLSM_COLS)
    # html
    sections = [("Asignaciones", list_to_html_table(res["assignments"], VLSM_COLS, VLSM_TITLES))]
    if res["free_blocks"]:
        items = "".join(f"<li><code>{html.escape(b)}</code></li>" for b in res["free_blocks"])
        free_html = f"<ul>{items}</ul>"
        sections.append((f"Bloques libres ({res['free_count']})", free_html))
    return render_html_page(title, sections)


def _render_supernet(res: dict, fmt: str, title: str) -> str:
    if fmt == "json":
        return to_json(res)
    if fmt == "html":
        kv = info_to_html_table(
            {
                "input_count": res["input_count"],
                "collapsed": ", ".join(res["collapsed"]),
                "collapsed_count": res["collapsed_count"],
                "spanning": ", ".join(res["spanning"]),
                "is_single_supernet": res["is_single_supernet"],
                "total_addresses_collapsed": res["total_addresses_collapsed"],
                "first_address": res["first_address"],
                "last_address": res["last_address"],
            }
        )
        return render_html_page(title, [("Resumen", kv)])
    # table
    lines = [
        f"  Redes de entrada      {res['input_count']}",
        f"  Bloques resultantes   {res['collapsed_count']}",
        f"  ¿Supernet única?      {'sí' if res['is_single_supernet'] else 'no'}",
        f"  Total de direcciones  {res['total_addresses_collapsed']}",
        f"  Primera dirección     {res['first_address']}",
        f"  Última dirección      {res['last_address']}",
        "",
        "Collapsed:",
    ]
    for c in res["collapsed"]:
        lines.append(f"  - {c}")
    return "\n".join(lines)


def _render_verify(ver, fmt: str, title: str) -> str:
    if fmt == "json":
        return to_json(ver.to_dict())
    if fmt == "html":
        return render_html_page(title, [("Verificación", info_to_html_table(ver))])
    # table
    d = ver.to_dict()
    names = {
        "ip": "IP",
        "network": "Red",
        "version": "Versión",
        "belongs": "Pertenece",
        "role": "Rol",
        "is_first_host": "¿Primer host?",
        "is_last_host": "¿Último host?",
        "note": "Nota",
    }
    width = max(len(v) for v in names.values())
    lines = []
    for k in names:
        v = d[k]
        if isinstance(v, bool):
            v = "sí" if v else "no"
        lines.append(f"  {names[k]:<{width}}  {v}")
    return "\n".join(lines)


# --- dispatch ----------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "info":
            info = analyze(args.network)
            print(_render_info(info, args.format))
        elif args.command == "split":
            results = split_network(args.network, count=args.count, hosts=args.hosts)
            print(_render_split(results, args.format, f"División de {args.network}"))
        elif args.command == "vlsm":
            needs = _parse_needs(args.needs)
            res = vlsm_allocate(args.network, needs)
            print(_render_vlsm(res, args.format, f"VLSM sobre {args.network}"))
        elif args.command == "supernet":
            res = summarize(args.networks)
            print(_render_supernet(res, args.format, "Supernetting / CIDR"))
        elif args.command == "verify":
            ver = verify_ip(args.ip, args.network)
            print(_render_verify(ver, args.format, f"Verificación de {args.ip}"))
        else:  # pragma: no cover
            parser.error("Comando desconocido")
    except SubnetError as exc:
        # Sanitizar el eco: evita inyección en terminal (ANSI bombing) aunque
        # las entradas ya estén validadas por ipaddress.
        print(f"Error: {sanitize_for_display(exc)}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
