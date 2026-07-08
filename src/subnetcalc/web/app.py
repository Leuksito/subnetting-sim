"""Aplicación web del simulador de subnetting (Flask).

Reutiliza el núcleo de ``subnetcalc`` y renderiza los resultados en HTML.
Arranque (desarrollo):  flask --app subnetcalc.web.app run
Producción:  usar un WSGI server (gunicorn/waitress) y definir SECRET_KEY.
"""

from __future__ import annotations

import hmac
import os
import secrets
import time
from collections import defaultdict, deque

from flask import Flask, abort, render_template, request, session
from markupsafe import escape

from subnetcalc import (
    SubnetError,
    analyze,
    split_network,
    summarize,
    verify_ip,
    vlsm_allocate,
)
from subnetcalc.export import info_to_html_table, list_to_html_table
from subnetcalc.limits import WEB_RATE_MAX_REQUESTS, WEB_RATE_WINDOW_SECONDS

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

# Política de Seguridad de Contenido estricta: solo recursos propios (self).
# Los scripts van en /static/app.js (sin inline) para evitar 'unsafe-inline'.
_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=(), clipboard-read=()",
    "Content-Security-Policy": (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self'; "
        "img-src 'self'; "
        "object-src 'none'; "
        "base-uri 'none'; "
        "frame-ancestors 'none'; "
        "form-action 'self'"
    ),
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
}


class _RateLimiter:
    """Limitador en memoria por IP (ventana deslizante)."""

    def __init__(self, max_requests: int, window: float) -> None:
        self.max_requests = max_requests
        self.window = window
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def is_limited(self, key: str) -> bool:
        now = time.monotonic()
        q = self._hits[key]
        cutoff = now - self.window
        while q and q[0] < cutoff:
            q.popleft()
        if len(q) >= self.max_requests:
            return True
        q.append(now)
        # Evitar crecimiento indefinido del diccionario (limpieza periódica).
        if len(self._hits) > 10_000:
            self._evict(now)
        return False

    def _evict(self, now: float) -> None:
        cutoff = now - self.window
        for k in [k for k, q in self._hits.items() if not q or q[-1] < cutoff]:
            del self._hits[k]


def _new_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def _check_csrf() -> None:
    """Verifica el token CSRF del formulario contra el de la sesión."""
    token = session.get("csrf_token")
    submitted = request.form.get("csrf_token", "")
    if not token or not submitted or not hmac.compare_digest(token, submitted):
        abort(403, description="Token CSRF inválido o ausente.")


def create_app() -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static")
    # Secret key: en producción DEBE definirse vía entorno. Sin él, se genera
    # una efímera por proceso (los tokens CSRF no sobreviven reinicios, lo que
    # es aceptable para uso local pero no para producción).
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY") or secrets.token_urlsafe(32)
    app.config["MAX_CONTENT_LENGTH"] = 8 * 1024  # limita cuerpo POST
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["SESSION_COOKIE_SECURE"] = app.config.get("SESSION_COOKIE_SECURE", False)

    limiter = _RateLimiter(WEB_RATE_MAX_REQUESTS, WEB_RATE_WINDOW_SECONDS)

    @app.before_request
    def _gate():
        if request.path == "/" and request.method == "POST":
            # Rate limiting por IP de cliente. Detrás de un proxy, configura
            # ProxyFix para que remote_addr sea real.
            if limiter.is_limited(request.remote_addr or "unknown"):
                abort(429, description="Demasiadas peticiones. Inténtalo más tarde.")
            _check_csrf()

    @app.after_request
    def _headers(resp):
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        for k, v in _SECURITY_HEADERS.items():
            resp.headers[k] = v
        if request.is_secure:
            resp.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains; preload"
            )
        return resp

    @app.get("/")
    def index():
        # Renovar el token CSRF si no existe o por seguridad se rota por sesión.
        if "csrf_token" not in session:
            session["csrf_token"] = _new_csrf_token()
        return render_template("index.html", csrf_token=session["csrf_token"])

    @app.post("/")
    def compute():
        action = request.form.get("action", "info").strip()
        network = request.form.get("network", "").strip()
        title = ""
        body = ""
        error = None

        try:
            if action == "info":
                info = analyze(network)
                title = f"Análisis de {info.input}"
                body = info_to_html_table(info)

            elif action == "split":
                count = request.form.get("count", "").strip()
                hosts = request.form.get("hosts", "").strip()
                if count:
                    results = split_network(network, count=int(count))
                    title = f"{network} → {int(count)} subredes"
                else:
                    h = int(hosts) if hosts else 1
                    results = split_network(network, hosts=h)
                    title = f"{network} → subredes de ≥{h} hosts"
                body = list_to_html_table(results, SUBNET_COLS, SUBNET_TITLES)

            elif action == "vlsm":
                needs_raw = request.form.get("needs", "").strip()
                needs = [int(x.strip()) for x in needs_raw.split(",") if x.strip()]
                res = vlsm_allocate(network, needs)
                title = f"VLSM sobre {network}"
                sections = [list_to_html_table(res["assignments"], VLSM_COLS, VLSM_TITLES)]
                if res["free_blocks"]:
                    # Escape defensivo aunque los bloques estén validados.
                    items = "".join(
                        f"<li><code>{escape(b)}</code></li>" for b in res["free_blocks"]
                    )
                    free = f"<ul class='free'>{items}</ul>"
                    sections.append(f"<h3>Bloques libres ({res['free_count']})</h3>{free}")
                body = "".join(sections)

            elif action == "supernet":
                raw_nets = request.form.get("networks", "").split()
                networks = [n.strip() for n in raw_nets if n.strip()]
                res = summarize(networks)
                title = "Supernetting / CIDR"
                kv = {
                    "Redes de entrada": res["input_count"],
                    "Bloques resultantes": res["collapsed_count"],
                    "¿Supernet única?": "sí" if res["is_single_supernet"] else "no",
                    "Total de direcciones": res["total_addresses_collapsed"],
                    "Primera dirección": res["first_address"],
                    "Última dirección": res["last_address"],
                    "Collapsed": ", ".join(res["collapsed"]),
                }
                spanning_html = ""
                if res["spanning"]:
                    spanning_html = (
                        f"<h3>Spanning</h3><p><code>{escape(', '.join(res['spanning']))}</code></p>"
                    )
                body = info_to_html_table(kv) + spanning_html

            elif action == "verify":
                ip = request.form.get("ip", "").strip()
                ver = verify_ip(ip, network)
                title = f"Verificación de {ver.ip}"
                body = info_to_html_table(ver)

            else:
                error = "Acción desconocida."

        except SubnetError as exc:
            error = str(exc)
        except (ValueError, TypeError) as exc:
            error = f"Entrada inválida: {exc}"

        return render_template(
            "result.html",
            title=title,
            body=body,
            error=error,
            action=action,
            csrf_token=session.get("csrf_token", ""),
        )

    return app


app = create_app()


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    # Debug SOLO si se pide explícitamente; el debugger de Werkzeug permite RCE
    # si queda expuesto en producción.
    debug = os.environ.get("FLASK_DEBUG") == "1"
    app.run(host="127.0.0.1", port=port, debug=debug)
