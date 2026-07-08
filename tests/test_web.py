"""Tests de la web Flask (incluye CSRF, headers y rate limiting)."""

import pytest

from subnetcalc.web.app import create_app


@pytest.fixture()
def client():
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


def _csrf(client) -> bytes:
    """Obtiene un token CSRF válido haciendo GET / y leyéndolo de la sesión."""
    client.get("/")
    with client.session_transaction() as sess:
        return sess["csrf_token"].encode()


def test_index_get(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert b"Simulador de subnetting" in resp.data
    assert b"<form" in resp.data
    # El campo CSRF debe estar presente
    assert b"csrf_token" in resp.data


def test_index_post_sin_csrf_es_403(client):
    resp = client.post("/", data={"action": "info", "network": "192.168.1.10/24"})
    assert resp.status_code == 403


def test_index_post_csrf_invalido_es_403(client):
    resp = client.post(
        "/",
        data={"action": "info", "network": "192.168.1.10/24", "csrf_token": "falso"},
    )
    assert resp.status_code == 403


def test_index_post_info(client):
    token = _csrf(client)
    resp = client.post(
        "/",
        data={"action": "info", "network": "192.168.1.10/24", "csrf_token": token},
    )
    assert resp.status_code == 200
    assert b"192.168.1.0/24" in resp.data
    assert b"Broadcast" in resp.data


def test_index_post_split(client):
    token = _csrf(client)
    resp = client.post(
        "/",
        data={
            "action": "split",
            "network": "10.0.0.0/24",
            "count": "4",
            "csrf_token": token,
        },
    )
    assert resp.status_code == 200
    assert b"10.0.0.0/26" in resp.data


def test_index_post_vlsm(client):
    token = _csrf(client)
    resp = client.post(
        "/",
        data={
            "action": "vlsm",
            "network": "172.16.0.0/16",
            "needs": "100,50,25,25,2",
            "csrf_token": token,
        },
    )
    assert resp.status_code == 200
    assert b"VLSM" in resp.data


def test_index_post_supernet(client):
    token = _csrf(client)
    resp = client.post(
        "/",
        data={
            "action": "supernet",
            "networks": "192.168.0.0/24 192.168.1.0/24 192.168.2.0/24 192.168.3.0/24",
            "csrf_token": token,
        },
    )
    assert resp.status_code == 200
    assert b"192.168.0.0/22" in resp.data


def test_index_post_verify(client):
    token = _csrf(client)
    resp = client.post(
        "/",
        data={
            "action": "verify",
            "network": "192.168.1.0/24",
            "ip": "192.168.1.50",
            "csrf_token": token,
        },
    )
    assert resp.status_code == 200
    assert b"host" in resp.data.lower()


def test_index_post_error_capturado(client):
    token = _csrf(client)
    resp = client.post(
        "/",
        data={"action": "info", "network": "no-es-una-red", "csrf_token": token},
    )
    assert resp.status_code == 200
    assert b"Error" in resp.data


def test_security_headers_presentes(client):
    resp = client.get("/")
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert "Content-Security-Policy" in resp.headers
    assert "frame-ancestors 'none'" in resp.headers["Content-Security-Policy"]
    assert "script-src 'self'" in resp.headers["Content-Security-Policy"]
    assert resp.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"


def test_csp_sin_unsafe_inline(client):
    # La CSP no debe permitir inline (ni scripts ni estilos).
    csp = client.get("/").headers["Content-Security-Policy"]
    assert "unsafe-inline" not in csp
    assert "unsafe-eval" not in csp


def test_rate_limiting_tras_umbral(client):
    # WEB_RATE_MAX_REQUESTS = 30; la petición 31 debe dar 429.
    token = _csrf(client)
    data = {
        "action": "info",
        "network": "192.168.1.10/24",
        "csrf_token": token,
    }
    for _ in range(30):
        r = client.post("/", data=data)
        assert r.status_code == 200, "las 30 primeras deben pasar"
    r31 = client.post("/", data=data)
    assert r31.status_code == 429


def test_max_content_length_rejects_oversized(client):
    token = _csrf(client)
    huge = "x" * (20 * 1024)  # 20 KB > 8 KB
    resp = client.post(
        "/",
        data={"action": "info", "network": huge, "csrf_token": token},
    )
    assert resp.status_code == 413
