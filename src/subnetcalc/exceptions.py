"""Excepciones del paquete.

Definidas en un módulo aparte para evitar imports circulares entre
``core`` y ``limits``.
"""

from __future__ import annotations


class SubnetError(ValueError):
    """Entrada de red/IP no válida."""


class SecurityError(SubnetError):
    """Entrada rechazada por superar un límite de seguridad (anti-DoS)."""
