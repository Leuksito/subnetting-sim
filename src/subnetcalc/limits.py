"""Límites de seguridad (anti-DoS).

Estas constantes acotan la memoria y el tiempo de CPU cuando la entrada del
usuario podría generar resultados desproporcionadamente grandes (p. ej.
``split 0.0.0.0/0 --hosts 1`` produciría 2^32 subredes). Son lo suficientemente
amplias para cualquier uso legítimo de estudio y bloquean los abusos obvios.
"""

from __future__ import annotations

# Longitud máxima de una cadena de entrada (IP/red). Una red IPv6 comprimida
# con /128 no supera los ~45 caracteres; 256 deja margen amplio.
MAX_INPUT_LENGTH = 256

# Número máximo de subredes que devolverá ``split_network``. Suficiente para
# dividir un /20 en /32 (4096) y bloquea intentos de materializar millones.
MAX_SUBNETS = 4096

# Número máximo de subredes en una petición VLSM.
MAX_VLSM_NEEDS = 256

# Máximo valor admisible para una necesidad de hosts en VLSM.
MAX_HOSTS_NEEDED = 1 << 31

# Número máximo de redes de entrada en supernetting.
MAX_SUPERNET_INPUTS = 256

# Rate limiting de la web: peticiones por ventana por IP.
WEB_RATE_MAX_REQUESTS = 30
WEB_RATE_WINDOW_SECONDS = 60
