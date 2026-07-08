"""Saneamiento de texto para mostrar al usuario.

Evita la inyección en terminal (ANSI bombing / title spoofing) y la fuga de
caracteres de control al loguear o devolver entradas arbitrarias del usuario.
Las direcciones IP validadas por ``ipaddress`` no contienen caracteres de
control, pero aplicamos defensa en profundidad en todos los puntos de eco.
"""

from __future__ import annotations

import re

# Secuencias de escape CSI/SS3 de terminal (ESC [ ... letra, ESC ] ... BEL, etc.)
_ANSI_CSI_RE = re.compile(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")
_ANSI_RE = re.compile(r"\x1b[@-_][0-9;?]*[@-~]")
# Caracteres de control C0 (0x00-0x1F) y DEL + C1 (0x7F-0x9F). Se mantiene el
# tab, newline y retorno solo cuando se permite multilínea.
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")


def sanitize_for_display(text: object, *, multiline: bool = False) -> str:
    """Devuelve una representación segura para mostrar del texto.

    - Elimina secuencias de escape ANSI completas.
    - Elimina el resto de caracteres de control (salvo \\t, \\n, \\r si
      ``multiline`` es True).
    """
    s = "" if text is None else str(text)
    s = _ANSI_CSI_RE.sub("", s)
    s = _ANSI_RE.sub("", s)
    if multiline:
        s = s.replace("\r\n", "\n").replace("\r", "\n")
        s = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]", "", s)
    else:
        s = _CONTROL_RE.sub("", s)
    return s
