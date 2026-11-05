"""Emissor e conquista com imagem, para a parte visual do badge.

As imagens vão embutidas na credencial como ``data:image/svg+xml;base64,...``:
as URLs de ``example.com`` não existem, e a biblioteca aceita ``data:`` URI
no campo ``image.id`` tanto em JWT-VC quanto em Data Integrity (testado).

O fluxo de emissão existente (``src/issue.py``) não muda: aqui só se copiam
o emissor e a conquista dele, acrescentando a imagem.
"""

import base64
import dataclasses
from pathlib import Path

from openbadgeslib.ob3 import Achievement, Issuer

from .issue import build_achievements, build_issuer

ASSETS_DIR = Path(__file__).resolve().parent.parent / "assets"
ISSUER_LOGO = ASSETS_DIR / "issuer-logo.svg"
ACHIEVEMENT_ART = ASSETS_DIR / "achievement-python-basico.svg"

SVG_DATA_PREFIX = "data:image/svg+xml;base64,"


def svg_data_uri(path: Path) -> str:
    return SVG_DATA_PREFIX + base64.b64encode(path.read_bytes()).decode("ascii")


def decode_svg_data_uri(uri: str) -> bytes:
    if not uri.startswith(SVG_DATA_PREFIX):
        raise ValueError("não é um data: URI de SVG em base64")
    return base64.b64decode(uri[len(SVG_DATA_PREFIX):], validate=True)


def issuer_with_logo(issuer_id: str) -> Issuer:
    return dataclasses.replace(build_issuer(issuer_id),
                               image_url=svg_data_uri(ISSUER_LOGO))


def achievement_with_art() -> Achievement:
    """A conquista "Python Básico" do fluxo atual, com o desenho do selo."""
    return dataclasses.replace(build_achievements()[0],
                               image_url=svg_data_uri(ACHIEVEMENT_ART))
