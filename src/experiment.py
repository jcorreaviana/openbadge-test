"""Experimento: o que a assinatura de um badge baked cobre?

Uso: ``python -m src.experiment`` (depois de ``python -m src.baked`` ou
``python -m src.visual``, com o mesmo ``--alg``).

Altera o DESENHO de ``out/badge_baked.svg`` sem tocar no elemento
``<openbadges:credential>`` e verifica de novo. Como controle, altera um
caractere do próprio token. Resultado observado (biblioteca 4.6.3): as
alterações no desenho passam; só a do token é rejeitada.
"""

import argparse
import re
import sys
from pathlib import Path

from openbadgeslib.ob3 import OB3VerificationError

from .baked import BAKED_NAME, OUT_DIR, extract_token, verify_baked
from .images import ISSUER_LOGO
from .issue import jwt_key_for
from .keys import ALGORITHMS, generate_keys

_CREDENTIAL_ELEMENT = re.compile(rb"<openbadges:credential\b[^>]*/>")


def credential_element(svg_bytes: bytes) -> bytes:
    match = _CREDENTIAL_ELEMENT.search(svg_bytes)
    if match is None:
        raise ValueError("SVG sem <openbadges:credential/>")
    return match.group(0)


def tamper_drawing(svg_bytes: bytes) -> bytes:
    """Troca a cor do selo e o texto visível; a credencial fica intacta."""
    tampered = (svg_bytes
                .replace(b'fill="#2e7d4f"', b'fill="#b22222"')
                .replace(b">Python<", b">Doutorado<")
                .replace("Básico".encode(), b"Honoris"))
    if tampered == svg_bytes:
        raise ValueError("o desenho não tem os elementos esperados")
    return tampered


def transplant(svg_bytes: bytes, target_svg: bytes) -> bytes:
    """Copia o elemento da credencial para outro SVG qualquer."""
    return target_svg.replace(b"</svg>", credential_element(svg_bytes) + b"</svg>")


def tamper_token(svg_bytes: bytes) -> bytes:
    """Controle: altera um caractere no meio do token (no payload)."""
    token = extract_token(svg_bytes)
    i = len(token) // 2
    forged = token[:i] + ("A" if token[i] != "A" else "B") + token[i + 1:]
    return svg_bytes.replace(token.encode(), forged.encode())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--alg", choices=ALGORITHMS, default="RS256")
    alg = parser.parse_args(argv).alg
    if alg == "EdDSA":
        parser.error("EdDSA usa chave efêmera; o badge salvo não pode ser reverificado")

    key = jwt_key_for(alg, generate_keys())
    original = (OUT_DIR / BAKED_NAME).read_bytes()
    cases = {
        "original": original,
        "cor e texto do desenho trocados": tamper_drawing(original),
        "credencial transplantada para o logo": transplant(original, ISSUER_LOGO.read_bytes()),
        "controle: 1 caractere do token alterado": tamper_token(original),
    }
    for label, data in cases.items():
        try:
            credential = verify_baked(data, key.public_pem)
            print(f"  PASSA     {label}  (nome assinado: '{credential.achievement.name}')")
        except OB3VerificationError as exc:
            print(f"  REJEITADO {label}  ({exc})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
