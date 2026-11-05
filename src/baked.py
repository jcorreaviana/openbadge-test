"""Badge "baked": a credencial JWT-VC assinada embutida no SVG da conquista.

Uso: ``python -m src.baked [--alg RS256]``. Grava ``out/badge_baked.svg``,
extrai o token de volta do arquivo e o verifica com ``OB3Verifier``.

A chave e o algoritmo são os do fluxo atual (``jwt_key_for``): RS256 e ES256
vêm do keystore de teste; EdDSA usa uma chave efêmera.
"""

import argparse
import sys
from pathlib import Path

from openbadgeslib.ob3 import (OB3Signer, OB3VerificationError, OB3Verifier,
                               OpenBadgeCredential)

from .images import ACHIEVEMENT_ART, achievement_with_art, issuer_with_logo
from .issue import RECIPIENT_ID, build_credential, jwt_key_for
from .keys import ALGORITHMS, JwtKey, generate_keys
from .verify import verify_jwt

OUT_DIR = Path("out")
BAKED_NAME = "badge_baked.svg"


def build_visual_credential(key: JwtKey) -> OpenBadgeCredential:
    return build_credential(issuer_with_logo(key.issuer_id), achievement_with_art())


def bake(key: JwtKey, credential: OpenBadgeCredential,
         svg_bytes: bytes | None = None) -> bytes:
    """Assina a credencial e a embute no SVG (por padrão, o selo da conquista)."""
    art = ACHIEVEMENT_ART.read_bytes() if svg_bytes is None else svg_bytes
    return OB3Signer(key.private_pem, algorithm=key.alg).sign_into_svg(credential, art)


def extract_token(svg_bytes: bytes) -> str:
    return OB3Verifier.extract_token_from_svg(svg_bytes)


def verify_baked(svg_bytes: bytes, public_pem: bytes,
                 expected_recipient: str = RECIPIENT_ID) -> OpenBadgeCredential:
    """Extrai o token do SVG e verifica assinatura, validade e destinatário."""
    return verify_jwt(extract_token(svg_bytes), public_pem, expected_recipient)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--alg", choices=ALGORITHMS, default="RS256")
    alg = parser.parse_args(argv).alg

    key = jwt_key_for(alg, generate_keys())
    OUT_DIR.mkdir(exist_ok=True)
    path = OUT_DIR / BAKED_NAME
    path.write_bytes(bake(key, build_visual_credential(key)))
    print(path)

    try:
        credential = verify_baked(path.read_bytes(), key.public_pem)
    except OB3VerificationError as exc:
        print(f"FALHA na verificação do badge baked: {exc}", file=sys.stderr)
        return 1
    print(f"alg={alg} emissor={key.issuer_id} conquista='{credential.achievement.name}'")
    print("token extraído do SVG e verificado com OB3Verifier")
    return 0


if __name__ == "__main__":
    sys.exit(main())
