"""Emite um badge fictício como JWT-VC e grava em ``out/badge_<alg>.jwt``.

Uso: ``python -m src.export --alg RS256``. Com RS256 ou ES256 a chave vem do
keystore de teste (``src/keystore.py``), então o mesmo emissor é reutilizado
entre execuções. Com EdDSA a chave é efêmera, só em memória.
"""

import argparse
import sys
from pathlib import Path

from .issue import (build_achievements, build_credential, build_issuer,
                    issue_jwt, jwt_key_for)
from .keys import ALGORITHMS, generate_keys

OUT_DIR = Path("out")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--alg", choices=ALGORITHMS, default="RS256",
                        help="algoritmo da assinatura (padrão: RS256)")
    alg = parser.parse_args(argv).alg

    key = jwt_key_for(alg, generate_keys())
    credential = build_credential(build_issuer(key.issuer_id),
                                  build_achievements()[0])
    token = issue_jwt(key, credential)

    OUT_DIR.mkdir(exist_ok=True)
    path = OUT_DIR / f"badge_{alg.lower()}.jwt"
    path.write_text(token + "\n")

    print(path)
    print(f"alg={alg} emissor={key.issuer_id} "
          f"conquista='{credential.achievement.name}' id={credential.id}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
