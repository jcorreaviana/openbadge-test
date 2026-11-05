"""Emite um badge fictício como JWT-VC e grava em ``out/badge_<alg>.jwt``.

Uso: ``python -m src.export --alg RS256 [--hosted [--base-url URL]]``. Com
RS256 ou ES256 a chave vem do keystore de teste (``src/keystore.py``), então o
mesmo emissor é reutilizado entre execuções. Com EdDSA a chave é efêmera, só
em memória.

Com ``--hosted`` (só RS256), o badge usa como ``issuer.id`` a URL do perfil
publicado em ``docs/`` e referencia a chave pelo ``kid`` (sem ``jwk``), e vai
para ``out/badge_rs256_hosted.jwt``. Gere ``docs/`` antes com
``python -m src.hosting``.

Depois de gravar, relê o arquivo exatamente como gravado (sem ``strip``) e o
verifica; sai com código 1 se a verificação falhar. O badge comum é verificado
com a chave pública do emissor; o hospedado, só com os arquivos de ``docs/``.
"""

import argparse
import sys
from pathlib import Path

from openbadgeslib.ob3 import OB3VerificationError

from . import hosting
from .issue import (RECIPIENT_ID, build_achievements, build_credential, build_issuer,
                    issue_jwt, jwt_key_for)
from .keys import ALGORITHMS, generate_keys
from .verify import verify_jwt

OUT_DIR = Path("out")


def write_token(path: Path, token: str) -> None:
    # Sem "\n" final: validadores que não fazem strip leem o "\n" como parte
    # da assinatura e a rejeitam (o java-jwt do validador da 1EdTech, o PyJWT).
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(token)


def export_plain(alg: str) -> int:
    key = jwt_key_for(alg, generate_keys())
    credential = build_credential(build_issuer(key.issuer_id),
                                  build_achievements()[0])
    path = OUT_DIR / f"badge_{alg.lower()}.jwt"
    write_token(path, issue_jwt(key, credential))

    print(path)
    print(f"alg={alg} emissor={key.issuer_id} "
          f"conquista='{credential.achievement.name}' id={credential.id}")

    try:
        verify_jwt(path.read_text(), key.public_pem, RECIPIENT_ID)
    except OB3VerificationError as exc:
        print(f"FALHA na verificação local: {exc}", file=sys.stderr)
        return 1
    origin = "keystore" if alg != "EdDSA" else "em memória"
    print(f"verificado localmente com OB3Verifier (chave pública {origin})")
    return 0


def export_hosted(base_url: str | None, docs_dir: Path) -> int:
    from .keystore import load_or_create
    site = hosting.site_from(base_url)
    token = hosting.issue_hosted(site, load_or_create("rsa").private_pem,
                                 build_achievements()[0])
    path = OUT_DIR / "badge_rs256_hosted.jwt"
    write_token(path, token)

    print(path)
    print(f"alg=RS256 emissor={site.profile_url}")
    print(f"kid={site.key_url}")

    try:
        credential = hosting.verify_hosted(path.read_text(), site, RECIPIENT_ID,
                                           docs_dir)
    except OB3VerificationError as exc:
        print(f"FALHA na verificação a partir de {docs_dir}: {exc}", file=sys.stderr)
        print("se a chave ou a URL mudou, regenere com: python -m src.hosting",
              file=sys.stderr)
        return 1
    print(f"verificado a partir de {docs_dir}/ (kid, JWKS, did.json e perfil), "
          f"sem keystore: '{credential.achievement.name}'")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--alg", choices=ALGORITHMS, default="RS256",
                        help="algoritmo da assinatura (padrão: RS256)")
    parser.add_argument("--hosted", action="store_true",
                        help="emissor e chave publicados em docs/ (só RS256)")
    parser.add_argument("--base-url", help="URL base do site (com --hosted; padrão: "
                                           f"${hosting.BASE_URL_ENV} ou "
                                           f"{hosting.DEFAULT_BASE_URL})")
    parser.add_argument("--docs-dir", type=Path, default=hosting.DOCS_DIR,
                        help="pasta com os arquivos publicados (com --hosted)")
    args = parser.parse_args(argv)

    if not args.hosted:
        if args.base_url:
            parser.error("--base-url só faz sentido com --hosted")
        return export_plain(args.alg)
    if args.alg != "RS256":
        parser.error("--hosted só é suportado com --alg RS256")
    return export_hosted(args.base_url, args.docs_dir)


if __name__ == "__main__":
    sys.exit(main())
