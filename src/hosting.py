"""Site estático do emissor em ``docs/``, para publicar pelo GitHub Pages.

Uso: ``python -m src.hosting [--base-url URL] [--docs-dir PASTA]``.

A URL base vem de ``--base-url``, senão de ``$OPENBADGE_BASE_URL``, senão de
``DEFAULT_BASE_URL``. Os arquivos gerados contêm só a chave PÚBLICA RSA do
keystore (``~/.openbadge-test/keys/``):

- ``issuer.json``: perfil do emissor (``Profile`` OB 3.0 em JSON-LD), com
  ``id`` igual à própria URL;
- ``issuer-key.json``: a chave pública como um JWK único. É para onde aponta o
  ``kid`` dos badges hospedados (OB 3.0 §8.2.3: o ``kid`` é uma URI que, ao ser
  desreferenciada, devolve um JWK);
- ``jwks.json``: a mesma chave em um JWK Set (RFC 7517 §5);
- ``did.json``: documento ``did:web`` com a mesma chave (``JsonWebKey2020``).
"""

import argparse
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from openbadgeslib.keys import public_jwk_from_pem
from openbadgeslib.ob3 import Issuer, build_did_document, did_web_from_url

from .keystore import PROJECT_ROOT

DEFAULT_BASE_URL = "https://jcorreaviana.github.io/openbadge-test"
BASE_URL_ENV = "OPENBADGE_BASE_URL"
DOCS_DIR = PROJECT_ROOT / "docs"

PROFILE_FILE = "issuer.json"
JWK_FILE = "issuer-key.json"
JWKS_FILE = "jwks.json"
DID_FILE = "did.json"
DID_KEY_FRAGMENT = "key-1"

PROFILE_CONTEXT = ["https://www.w3.org/ns/credentials/v2",
                   "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json"]

# Membros de JWK que só existem em chave privada (RFC 7518 §6.2.2, §6.3.2,
# §6.4.1; RFC 8037 §2). Nenhum deles pode aparecer em docs/.
PRIVATE_JWK_MEMBERS = frozenset({"d", "p", "q", "dp", "dq", "qi", "oth", "k"})


@dataclass(frozen=True)
class Site:
    """URLs públicas do emissor, todas derivadas da URL base."""
    base_url: str

    @property
    def profile_url(self) -> str:
        return f"{self.base_url}/{PROFILE_FILE}"

    @property
    def key_url(self) -> str:  # valor do "kid" dos badges hospedados
        return f"{self.base_url}/{JWK_FILE}"

    @property
    def jwks_url(self) -> str:
        return f"{self.base_url}/{JWKS_FILE}"

    @property
    def did(self) -> str:
        return did_web_from_url(self.base_url)

    @property
    def did_verification_method(self) -> str:
        return f"{self.did}#{DID_KEY_FRAGMENT}"


def normalize_base_url(url: str) -> str:
    """Remove a barra final e exige uma URL https válida para did:web."""
    url = url.strip().rstrip("/")
    did_web_from_url(url)  # ValueError se não for https, sem host, com "@"...
    return url


def site_from(base_url: str | None = None) -> Site:
    """URL do argumento, senão do ambiente, senão a padrão."""
    return Site(normalize_base_url(
        base_url or os.environ.get(BASE_URL_ENV) or DEFAULT_BASE_URL))


# ── conteúdo dos arquivos ────────────────────────────────────────────────────

def find_private_members(value: Any, path: str = "$") -> list[str]:
    """Caminhos de todo membro privado de JWK em qualquer nível do JSON."""
    found = []
    if isinstance(value, dict):
        for key, item in value.items():
            if key in PRIVATE_JWK_MEMBERS:
                found.append(f"{path}.{key}")
            found += find_private_members(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            found += find_private_members(item, f"{path}[{index}]")
    return found


def public_jwk(public_pem: bytes) -> dict[str, Any]:
    """JWK público RSA para RS256. Recusa qualquer coisa que não seja RSA."""
    jwk = public_jwk_from_pem(public_pem)
    if jwk.get("kty") != "RSA":
        raise ValueError(f"o site hospeda só chave RSA, recebi kty={jwk.get('kty')!r}")
    jwk = {k: v for k, v in jwk.items() if k != "key_ops"}
    return {**jwk, "alg": "RS256", "use": "sig"}


def hosted_issuer(site: Site) -> Issuer:
    """Emissor dos badges hospedados: o id é a URL do perfil publicado."""
    return Issuer(id=site.profile_url, name="Escola Exemplo",
                  url=site.base_url, email="contato@example.com")


def build_profile(site: Site) -> dict[str, Any]:
    return {"@context": PROFILE_CONTEXT, **hosted_issuer(site).to_dict(),
            "description": "Emissor fictício para testes. Não emite credenciais reais."}


def build_site_files(site: Site, public_pem: bytes) -> dict[str, dict[str, Any]]:
    """Nome do arquivo -> conteúdo JSON. Falha se sobrar algum campo privado."""
    jwk = public_jwk(public_pem)
    files = {
        PROFILE_FILE: build_profile(site),
        JWK_FILE: {**jwk, "kid": site.key_url},
        JWKS_FILE: {"keys": [{**jwk, "kid": site.key_url}]},
        DID_FILE: build_did_document(site.did, [(DID_KEY_FRAGMENT, jwk)]),
    }
    leaked = find_private_members(files)
    if leaked:  # defesa extra: public_jwk_from_pem já só devolve parte pública
        raise ValueError(f"campos privados no site: {', '.join(leaked)}")
    return files


def write_site(site: Site, public_pem: bytes, docs_dir: Path = DOCS_DIR) -> list[Path]:
    docs_dir.mkdir(parents=True, exist_ok=True)
    paths = []
    for name, content in build_site_files(site, public_pem).items():
        path = docs_dir / name
        path.write_text(json.dumps(content, indent=2, ensure_ascii=False) + "\n",
                        encoding="utf-8")
        paths.append(path)
    return paths


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--base-url", help=f"URL base do site (padrão: ${BASE_URL_ENV} "
                                           f"ou {DEFAULT_BASE_URL})")
    parser.add_argument("--docs-dir", type=Path, default=DOCS_DIR,
                        help="pasta de saída (padrão: docs/)")
    args = parser.parse_args(argv)

    from .keystore import load_or_create
    site = site_from(args.base_url)
    paths = write_site(site, load_or_create("rsa").public_pem, args.docs_dir)
    for path in paths:
        print(path)
    print(f"perfil: {site.profile_url}")
    print(f"kid:    {site.key_url}")
    print(f"did:    {site.did}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
