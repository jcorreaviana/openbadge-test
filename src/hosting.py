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

Também emite badges com ``kid`` (``KidSigner``) e os verifica lendo só esses
arquivos (``verify_hosted``), sem usar o keystore.
"""

import argparse
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import jwt
from openbadgeslib.keys import public_jwk_from_pem
from openbadgeslib.ob3 import (Achievement, Issuer, OB3Signer, OB3VerificationError,
                               OpenBadgeCredential, build_did_document,
                               did_web_from_url, resolve_verification_method)
from openbadgeslib.ob3.did import _jwk_to_pem  # mesma conversão usada no did:web

from .issue import RECIPIENT_ID
from .keystore import PROJECT_ROOT
from .verify import verify_jwt

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


# ── emissão com kid ──────────────────────────────────────────────────────────

class KidSigner(OB3Signer):
    """``OB3Signer`` com cabeçalho ``{"kid": ...}`` no lugar do ``jwk``.

    A biblioteca fixa o cabeçalho em ``{"jwk": ...}`` (``sign_payload``) e não
    aceita campos extras. Aqui só o cabeçalho muda: payload, chave e algoritmo
    são os mesmos do ``OB3Signer``. Sem o ``jwk``, quem verifica é obrigado a
    buscar a chave pelo ``kid``, que é o que se quer testar.
    """

    def __init__(self, privkey_pem: Any, kid: str, algorithm: str = "RS256") -> None:
        super().__init__(privkey_pem, algorithm=algorithm)
        self.kid = kid

    def sign_payload(self, payload: dict[str, Any]) -> str:
        return jwt.encode(payload, self._load_privkey(), algorithm=self.algorithm,
                          headers={"kid": self.kid})


def issue_hosted(site: Site, private_pem: bytes, achievement: Achievement) -> str:
    credential = OpenBadgeCredential(issuer=hosted_issuer(site),
                                     recipient_id=RECIPIENT_ID, achievement=achievement)
    return KidSigner(private_pem, kid=site.key_url).sign(credential)


# ── verificação só com os arquivos publicados ────────────────────────────────

def local_path(site: Site, url: str, docs_dir: Path = DOCS_DIR) -> Path:
    """Arquivo de ``docs_dir`` que será servido em ``url``.

    Só aceita URLs do próprio site, sem query, fragmento ou ``..``: o ``kid``
    vem do token, que não é confiável antes da verificação.
    """
    prefix = site.base_url + "/"
    if not url.startswith(prefix) or any(c in url for c in "?#\\"):
        raise OB3VerificationError(f"URL fora do site publicado: {url!r}")
    relative = url[len(prefix):]
    if not relative or any(part in ("", ".", "..") for part in relative.split("/")):
        raise OB3VerificationError(f"caminho inválido no site publicado: {url!r}")
    base = docs_dir.resolve()
    path = (base / relative).resolve()
    if base not in path.parents:
        raise OB3VerificationError(f"caminho fora de docs/: {url!r}")
    return path


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise OB3VerificationError(f"não consegui ler {path.name}: {exc}") from exc
    if not isinstance(value, dict):
        raise OB3VerificationError(f"{path.name} não é um objeto JSON")
    return value


def _rsa_public(jwk: dict[str, Any]) -> tuple[Any, Any, Any]:
    return jwk.get("kty"), jwk.get("n"), jwk.get("e")


def verify_hosted(token: str, site: Site, expected_recipient: str,
                  docs_dir: Path = DOCS_DIR) -> OpenBadgeCredential:
    """Verifica um badge hospedado usando SÓ os arquivos de ``docs_dir``.

    Faz o caminho que um validador externo faria pela rede, trocando cada GET
    pela leitura do arquivo que o GitHub Pages vai servir naquela URL:

    1. o ``kid`` do cabeçalho é desreferenciado para um JWK (``issuer-key.json``);
    2. o JWKS publicado precisa conter a mesma chave sob o mesmo ``kid``;
    3. o ``did.json`` publicado, resolvido pela própria biblioteca, também;
    4. a assinatura é verificada com essa chave (``OB3Verifier``);
    5. o ``issuer.id`` do badge precisa ser o ``id`` do perfil publicado.
    """
    try:
        header = jwt.get_unverified_header(token)
    except jwt.exceptions.InvalidTokenError as exc:
        raise OB3VerificationError(f"JWT inválido: {exc}") from exc
    kid = header.get("kid")
    if not isinstance(kid, str):
        raise OB3VerificationError("o cabeçalho não tem kid")

    # 1. kid -> JWK publicado
    jwk = _read_json(local_path(site, kid, docs_dir))
    leaked = find_private_members(jwk)
    if leaked:
        raise OB3VerificationError(f"JWK publicado tem campos privados: {leaked}")
    if jwk.get("kid") != kid:
        raise OB3VerificationError("o JWK publicado não declara o kid do token")
    public_pem = _jwk_to_pem(jwk)

    # 2. JWKS
    jwks = _read_json(local_path(site, site.jwks_url, docs_dir))
    if not any(isinstance(k, dict) and k.get("kid") == kid
               and _rsa_public(k) == _rsa_public(jwk) for k in jwks.get("keys", [])):
        raise OB3VerificationError("o JWKS publicado não contém a chave do kid")

    # 3. did:web, resolvido pela biblioteca com "download" lendo de docs/
    def fetch(url: str) -> bytes:
        return local_path(site, url, docs_dir).read_bytes()
    if resolve_verification_method(site.did_verification_method, download=fetch) != public_pem:
        raise OB3VerificationError("o did.json publicado não contém a chave do kid")

    # 4. assinatura, validade e destinatário
    credential = verify_jwt(token, public_pem, expected_recipient)

    # 5. vínculo com o perfil publicado
    profile = _read_json(local_path(site, site.profile_url, docs_dir))
    if "Profile" not in (profile.get("type") or []):
        raise OB3VerificationError("o perfil publicado não é do tipo Profile")
    if profile.get("id") != site.profile_url or credential.issuer.id != profile["id"]:
        raise OB3VerificationError(
            f"issuer.id {credential.issuer.id!r} não é o perfil publicado "
            f"{profile.get('id')!r}")
    return credential


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
