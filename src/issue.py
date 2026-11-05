"""Emissão de Open Badges 3.0 (JWT-VC e Data Integrity) e de um CLR 2.0.

Tudo é fictício e roda offline: emissor, conquistas e destinatário usam
``example.com``.
"""

import hashlib
import secrets
from dataclasses import dataclass
from typing import Any

from openbadgeslib.ob3 import (Achievement, IdentityObject, Issuer,
                               OB3LdpSigner, OB3Signer, OpenBadgeCredential,
                               build_clr_credential, sign_clr_credential)

from .keys import IssuerKeys, JwtKey, jwt_key_from_pems

RECIPIENT_EMAIL = "ana.souza@example.com"
# Formato fixado após testar com e sem o prefixo (ver README).
RECIPIENT_ID = f"mailto:{RECIPIENT_EMAIL}"


@dataclass
class IssuedSet:
    issuer: Issuer                # emissor Ed25519 (Data Integrity e CLR)
    achievements: list[Achievement]
    jwt_key: JwtKey               # chave e algoritmo dos JWT-VC
    jwt_issuer: Issuer            # emissor dos JWT-VC
    jwts: list[str]               # um JWT-VC por conquista
    ldp_docs: list[dict[str, Any]]  # mesmas conquistas com Data Integrity
    clr: dict[str, Any]           # ClrCredential assinado, com ldp_docs dentro
    salt: str                     # salt usado no hash do e-mail


def hash_email(email: str, salt: str) -> str:
    """SHA-256 de ``email + salt`` no formato ``sha256$<hex>`` do OB 3.0."""
    return "sha256$" + hashlib.sha256((email + salt).encode()).hexdigest()


def build_issuer(issuer_id: str) -> Issuer:
    return Issuer(id=issuer_id, name="Escola Exemplo",
                  url="https://example.com", email="contato@example.com")


def build_achievements() -> list[Achievement]:
    return [
        Achievement(
            id="https://example.com/achievements/python-basico",
            name="Python Básico",
            description="Fundamentos de programação em Python.",
            criteria_narrative="Concluiu os exercícios e o projeto final.",
            achievement_type="Badge",
        ),
        Achievement(
            id="https://example.com/achievements/credenciais-verificaveis",
            name="Credenciais Verificáveis",
            description="Emissão e verificação de credenciais W3C.",
            criteria_narrative="Emitiu e verificou um Open Badge 3.0.",
            achievement_type="Badge",
        ),
    ]


def build_credential(issuer: Issuer, achievement: Achievement) -> OpenBadgeCredential:
    return OpenBadgeCredential(issuer=issuer, recipient_id=RECIPIENT_ID,
                               achievement=achievement)


def jwt_key_for(alg: str, keys: IssuerKeys) -> JwtKey:
    """EdDSA usa o par Ed25519 em memória; RS256 e ES256 usam o keystore."""
    if alg == "EdDSA":
        return jwt_key_from_pems(alg, keys.private_pem, keys.public_pem)
    from .keystore import load_or_create
    stored = load_or_create({"RS256": "rsa", "ES256": "ec"}[alg])
    return jwt_key_from_pems(alg, stored.private_pem, stored.public_pem)


def issue_jwt(key: JwtKey, credential: OpenBadgeCredential) -> str:
    return OB3Signer(key.private_pem, algorithm=key.alg).sign(credential)


def issue_ldp(keys: IssuerKeys, credential: OpenBadgeCredential) -> dict[str, Any]:
    signer = OB3LdpSigner(keys.private_pem,
                          verification_method=keys.verification_method)
    return signer.sign(credential)


def issue_clr(keys: IssuerKeys, issuer: Issuer, members: list[dict[str, Any]],
              salt: str) -> dict[str, Any]:
    identity = IdentityObject(
        identity_hash=hash_email(RECIPIENT_EMAIL, salt),
        identity_type="emailAddress", hashed=True, salt=salt,
    ).to_dict()
    document = build_clr_credential(
        issuer.to_dict(), [identity], members,
        credential_id=f"urn:uuid:{secrets.token_hex(16)}",
    )
    return sign_clr_credential(document, keys.private_pem,
                               keys.verification_method)


def issue_all(keys: IssuerKeys, alg: str = "EdDSA") -> IssuedSet:
    issuer = build_issuer(keys.did)
    jwt_key = jwt_key_for(alg, keys)
    jwt_issuer = issuer if alg == "EdDSA" else build_issuer(jwt_key.issuer_id)
    achievements = build_achievements()
    jwts, ldp_docs = [], []
    for achievement in achievements:
        jwts.append(issue_jwt(jwt_key, build_credential(jwt_issuer, achievement)))
        # Credencial nova (outro id) para a versão Data Integrity.
        ldp_docs.append(issue_ldp(keys, build_credential(issuer, achievement)))
    salt = secrets.token_hex(16)
    clr = issue_clr(keys, issuer, ldp_docs, salt)
    return IssuedSet(issuer, achievements, jwt_key, jwt_issuer, jwts,
                     ldp_docs, clr, salt)
