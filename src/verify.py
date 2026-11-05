"""Verificação de Open Badges 3.0 e de CLR 2.0.

Toda falha é sinalizada com ``OB3VerificationError``. A chave pública do
emissor é sempre fixada pelo verificador (nunca lida do próprio token).
"""

import hmac
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from openbadgeslib.ob3 import (OB3LdpVerifier, OB3VerificationError,
                               OB3Verifier, OpenBadgeCredential,
                               bundled_clr_contexts,
                               verify_data_integrity_proof)

from .issue import hash_email


def verify_jwt(token: str, issuer_public_pem: bytes,
               expected_recipient: str) -> OpenBadgeCredential:
    """Verifica um badge JWT-VC (assinatura, validade e destinatário)."""
    return OB3Verifier(issuer_public_pem).verify(
        token, expected_recipient=expected_recipient, verify_status_list=False)


def verify_ldp(document: dict[str, Any], issuer_public_pem: bytes,
               expected_recipient: str) -> OpenBadgeCredential:
    """Verifica um badge com prova Data Integrity (eddsa-rdfc-2022)."""
    return OB3LdpVerifier(issuer_public_pem).verify(
        document, expected_recipient=expected_recipient,
        verify_status_list=False)


@dataclass
class ClrResult:
    clr_id: str
    issuer_id: str
    members: list[OpenBadgeCredential]


def verify_clr(clr: dict[str, Any], issuer_public_pem: bytes, issuer_did: str,
               expected_email: str) -> ClrResult:
    """Verifica um ClrCredential e cada badge membro dentro dele.

    A prova do envelope sozinha não basta: quem tiver uma chave válida pode
    adulterar um membro e reassinar o envelope. Por isso cada membro, que é
    um documento assinado por si só, também é verificado.

    Simplificação desta prova de conceito: todos os membros são do mesmo
    emissor do CLR e são verificados com a mesma chave pública.
    """
    # 1. Prova do envelope, com o contexto CLR 2.0.1 fixado por hash.
    verify_data_integrity_proof(clr, issuer_public_pem,
                                extra_contexts=bundled_clr_contexts())

    # 2. Tipo e vínculo do emissor com a chave que assinou.
    types = clr.get("type", [])
    if "ClrCredential" not in types:
        raise OB3VerificationError(f"tipo inesperado para um CLR: {types!r}")
    issuer = clr.get("issuer")
    issuer_id = issuer.get("id") if isinstance(issuer, dict) else issuer
    if issuer_id != issuer_did:
        raise OB3VerificationError(
            f"emissor do CLR {issuer_id!r} difere do esperado {issuer_did!r}")
    vm_did = clr["proof"]["verificationMethod"].partition("#")[0]
    if vm_did != issuer_did:
        raise OB3VerificationError(
            f"verificationMethod {vm_did!r} não pertence a {issuer_did!r}")

    # 3. Janela de validade.
    now = datetime.now(timezone.utc)
    valid_from = datetime.fromisoformat(clr["validFrom"])
    if valid_from > now:
        raise OB3VerificationError("CLR ainda não é válido (validFrom futuro)")
    if "validUntil" in clr and datetime.fromisoformat(clr["validUntil"]) <= now:
        raise OB3VerificationError("CLR expirado")

    # 4. Destinatário: o e-mail esperado precisa bater com algum hash.
    subject = clr["credentialSubject"]
    if not any(_identity_matches(i, expected_email)
               for i in subject.get("identifier", [])):
        raise OB3VerificationError(
            "nenhum identifier do CLR corresponde ao destinatário esperado")

    # 5. Cada badge membro é verificado como documento assinado independente.
    members_raw = subject.get("verifiableCredential", [])
    if not members_raw:
        raise OB3VerificationError("CLR sem credenciais membro")
    members = []
    for index, member in enumerate(members_raw):
        try:
            members.append(verify_ldp(member, issuer_public_pem,
                                      f"mailto:{expected_email}"))
        except OB3VerificationError as exc:
            raise OB3VerificationError(
                f"badge membro #{index} inválido: {exc}") from exc

    return ClrResult(clr_id=clr["id"], issuer_id=issuer_id, members=members)


def _identity_matches(identity: dict[str, Any], email: str) -> bool:
    if identity.get("identityType") != "emailAddress":
        return False
    expected = (hash_email(email, identity.get("salt") or "")
                if identity.get("hashed") else email)
    return hmac.compare_digest(str(identity.get("identityHash", "")), expected)
