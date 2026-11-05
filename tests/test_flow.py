import copy

import pytest
from openbadgeslib.ob3 import (OB3Signer, OB3VerificationError,
                               bundled_clr_contexts, sign_clr_credential,
                               verify_data_integrity_proof)

from src.demo import tamper_jwt_payload
from src.issue import (RECIPIENT_EMAIL, RECIPIENT_ID, build_credential,
                       hash_email, issue_all)
from src.keys import generate_keys
from src.verify import verify_clr, verify_jwt, verify_ldp


@pytest.fixture(scope="module")
def keys():
    return generate_keys()


@pytest.fixture(scope="module")
def attacker():
    return generate_keys()


@pytest.fixture(scope="module")
def issued(keys):
    return issue_all(keys)


def _set_member_name(clr, index, name):
    clr["credentialSubject"]["verifiableCredential"][index][
        "credentialSubject"]["achievement"]["name"] = name


# ── emissão ──────────────────────────────────────────────────────────────────

def test_keys_use_did_fragment_format(keys):
    did, _, fragment = keys.verification_method.partition("#")
    assert did == keys.did
    assert fragment == keys.did.removeprefix("did:key:")


def test_issue(issued, keys):
    assert len(issued.jwts) == 2 and len(issued.ldp_docs) == 2
    assert all(t.count(".") == 2 for t in issued.jwts)
    for doc in issued.ldp_docs:
        assert doc["proof"]["cryptosuite"] == "eddsa-rdfc-2022"
        assert doc["proof"]["verificationMethod"] == keys.verification_method
    subject = issued.clr["credentialSubject"]
    assert "ClrCredential" in issued.clr["type"]
    assert len(subject["verifiableCredential"]) == 2
    identity = subject["identifier"][0]
    assert identity["hashed"] is True
    assert identity["identityHash"] == hash_email(RECIPIENT_EMAIL, issued.salt)
    assert RECIPIENT_EMAIL not in str(subject["identifier"])


# ── verificação de badges ────────────────────────────────────────────────────

def test_verify_jwt(issued, keys):
    names = [verify_jwt(t, keys.public_pem, RECIPIENT_ID).achievement.name
             for t in issued.jwts]
    assert names == [a.name for a in issued.achievements]


def test_verify_ldp(issued, keys):
    for doc in issued.ldp_docs:
        assert verify_ldp(doc, keys.public_pem, RECIPIENT_ID).recipient_id == RECIPIENT_ID


@pytest.mark.parametrize("recipient", [RECIPIENT_ID, RECIPIENT_EMAIL])
def test_expected_recipient_with_and_without_mailto(issued, keys, recipient):
    # O código usa a forma com "mailto:"; a forma sem prefixo é equivalente.
    verify_jwt(issued.jwts[0], keys.public_pem, recipient)
    verify_ldp(issued.ldp_docs[0], keys.public_pem, recipient)


@pytest.mark.parametrize("recipient", ["mailto:outra@example.com", "outra@example.com"])
def test_wrong_recipient_rejected(issued, keys, recipient):
    with pytest.raises(OB3VerificationError, match="Recipient mismatch"):
        verify_jwt(issued.jwts[0], keys.public_pem, recipient)


def test_tampered_token_rejected(issued, keys):
    forged = tamper_jwt_payload(issued.jwts[0], "Doutorado")
    with pytest.raises(OB3VerificationError):
        verify_jwt(forged, keys.public_pem, RECIPIENT_ID)


def test_tampered_signature_rejected(issued, keys):
    header, payload, signature = issued.jwts[0].split(".")
    flipped = ("A" if signature[0] != "A" else "B") + signature[1:]
    with pytest.raises(OB3VerificationError):
        verify_jwt(f"{header}.{payload}.{flipped}", keys.public_pem, RECIPIENT_ID)


def test_badge_signed_by_other_issuer_rejected(issued, keys, attacker):
    # Atacante assina um badge que se diz do emissor legítimo.
    forged = OB3Signer(attacker.private_pem, algorithm="EdDSA").sign(
        build_credential(issued.issuer, issued.achievements[0]))
    with pytest.raises(OB3VerificationError):
        verify_jwt(forged, keys.public_pem, RECIPIENT_ID)


def test_badge_verified_with_wrong_key_rejected(issued, attacker):
    with pytest.raises(OB3VerificationError):
        verify_jwt(issued.jwts[0], attacker.public_pem, RECIPIENT_ID)


# ── CLR ──────────────────────────────────────────────────────────────────────

def test_clr_valid(issued, keys):
    result = verify_clr(issued.clr, keys.public_pem, keys.did, RECIPIENT_EMAIL)
    assert result.issuer_id == keys.did
    assert [m.achievement.name for m in result.members] == \
        [a.name for a in issued.achievements]


def test_clr_tampered_achievement_name_rejected(issued, keys):
    clr = copy.deepcopy(issued.clr)
    _set_member_name(clr, 1, "Doutorado")
    with pytest.raises(OB3VerificationError):
        verify_clr(clr, keys.public_pem, keys.did, RECIPIENT_EMAIL)


def test_clr_tampered_identifier_rejected(issued, keys):
    clr = copy.deepcopy(issued.clr)
    clr["credentialSubject"]["identifier"][0]["identityHash"] = \
        hash_email("outra@example.com", issued.salt)
    with pytest.raises(OB3VerificationError):
        verify_clr(clr, keys.public_pem, keys.did, RECIPIENT_EMAIL)


def test_clr_tampered_member_inside_resigned_envelope_rejected(issued, keys):
    clr = copy.deepcopy(issued.clr)
    del clr["proof"]
    _set_member_name(clr, 0, "Doutorado")
    resigned = sign_clr_credential(clr, keys.private_pem, keys.verification_method)

    # A prova do envelope sozinha aceita: por isso os membros são verificados.
    verify_data_integrity_proof(resigned, keys.public_pem,
                                extra_contexts=bundled_clr_contexts())
    with pytest.raises(OB3VerificationError, match="badge membro #0"):
        verify_clr(resigned, keys.public_pem, keys.did, RECIPIENT_EMAIL)


def test_clr_wrong_key_rejected(issued, keys, attacker):
    with pytest.raises(OB3VerificationError):
        verify_clr(issued.clr, attacker.public_pem, keys.did, RECIPIENT_EMAIL)


def test_clr_wrong_issuer_did_rejected(issued, keys, attacker):
    with pytest.raises(OB3VerificationError, match="emissor do CLR"):
        verify_clr(issued.clr, keys.public_pem, attacker.did, RECIPIENT_EMAIL)


def test_clr_wrong_recipient_rejected(issued, keys):
    with pytest.raises(OB3VerificationError, match="identifier"):
        verify_clr(issued.clr, keys.public_pem, keys.did, "outra@example.com")


def test_clr_needs_bundled_context(issued, keys):
    with pytest.raises(OB3VerificationError):
        verify_data_integrity_proof(issued.clr, keys.public_pem)
