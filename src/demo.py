"""Fluxo completo: emitir, verificar, tentar fraudes e agrupar em um CLR.

Uso: ``python -m src.demo``. Sai com código 1 se alguma fraude for aceita.
"""

import argparse
import base64
import copy
import json
import sys
from pathlib import Path
from typing import Any, Callable

from openbadgeslib.ob3 import (OB3Signer, OB3VerificationError,
                               sign_clr_credential)

from .issue import (RECIPIENT_EMAIL, RECIPIENT_ID, build_credential,
                    issue_all)
from .keys import ALGORITHMS, ephemeral_jwt_key, generate_keys
from .verify import verify_clr, verify_jwt, verify_ldp

OUT_DIR = Path("out")


def step(title: str) -> None:
    print(f"\n=== {title} ===")


def expect_rejected(label: str, attempt: Callable[[], Any]) -> bool:
    """Roda uma tentativa de fraude; devolve True se ela foi rejeitada."""
    try:
        attempt()
    except OB3VerificationError as exc:
        print(f"  [ok] {label}: rejeitado ({exc})")
        return True
    print(f"  [FALHA] {label}: ACEITO")
    return False


def tamper_jwt_payload(token: str, new_name: str) -> str:
    """Troca o nome da conquista no payload e mantém a assinatura original."""
    header, payload, signature = token.split(".")
    data = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    data["credentialSubject"]["achievement"]["name"] = new_name
    forged = base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode()
    return f"{header}.{forged}.{signature}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--alg", choices=ALGORITHMS, default="EdDSA",
                        help="algoritmo dos badges JWT-VC (padrão: EdDSA)")
    alg = parser.parse_args(argv).alg

    step("1. Chaves")
    keys = generate_keys()
    attacker = generate_keys()
    print(f"  emissor:  {keys.did}")
    print(f"  vm:       {keys.verification_method}")
    print(f"  atacante: {attacker.did}")

    step(f"2. Emissão (JWT-VC em {alg})")
    issued = issue_all(keys, alg)
    jwt_key = issued.jwt_key
    if alg != "EdDSA":
        print(f"  emissor dos JWT-VC ({alg}, keystore): {jwt_key.issuer_id}")
    for achievement, token in zip(issued.achievements, issued.jwts):
        print(f"  JWT-VC  '{achievement.name}': {token[:40]}... ({len(token)} bytes)")
    for doc in issued.ldp_docs:
        print(f"  DI      '{doc['credentialSubject']['achievement']['name']}': "
              f"{doc['proof']['cryptosuite']}")
    print(f"  CLR     {issued.clr['id']} com "
          f"{len(issued.clr['credentialSubject']['verifiableCredential'])} membros")

    step("3. Verificação dos badges")
    for token in issued.jwts:
        credential = verify_jwt(token, jwt_key.public_pem, RECIPIENT_ID)
        print(f"  [ok] JWT-VC '{credential.achievement.name}' para {credential.recipient_id}")
    for doc in issued.ldp_docs:
        credential = verify_ldp(doc, keys.public_pem, RECIPIENT_ID)
        print(f"  [ok] DI     '{credential.achievement.name}' para {credential.recipient_id}")

    step("4. Tentativas de fraude nos badges")
    jwt_attacker = ephemeral_jwt_key(alg)
    forged_by_attacker = OB3Signer(jwt_attacker.private_pem, algorithm=alg).sign(
        build_credential(issued.jwt_issuer, issued.achievements[0]))
    results = [
        expect_rejected("token adulterado (nome da conquista)", lambda: verify_jwt(
            tamper_jwt_payload(issued.jwts[0], "Doutorado"), jwt_key.public_pem, RECIPIENT_ID)),
        expect_rejected("badge assinado com a chave de outro emissor", lambda: verify_jwt(
            forged_by_attacker, jwt_key.public_pem, RECIPIENT_ID)),
        expect_rejected("badge apresentado por outro destinatário", lambda: verify_jwt(
            issued.jwts[0], jwt_key.public_pem, "mailto:outra@example.com")),
    ]

    step("5. Verificação do CLR")
    result = verify_clr(issued.clr, keys.public_pem, keys.did, RECIPIENT_EMAIL)
    print(f"  [ok] CLR {result.clr_id}")
    for member in result.members:
        print(f"       membro verificado: '{member.achievement.name}'")

    step("6. Tentativas de fraude no CLR")
    tampered = copy.deepcopy(issued.clr)
    tampered["credentialSubject"]["verifiableCredential"][0][
        "credentialSubject"]["achievement"]["name"] = "Doutorado"
    # Membro adulterado com o envelope reassinado: a prova do CLR passa, só a
    # verificação do próprio membro pega a fraude.
    resigned = copy.deepcopy(tampered)
    del resigned["proof"]
    resigned = sign_clr_credential(resigned, keys.private_pem, keys.verification_method)
    results += [
        expect_rejected("CLR com nome de conquista alterado", lambda: verify_clr(
            tampered, keys.public_pem, keys.did, RECIPIENT_EMAIL)),
        expect_rejected("CLR reassinado com badge membro adulterado", lambda: verify_clr(
            resigned, keys.public_pem, keys.did, RECIPIENT_EMAIL)),
        expect_rejected("CLR verificado com a chave de outro emissor", lambda: verify_clr(
            issued.clr, attacker.public_pem, keys.did, RECIPIENT_EMAIL)),
        expect_rejected("CLR apresentado por outro destinatário", lambda: verify_clr(
            issued.clr, keys.public_pem, keys.did, "outra@example.com")),
    ]

    step("7. Arquivos gerados")
    OUT_DIR.mkdir(exist_ok=True)
    (OUT_DIR / "badge1.jwt").write_text(issued.jwts[0])  # sem "\n" final
    (OUT_DIR / "clr.json").write_text(
        json.dumps(issued.clr, indent=2, ensure_ascii=False) + "\n")
    print(f"  {OUT_DIR / 'badge1.jwt'}")
    print(f"  {OUT_DIR / 'clr.json'}")

    step("Resultado")
    if not all(results):
        print(f"  FALHA: {results.count(False)} fraude(s) aceita(s)")
        return 1
    print(f"  {len(results)} fraudes rejeitadas, fluxo concluído")
    return 0


if __name__ == "__main__":
    sys.exit(main())
