"""Par de chaves Ed25519 em memória e identificador did:key.

Nenhuma chave é gravada em disco: o PEM existe apenas como ``bytes`` dentro
do processo e desaparece quando a execução termina.
"""

from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from openbadgeslib.ob3 import did_key_from_pem


@dataclass(frozen=True)
class IssuerKeys:
    private_pem: bytes
    public_pem: bytes
    did: str                  # did:key:z6Mk...
    verification_method: str  # did:key:z6Mk...#z6Mk...

    def __repr__(self) -> str:  # evita vazar a chave privada em logs
        return f"IssuerKeys(did={self.did!r})"


def generate_keys() -> IssuerKeys:
    """Gera um par Ed25519 novo e deriva o did:key correspondente."""
    private_key = Ed25519PrivateKey.generate()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    did = did_key_from_pem(public_pem)
    # Pela especificação did:key, o único fragmento válido é o próprio
    # identificador multibase: did:key:z6Mk...#z6Mk...
    fragment = did.removeprefix("did:key:")
    return IssuerKeys(private_pem, public_pem, did, f"{did}#{fragment}")
