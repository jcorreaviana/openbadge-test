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


# ── chaves para JWT-VC em qualquer algoritmo ─────────────────────────────────

ALGORITHMS = ("EdDSA", "RS256", "ES256")

# did:key só aceita Ed25519 e P-256; um emissor RSA precisa de um id em URL.
HTTP_ISSUER_ID = "https://example.com/issuers/escola-exemplo"


@dataclass(frozen=True)
class JwtKey:
    alg: str
    private_pem: bytes
    public_pem: bytes
    issuer_id: str

    def __repr__(self) -> str:  # evita vazar a chave privada em logs
        return f"JwtKey(alg={self.alg!r}, issuer_id={self.issuer_id!r})"


def jwt_key_from_pems(alg: str, private_pem: bytes, public_pem: bytes) -> JwtKey:
    if alg not in ALGORITHMS:
        raise ValueError(f"algoritmo não suportado: {alg!r}")
    issuer_id = HTTP_ISSUER_ID if alg == "RS256" else did_key_from_pem(public_pem)
    return JwtKey(alg, private_pem, public_pem, issuer_id)


def ephemeral_jwt_key(alg: str) -> JwtKey:
    """Par novo, só em memória, do tipo exigido por ``alg``."""
    from cryptography.hazmat.primitives.asymmetric import ec, rsa

    if alg == "EdDSA":
        keys = generate_keys()
        return jwt_key_from_pems(alg, keys.private_pem, keys.public_pem)
    if alg == "RS256":
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    elif alg == "ES256":
        private_key = ec.generate_private_key(ec.SECP256R1())
    else:
        raise ValueError(f"algoritmo não suportado: {alg!r}")
    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption())
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    return jwt_key_from_pems(alg, private_pem, public_pem)
