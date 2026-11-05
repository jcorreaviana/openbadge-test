"""Chave de TESTE persistente, guardada fora do repositório.

Na primeira chamada gera o par e grava em ``~/.openbadge-test/keys/``
(ou em ``$OPENBADGE_TEST_KEYDIR``): pasta com permissão 700, chave privada
com 600. Nas chamadas seguintes reutiliza o mesmo par.

Esta chave serve só para testes com dados fictícios. Nunca a reutilize para
emitir credenciais reais.
"""

import os
import stat
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

ENV_VAR = "OPENBADGE_TEST_KEYDIR"
DEFAULT_DIR = Path.home() / ".openbadge-test" / "keys"
PROJECT_ROOT = Path(__file__).resolve().parent.parent


class KeystoreError(Exception):
    pass


@dataclass(frozen=True)
class StoredKeys:
    private_pem: bytes
    public_pem: bytes
    private_path: Path

    def __repr__(self) -> str:  # nunca expõe a chave privada
        return f"StoredKeys(private_path={str(self.private_path)!r})"


def key_dir() -> Path:
    return Path(os.environ.get(ENV_VAR) or DEFAULT_DIR).expanduser().resolve()


def _generate_rsa() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


_GENERATORS = {"rsa": _generate_rsa}


def load_or_create(kind: str = "rsa") -> StoredKeys:
    """Devolve o par de teste do tipo ``kind``, criando-o se não existir."""
    if kind not in _GENERATORS:
        raise KeystoreError(f"tipo de chave não suportado: {kind!r}")
    directory = _prepare_dir(key_dir())
    private_path = directory / f"{kind}_private.pem"

    if private_path.exists():
        _check_private_mode(private_path)
        private_pem = private_path.read_bytes()
        private_key = serialization.load_pem_private_key(private_pem, password=None)
    else:
        private_key = _GENERATORS[kind]()
        private_pem = private_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption())
        _write_private(private_path, private_pem)

    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    return StoredKeys(private_pem, public_pem, private_path)


def _prepare_dir(directory: Path) -> Path:
    if directory == PROJECT_ROOT or PROJECT_ROOT in directory.parents:
        raise KeystoreError(
            f"{directory} está dentro do repositório; use uma pasta fora dele")
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    # mkdir respeita o umask e não altera pastas que já existiam.
    os.chmod(directory, 0o700)
    return directory


def _check_private_mode(path: Path) -> None:
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o077:
        raise KeystoreError(
            f"{path} tem permissão {oct(mode)}; corrija com: chmod 600 {path}")


def _write_private(path: Path, data: bytes) -> None:
    # O_EXCL: nunca sobrescreve; 0o600 já na criação, sem janela de exposição.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)
